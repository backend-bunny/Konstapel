package preview

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/exception"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// UserAgent identifies preview requests in API server audit logs.
const UserAgent = "konstapel-preview"

// snapshotSelector selects acceptance snapshot ConfigMaps as the exception
// controller writes them (exception.Snapshot.ConfigMap).
var snapshotSelector = exception.LabelComponent + "=" + exception.ComponentSnapshot + "," + targeting.LabelManagedBy + "=" + targeting.ManagedByValue

// managedSelector selects Konstapel-labelled engine policies. The label alone
// does not confer ownership (targeting.OwnedBy).
var managedSelector = targeting.LabelManagedBy + "=" + targeting.ManagedByValue

type reader struct {
	lim  ObserveLimits
	dyn  dynamic.Interface
	disc rest.Interface
}

func newReader(cfg *rest.Config, lim ObserveLimits) (*reader, error) {
	cfg = rest.CopyConfig(cfg)
	cfg.UserAgent = UserAgent
	if cfg.QPS == 0 {
		cfg.QPS, cfg.Burst = 50, 100
	}
	// Outermost, so a refused request reaches no other transport.
	cfg.Wrap(func(rt http.RoundTripper) http.RoundTripper { return readOnlyTransport{next: rt} })
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	dc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &reader{lim: lim, dyn: dyn, disc: dc.RESTClient()}, nil
}

// refusedError is a request the read-only transport never sent.
type refusedError struct{ method, path, why string }

func (e *refusedError) Error() string {
	return fmt.Sprintf("preview refused to send %s %s: %s", e.method, e.path, e.why)
}

// readOnlyTransport is the enforcement point of the access contract: only GET
// requests leave the process; Secrets, watches and dry-run are refused before
// sending. It also meters response bytes against the capture budget.
type readOnlyTransport struct{ next http.RoundTripper }

func (t readOnlyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if why := refuse(req); why != "" {
		return nil, &refusedError{method: req.Method, path: req.URL.Path, why: why}
	}
	resp, err := t.next.RoundTrip(req)
	if err == nil && resp.Body != nil {
		if b := budgetFrom(req.Context()); b != nil {
			resp.Body = &meteredBody{ReadCloser: resp.Body, b: b}
		}
	}
	return resp, err
}

func refuse(req *http.Request) string {
	if req.Method != http.MethodGet {
		return "the preview sends only GET requests"
	}
	q := req.URL.Query()
	if q.Has("dryRun") {
		return "server-side dry-run is a write-shaped request"
	}
	if w := q.Get("watch"); w != "" && w != "false" && w != "0" {
		return "the preview does not watch"
	}
	if isSecretPath(req.URL.Path) {
		return "the preview does not read Secrets"
	}
	return ""
}

// isSecretPath matches core Secret requests, /api/v1/secrets and
// /api/v1/namespaces/<ns>/secrets[/...], but not a namespace named "secrets".
func isSecretPath(p string) bool {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	if len(segs) < 3 || segs[0] != "api" {
		return false
	}
	return segs[2] == "secrets" || (segs[2] == "namespaces" && len(segs) >= 5 && segs[4] == "secrets")
}

type budget struct {
	max      int64
	used     atomic.Int64
	exceeded atomic.Bool
}

type budgetKey struct{}

func withBudget(ctx context.Context, b *budget) context.Context {
	return context.WithValue(ctx, budgetKey{}, b)
}

func budgetFrom(ctx context.Context) *budget { b, _ := ctx.Value(budgetKey{}).(*budget); return b }

var errByteLimit = errors.New("response byte limit exceeded")

type meteredBody struct {
	io.ReadCloser
	b *budget
}

func (m *meteredBody) Read(p []byte) (int, error) {
	n, err := m.ReadCloser.Read(p)
	if m.b.used.Add(int64(n)) > m.b.max {
		m.b.exceeded.Store(true)
		return n, errByteLimit
	}
	return n, err
}

// discover checks that every required API is served with get and list.
func (r *reader) discover(ctx context.Context) *Diagnostic {
	required := []struct {
		path      string
		gv        schema.GroupVersion
		resources []string
	}{
		{"/api/v1", schema.GroupVersion{Version: "v1"}, []string{"namespaces", "configmaps"}},
		{"/apis/" + v1alpha1.GroupVersion.String(), v1alpha1.GroupVersion, []string{"complianceprofiles", "compliancebindings", "complianceexceptions"}},
		{"/apis/" + gvrEnginePolicy.GroupVersion().String(), gvrEnginePolicy.GroupVersion(), []string{gvrEnginePolicy.Resource}},
	}
	for _, g := range required {
		raw, err := r.disc.Get().AbsPath(g.path).Do(ctx).Raw()
		if err != nil {
			d := classify(ctx, nil, err, g.gv.Group+"/"+g.gv.Version, "", "", true)
			if d.Code == ObserveAPIUnavailable {
				d.Message = fmt.Sprintf("the API %s is not served by this cluster", g.gv)
			}
			return d
		}
		var list metav1.APIResourceList
		if err := json.Unmarshal(raw, &list); err != nil {
			return &Diagnostic{Code: ObserveRequestFailed, Resource: g.gv.String(), Message: "discovery document: " + err.Error()}
		}
		for _, want := range g.resources {
			i := slices.IndexFunc(list.APIResources, func(a metav1.APIResource) bool { return a.Name == want })
			if i < 0 || !slices.Contains(list.APIResources[i].Verbs, "list") || !slices.Contains(list.APIResources[i].Verbs, "get") {
				return &Diagnostic{Code: ObserveAPIUnavailable, Resource: resourceString(g.gv.WithResource(want)),
					Message: fmt.Sprintf("required resource %s is not served with get and list", want)}
			}
		}
	}
	return nil
}

// classify turns a request error into a diagnostic. A list that is not found
// means the API is not served; a named get that is not found is a missing object.
func classify(ctx context.Context, b *budget, err error, resource, ns, name string, list bool) *Diagnostic {
	d := &Diagnostic{Resource: resource, Namespace: ns, Name: name, Message: err.Error()}
	var refused *refusedError
	switch {
	case b != nil && b.exceeded.Load():
		d.Code, d.Message = ObserveByteLimit, fmt.Sprintf("the capture exceeded %d response bytes", b.max)
	case errors.As(err, &refused):
		d.Code = ObserveRefusedRequest
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		d.Code, d.Message = ObserveTimeout, "the observation timed out"
	case errors.Is(ctx.Err(), context.Canceled):
		d.Code, d.Message = ObserveCanceled, "the observation was canceled"
	case apierrors.IsResourceExpired(err) || apierrors.IsGone(err):
		d.Code = ObservePaginationExpired
	case apierrors.IsForbidden(err):
		d.Code = ObserveAccessDenied
	case apierrors.IsUnauthorized(err):
		d.Code = ObserveUnauthorized
	case apierrors.IsNotFound(err) && list:
		d.Code = ObserveAPIUnavailable
	case apierrors.IsNotFound(err):
		d.Code = ObserveNotFound
	default:
		d.Code = ObserveRequestFailed
	}
	return d
}

// capture is one complete pass over every relevant projection.
type capture struct {
	r           *reader
	b           *budget
	pages, objs int
	collections []Collection
	// projections maps "resource namespace/name" to a digest of only the
	// fields that matter to comparison; status timestamps are excluded.
	projections map[string]string
	refs        []ObjectRef
	cluster     string
	profiles    []v1alpha1.ComplianceProfile
	bindings    []v1alpha1.ComplianceBinding
	// specs are the stored specs of profiles and bindings, as returned.
	specs       map[Identity]map[string]any
	namespaces  []ObservedNamespace
	applied     []AppliedPolicy
	unowned     []ObjectRef
	exceptions  []ObservedException
	snapshots   []ObservedAcceptanceSnapshot
	sources     *ObservedSources
	limitations []Diagnostic
}

func (r *reader) capture(ctx context.Context, opts ObserveOptions) (*capture, *Diagnostic) {
	c := &capture{r: r, b: &budget{max: r.lim.MaxResponseBytes}, projections: map[string]string{}, specs: map[Identity]map[string]any{}}
	ctx = withBudget(ctx, c.b)
	steps := []func(context.Context, ObserveOptions) *Diagnostic{
		c.readCluster, c.readNamespaces, c.readProfiles, c.readBindings, c.readEnginePolicies,
		c.readExceptions, c.readSnapshots, c.readSources,
	}
	for _, step := range steps {
		if d := step(ctx, opts); d != nil {
			return c, d
		}
	}
	return c, nil
}

func (c *capture) request() *Diagnostic {
	if c.pages >= c.r.lim.MaxPages {
		return &Diagnostic{Code: ObservePageLimit, Message: fmt.Sprintf("the capture needed more than %d requests", c.r.lim.MaxPages)}
	}
	c.pages++
	return nil
}

func (c *capture) count(n int) *Diagnostic {
	c.objs += n
	if c.objs > c.r.lim.MaxObjects {
		return &Diagnostic{Code: ObserveObjectLimit, Message: fmt.Sprintf("the capture found more than %d objects", c.r.lim.MaxObjects)}
	}
	return nil
}

// list reads every page of one collection. Items are returned in server order;
// callers sort.
func (c *capture) list(ctx context.Context, gvr schema.GroupVersionResource, ns, selector string) ([]unstructured.Unstructured, *Diagnostic) {
	res := resourceString(gvr)
	col := Collection{Resource: res, Namespace: ns, LabelSelector: selector}
	defer func() { c.collections = append(c.collections, col) }()
	var ri dynamic.ResourceInterface = c.r.dyn.Resource(gvr)
	if ns != "" {
		ri = c.r.dyn.Resource(gvr).Namespace(ns)
	}
	var items []unstructured.Unstructured
	seen := map[string]bool{}
	cont := ""
	for {
		if d := c.request(); d != nil {
			d.Resource, d.Namespace = res, ns
			return nil, d
		}
		l, err := ri.List(ctx, metav1.ListOptions{Limit: c.r.lim.PageSize, Continue: cont, LabelSelector: selector})
		col.Pages++
		if err != nil {
			return nil, classify(ctx, c.b, err, res, ns, "", true)
		}
		if col.ResourceVersion == "" {
			col.ResourceVersion = l.GetResourceVersion()
		}
		col.Objects += len(l.Items)
		if d := c.count(len(l.Items)); d != nil {
			d.Resource, d.Namespace = res, ns
			return nil, d
		}
		for _, it := range l.Items {
			key := it.GetNamespace() + "/" + it.GetName()
			if seen[key] {
				return nil, &Diagnostic{Code: ObserveInvalidObject, Resource: res, Namespace: it.GetNamespace(), Name: it.GetName(), Message: "the list returned this object twice"}
			}
			seen[key] = true
		}
		items = append(items, l.Items...)
		if cont = l.GetContinue(); cont == "" {
			return items, nil
		}
	}
}

// get reads one named object; found is false when it does not exist.
func (c *capture) get(ctx context.Context, gvr schema.GroupVersionResource, ns, name string) (*unstructured.Unstructured, bool, *Diagnostic) {
	res := resourceString(gvr)
	col := Collection{Resource: res, Namespace: ns, Name: name}
	defer func() { c.collections = append(c.collections, col) }()
	if d := c.request(); d != nil {
		d.Resource, d.Namespace, d.Name = res, ns, name
		return nil, false, d
	}
	var ri dynamic.ResourceInterface = c.r.dyn.Resource(gvr)
	if ns != "" {
		ri = c.r.dyn.Resource(gvr).Namespace(ns)
	}
	u, err := ri.Get(ctx, name, metav1.GetOptions{})
	col.Pages++
	if err != nil {
		d := classify(ctx, c.b, err, res, ns, name, false)
		if d.Code == ObserveNotFound {
			return nil, false, nil
		}
		return nil, false, d
	}
	col.ResourceVersion, col.Objects = u.GetResourceVersion(), 1
	if d := c.count(1); d != nil {
		d.Resource, d.Namespace, d.Name = res, ns, name
		return nil, false, d
	}
	return u, true, nil
}

// observe records an object's identity and relevant projection.
func (c *capture) observe(gvr schema.GroupVersionResource, u *unstructured.Unstructured, projection any) ObjectRef {
	ref := ObjectRef{Resource: resourceString(gvr), Namespace: u.GetNamespace(), Name: u.GetName(), UID: u.GetUID(),
		ResourceVersion: u.GetResourceVersion(), Generation: u.GetGeneration()}
	c.refs = append(c.refs, ref)
	c.projections[ref.Resource+" "+ref.Namespace+"/"+ref.Name] = digestOf(struct {
		UID        types.UID `json:"uid"`
		Projection any       `json:"projection"`
	}{ref.UID, projection})
	return ref
}

func digestOf(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		// Only decoded JSON values and fixed structs reach here.
		panic("preview: projection: " + err.Error())
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (c *capture) readCluster(ctx context.Context, _ ObserveOptions) *Diagnostic {
	u, found, d := c.get(ctx, gvrNamespaces, "", "kube-system")
	if d != nil {
		return d
	}
	if !found || u.GetUID() == "" {
		return &Diagnostic{Code: ObserveNotFound, Resource: resourceString(gvrNamespaces), Name: "kube-system", Message: "the cluster identity (the kube-system namespace UID) is not readable"}
	}
	// The namespace itself is observed with the namespace list; the
	// identity is projected separately so a replaced cluster is drift.
	c.cluster = "kube-system:" + string(u.GetUID())
	c.projections["cluster"] = c.cluster
	return nil
}

func (c *capture) readNamespaces(ctx context.Context, _ ObserveOptions) *Diagnostic {
	items, d := c.list(ctx, gvrNamespaces, "", "")
	if d != nil {
		return d
	}
	for i := range items {
		u := &items[i]
		n := ObservedNamespace{Name: u.GetName(), UID: u.GetUID(), ResourceVersion: u.GetResourceVersion(), Labels: u.GetLabels(), Terminating: u.GetDeletionTimestamp() != nil}
		if n.Labels == nil {
			n.Labels = map[string]string{}
		}
		// Membership depends on the instance and its labels only.
		c.observe(gvrNamespaces, u, struct {
			Labels      map[string]string `json:"labels"`
			Terminating bool              `json:"terminating"`
		}{n.Labels, n.Terminating})
		c.namespaces = append(c.namespaces, n)
	}
	return nil
}

// decodeStrict decodes an API object without its status. Unknown spec or
// metadata fields mean the cluster serves a contract this preview does not
// understand: the object cannot be compared safely.
func decodeStrict(gvr schema.GroupVersionResource, u *unstructured.Unstructured, into any) *Diagnostic {
	obj := runtime.DeepCopyJSON(u.Object)
	delete(obj, "status")
	if err := runtime.DefaultUnstructuredConverter.FromUnstructuredWithValidation(obj, into, true); err != nil {
		return &Diagnostic{Code: ObserveInvalidObject, Resource: resourceString(gvr), Namespace: u.GetNamespace(), Name: u.GetName(),
			Message: "the object does not match the supported contract: " + err.Error()}
	}
	return nil
}

func (c *capture) readProfiles(ctx context.Context, _ ObserveOptions) *Diagnostic {
	items, d := c.list(ctx, gvrProfiles, "", "")
	if d != nil {
		return d
	}
	for i := range items {
		var p v1alpha1.ComplianceProfile
		if d := decodeStrict(gvrProfiles, &items[i], &p); d != nil {
			return d
		}
		c.observe(gvrProfiles, &items[i], struct {
			Generation  int64  `json:"generation"`
			Terminating bool   `json:"terminating"`
			Config      string `json:"config"`
		}{p.Generation, p.DeletionTimestamp != nil, Fingerprint(&p, nil)})
		c.storeSpec(KindProfile, &items[i])
		c.profiles = append(c.profiles, p)
	}
	return nil
}

func (c *capture) readBindings(ctx context.Context, _ ObserveOptions) *Diagnostic {
	items, d := c.list(ctx, gvrBindings, "", "")
	if d != nil {
		return d
	}
	for i := range items {
		var b v1alpha1.ComplianceBinding
		if d := decodeStrict(gvrBindings, &items[i], &b); d != nil {
			return d
		}
		// The enforcement epoch is outside the configuration fingerprint but
		// is a revision input, so it is part of the projection.
		c.observe(gvrBindings, &items[i], struct {
			Generation  int64  `json:"generation"`
			Epoch       int64  `json:"epoch"`
			Terminating bool   `json:"terminating"`
			Config      string `json:"config"`
		}{b.Generation, b.Spec.EnforcementEpoch, b.DeletionTimestamp != nil, Fingerprint(nil, &b)})
		c.storeSpec(KindBinding, &items[i])
		c.bindings = append(c.bindings, b)
	}
	return nil
}

// storeSpec keeps the spec exactly as stored, so a proposal can be compared
// with what the API server holds rather than with normalized configuration.
func (c *capture) storeSpec(kind string, u *unstructured.Unstructured) {
	if spec, ok := u.Object["spec"].(map[string]any); ok {
		c.specs[Identity{Group: v1alpha1.GroupVersion.Group, Kind: kind, Name: u.GetName()}] = runtime.DeepCopyJSON(spec)
	}
}

func (c *capture) readEnginePolicies(ctx context.Context, _ ObserveOptions) *Diagnostic {
	items, d := c.list(ctx, gvrEnginePolicy, "", managedSelector)
	if d != nil {
		return d
	}
	bindings := map[types.UID]bool{}
	for _, b := range c.bindings {
		bindings[b.UID] = true
	}
	for i := range items {
		u := &items[i]
		ann := map[string]string{}
		for k, v := range u.GetAnnotations() {
			if strings.HasPrefix(k, v1alpha1.GroupVersion.Group+"/") {
				ann[k] = v
			}
		}
		ready := targeting.KyvernoReady(u)
		// Readiness is the derived engine acceptance; Kyverno's condition
		// timestamps and messages are not relevant.
		ref := c.observe(gvrEnginePolicy, u, struct {
			Labels      map[string]string       `json:"labels"`
			Annotations map[string]string       `json:"annotations"`
			Owners      []metav1.OwnerReference `json:"owners"`
			Spec        any                     `json:"spec"`
			Ready       bool                    `json:"ready"`
			Terminating bool                    `json:"terminating"`
		}{u.GetLabels(), ann, u.GetOwnerReferences(), u.Object["spec"], ready, u.GetDeletionTimestamp() != nil})
		bindingUID := types.UID(u.GetLabels()[targeting.LabelBindingUID])
		if bindingUID == "" || !targeting.OwnedBy(u, bindingUID) {
			c.unowned = append(c.unowned, ref)
			continue
		}
		a := AppliedPolicy{ObjectRef: ref, BindingUID: bindingUID, Ready: ready, Ownership: Owned, Terminating: u.GetDeletionTimestamp() != nil}
		if !bindings[bindingUID] {
			a.Ownership = Orphaned
		}
		if contrib, err := targeting.AppliedContribution(u.Object); err != nil {
			a.ProvenanceError = err.Error()
		} else {
			a.Contribution = &contrib
		}
		c.applied = append(c.applied, a)
	}
	return nil
}

func (c *capture) readExceptions(ctx context.Context, _ ObserveOptions) *Diagnostic {
	items, d := c.list(ctx, gvrExceptions, "", "")
	if d != nil {
		return d
	}
	for i := range items {
		u := &items[i]
		var ex v1alpha1.ComplianceException
		if d := decodeStrict(gvrExceptions, u, &ex); d != nil {
			return d
		}
		var snapRef *v1alpha1.AcceptanceSnapshotReference
		if raw, found, _ := unstructured.NestedMap(u.Object, "status", "acceptance"); found {
			snapRef = &v1alpha1.AcceptanceSnapshotReference{}
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(raw, snapRef); err != nil {
				return &Diagnostic{Code: ObserveInvalidObject, Resource: resourceString(gvrExceptions), Namespace: u.GetNamespace(), Name: u.GetName(),
					Message: "status.acceptance: " + err.Error()}
			}
		}
		// The protected acceptance record and the snapshot reference are
		// acceptance inputs; conditions and their timestamps are not.
		ref := c.observe(gvrExceptions, u, struct {
			Generation  int64                                 `json:"generation"`
			Spec        v1alpha1.ComplianceExceptionSpec      `json:"spec"`
			Acceptance  string                                `json:"acceptance"`
			Snapshot    *v1alpha1.AcceptanceSnapshotReference `json:"snapshot"`
			Terminating bool                                  `json:"terminating"`
		}{ex.Generation, ex.Spec, ex.Annotations[exception.AcceptanceAnnotation], snapRef, ex.DeletionTimestamp != nil})
		o := ObservedException{ObjectRef: ref, Policy: ex.Spec.Policy, AcceptanceRevision: ex.Spec.AcceptanceRevision,
			ExpiresAt: ex.Spec.ExpiresAt.UTC(), Terminating: ex.DeletionTimestamp != nil, Snapshot: snapRef}
		a, present, err := exception.ParseAcceptance(&ex)
		switch {
		case err != nil:
			o.AcceptanceError = err.Error()
		case present:
			o.Acceptance = &Acceptance{Revision: a.Revision, Cluster: a.Cluster, Namespace: a.Namespace, Policy: a.Policy, AcceptedAt: a.AcceptedAt.UTC()}
			if a.Eligibility != nil {
				o.Acceptance.Contributors = len(a.Eligibility.Contributors)
			}
		}
		c.exceptions = append(c.exceptions, o)
	}
	return nil
}

func (c *capture) readSnapshots(ctx context.Context, opts ObserveOptions) *Diagnostic {
	items, d := c.list(ctx, gvrConfigMaps, opts.Namespace, snapshotSelector)
	if d != nil {
		return d
	}
	for i := range items {
		u := &items[i]
		var cm corev1.ConfigMap
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &cm); err != nil {
			return &Diagnostic{Code: ObserveInvalidObject, Resource: resourceString(gvrConfigMaps), Namespace: u.GetNamespace(), Name: u.GetName(), Message: err.Error()}
		}
		ref := c.observe(gvrConfigMaps, u, struct {
			Data   map[string]string `json:"data"`
			Digest string            `json:"digest"`
		}{cm.Data, cm.Annotations[exception.AnnotationSnapshotDigest]})
		o := ObservedAcceptanceSnapshot{ObjectRef: ref}
		s, digest, err := exception.SnapshotFrom(&cm)
		o.Digest = digest
		if err != nil {
			o.VerifyError = err.Error()
		} else {
			o.Cluster, o.ExceptionUID, o.ExceptionName, o.ExceptionNamespace = s.Cluster, s.Exception.UID, s.Exception.Name, s.Exception.Namespace
			o.AcceptanceRevision, o.Namespace, o.Policy, o.ExpiresAt = s.AcceptanceRevision, s.Namespace, s.Policy, s.ExpiresAt.UTC()
			elig := s.Eligibility
			o.Eligibility = &elig
		}
		c.snapshots = append(c.snapshots, o)
	}
	return nil
}

func (c *capture) readSources(ctx context.Context, opts ObserveOptions) *Diagnostic {
	if opts.SourcesConfigMap == "" {
		c.limitations = append(c.limitations, Diagnostic{Code: LimitSourcesNotSelected,
			Message: "no bundle-source ConfigMap was selected; only vendored content can be resolved, as for a controller without --bundle-sources-configmap"})
		return nil
	}
	u, found, d := c.get(ctx, gvrConfigMaps, opts.Namespace, opts.SourcesConfigMap)
	if d != nil {
		return d
	}
	o := &ObservedSources{ConfigMap: ObjectRef{Resource: resourceString(gvrConfigMaps), Namespace: opts.Namespace, Name: opts.SourcesConfigMap}}
	c.sources = o
	key := resourceString(gvrConfigMaps) + " " + opts.Namespace + "/" + opts.SourcesConfigMap
	if !found {
		o.Missing = true
		c.projections[key] = "missing"
		c.limitations = append(c.limitations, Diagnostic{Code: LimitSourcesUnusable, Resource: o.ConfigMap.Resource, Namespace: opts.Namespace, Name: opts.SourcesConfigMap,
			Message: "the selected bundle-source ConfigMap does not exist; OCI-pinned profiles cannot resolve"})
		return nil
	}
	data, _, _ := unstructured.NestedStringMap(u.Object, "data")
	o.Digest = digestOf(data)
	o.ConfigMap = c.observe(gvrConfigMaps, u, o.Digest)
	sources, err := bundle.ParseConfigMapData(data)
	if err != nil {
		o.ParseError = err.Error()
		c.limitations = append(c.limitations, Diagnostic{Code: LimitSourcesUnusable, Resource: o.ConfigMap.Resource, Namespace: opts.Namespace, Name: opts.SourcesConfigMap,
			Message: "the selected bundle-source configuration is invalid; OCI-pinned profiles cannot resolve"})
		return nil
	}
	type trustRef struct{ name, key string }
	var trust []trustRef
	secrets := map[string]bool{}
	note := func(r *bundle.ObjectRef, defaultKey string) {
		if r == nil {
			return
		}
		k := r.Key
		if k == "" {
			k = defaultKey
		}
		if r.Kind == bundle.KindSecret {
			secrets[r.Name] = true
			return
		}
		trust = append(trust, trustRef{r.Name, k})
	}
	for _, s := range sources.Sources {
		o.Sources = append(o.Sources, ObservedSource{Name: s.Name, Repository: s.Repository, Publisher: s.Publisher.Type})
		if s.CredentialSecret != nil {
			secrets[s.CredentialSecret.Name] = true
		}
		note(s.CA, bundle.DefaultCAKey)
		note(s.Publisher.TrustRoot, bundle.DefaultTrustRootKey)
		note(s.Publisher.PublicKey, bundle.DefaultPublicKey)
	}
	slices.SortFunc(trust, func(a, b trustRef) int { return strings.Compare(a.name+"\x00"+a.key, b.name+"\x00"+b.key) })
	trust = slices.Compact(trust)
	read := map[string]*unstructured.Unstructured{}
	for _, t := range trust {
		obj, seen := read[t.name]
		if !seen {
			got, found, d := c.get(ctx, gvrConfigMaps, opts.Namespace, t.name)
			if d != nil {
				return d
			}
			if found {
				obj = got
			}
			read[t.name] = obj
		}
		to := ObservedTrustObject{ObjectRef: ObjectRef{Resource: resourceString(gvrConfigMaps), Namespace: opts.Namespace, Name: t.name}, Key: t.key}
		tkey := key + "#trust/" + t.name + "#" + t.key
		if obj == nil {
			to.Missing = true
			c.projections[tkey] = "missing"
		} else {
			to.ObjectRef = ObjectRef{Resource: to.Resource, Namespace: opts.Namespace, Name: t.name, UID: obj.GetUID(), ResourceVersion: obj.GetResourceVersion()}
			v, ok, _ := unstructured.NestedString(obj.Object, "data", t.key)
			if !ok {
				to.Missing = true
			} else {
				to.Digest = digestOf(v)
			}
			c.projections[tkey] = digestOf([]any{obj.GetUID(), to.Missing, to.Digest})
		}
		o.TrustConfigMaps = append(o.TrustConfigMaps, to)
	}
	for _, s := range slices.Sorted(maps.Keys(secrets)) {
		o.UnreadSecrets = append(o.UnreadSecrets, s)
		c.limitations = append(c.limitations, Diagnostic{Code: LimitSecretNotRead, Resource: "/v1/secrets", Namespace: opts.Namespace, Name: s,
			Message: "a bundle source references this Secret; the observation never reads Secrets"})
	}
	return nil
}

// fill copies a stable capture into the snapshot in deterministic order.
func (c *capture) fill(s *Snapshot, opts ObserveOptions) {
	s.Cluster = c.cluster
	s.Objects = slices.SortedFunc(slices.Values(c.refs), compareRef)
	s.Live = Live{Profiles: c.profiles, Bindings: c.bindings, StoredSpecs: c.specs}
	slices.SortFunc(s.Live.Profiles, func(a, b v1alpha1.ComplianceProfile) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(s.Live.Bindings, func(a, b v1alpha1.ComplianceBinding) int { return strings.Compare(a.Name, b.Name) })
	s.Namespaces = c.namespaces
	slices.SortFunc(s.Namespaces, func(a, b ObservedNamespace) int {
		return strings.Compare(a.Name+"\x00"+string(a.UID), b.Name+"\x00"+string(b.UID))
	})
	s.Applied = c.applied
	slices.SortFunc(s.Applied, func(a, b AppliedPolicy) int { return compareRef(a.ObjectRef, b.ObjectRef) })
	s.Unowned = slices.SortedFunc(slices.Values(c.unowned), compareRef)
	s.Exceptions = c.exceptions
	slices.SortFunc(s.Exceptions, func(a, b ObservedException) int { return compareRef(a.ObjectRef, b.ObjectRef) })
	s.AcceptanceSnapshots = c.snapshots
	slices.SortFunc(s.AcceptanceSnapshots, func(a, b ObservedAcceptanceSnapshot) int { return compareRef(a.ObjectRef, b.ObjectRef) })
	s.Sources = c.sources
	lims := append(slices.Clone(c.limitations),
		Diagnostic{Code: LimitNoAtomicSnapshot, Message: "Kubernetes has no cross-resource transaction: two consecutive captures agreed on every relevant projection, which detects drift but does not prove an atomic snapshot or guarantee the state at apply time"},
		Diagnostic{Code: LimitRevocationUnavailable, Resource: resourceString(gvrExceptions),
			Message: "exception revocation (spec.revoked and revocation records) is not available in this version; acceptance is observed from the protected acceptance record, its status reference and the frozen snapshots only"})
	s.Limitations = sortDiagnostics(lims)
}

func compareRef(a, b ObjectRef) int {
	return strings.Compare(a.Resource+"\x00"+a.Namespace+"\x00"+a.Name, b.Resource+"\x00"+b.Namespace+"\x00"+b.Name)
}

// serverHost returns the host of an API server URL, without scheme, userinfo,
// path or query, so no credential-bearing URL reaches a report.
func serverHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}
