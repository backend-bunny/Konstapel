package exception

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// AcceptanceAnnotation holds the protected acceptance record. Only the
// exception admission webhook writes it: on creation and on an explicit
// renewal. Any other change to it is rejected.
const AcceptanceAnnotation = "compliance.erenius.io/acceptance"

// ClaimAnnotation is an optional, caller-owned reference such as a ticket or
// the human behind a GitOps commit. It is recorded as a claim and never
// treated as the authenticated actor.
const ClaimAnnotation = "compliance.erenius.io/claimed-by"

// Webhook paths served by the manager's webhook server.
const (
	MutatePath   = "/exceptions/mutate"
	ValidatePath = "/exceptions/validate"
)

// Acceptance is what admission records for one acceptance revision. The
// controller copies it into the immutable snapshot (task 3.1); later
// configuration never replaces it.
type Acceptance struct {
	// Revision is the spec.acceptanceRevision this record accepts.
	Revision int64 `json:"revision"`
	// AcceptedAt is the API server request time as seen by admission.
	AcceptedAt metav1.Time `json:"acceptedAt"`
	// Actor is the authenticated principal of the accepting request.
	Actor Actor `json:"actor"`
	// Claim is the caller-supplied ClaimAnnotation at acceptance, unverified.
	Claim     string                 `json:"claim,omitempty"`
	Cluster   string                 `json:"cluster"`
	Namespace targeting.NamespaceRef `json:"namespace"`
	Policy    string                 `json:"policy"`
	// Eligibility is the resolved effective eligibility and the complete
	// contribution/revision set for the policy in this namespace at
	// acceptance. Admission rejects an acceptance without one.
	Eligibility *targeting.Eligibility `json:"eligibility"`
}

// Actor is an authenticated Kubernetes identity from AdmissionReview userInfo.
type Actor struct {
	Username string   `json:"username"`
	UID      string   `json:"uid,omitempty"`
	Groups   []string `json:"groups,omitempty"`
}

// Resolver resolves a policy's current contributions in a namespace.
type Resolver interface {
	Resolve(ctx context.Context, ns targeting.NamespaceRef, policy string) (Resolution, error)
}

// Resolution is the current targeting result for one policy in one namespace.
type Resolution struct {
	// Eligibility is nil when no contribution applies the policy there.
	Eligibility *targeting.Eligibility
	// Restrictive names the bindings whose contribution does not permit
	// SelfService, sorted.
	Restrictive []string
}

// Mutator records the acceptance on creation and explicit renewal, and the
// revocation when spec.revoked becomes true. It only reads the cluster, so
// dry-run requests have no side effects.
type Mutator struct {
	Reader   client.Reader
	Resolver Resolver
	Cluster  string
	Now      func() time.Time
	Decoder  admission.Decoder
	// HistoryNamespace holds the independent revocation records a renewal
	// of a revoked revision must find first (the snapshot namespace).
	HistoryNamespace string
}

// Handle implements admission.Handler.
func (m *Mutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	updated, err := m.record(ctx, req)
	var bad badRequest
	var denied *Denial
	switch {
	case errors.As(err, &denied):
		return admission.Denied(denied.Error())
	case errors.As(err, &bad):
		return admission.Errored(http.StatusBadRequest, err)
	case err != nil:
		// Fail closed: an acceptance without its resolved set is not recorded.
		return admission.Errored(http.StatusInternalServerError, err)
	case updated == nil:
		return admission.Allowed("no acceptance or revocation in this operation")
	}
	current, err := json.Marshal(updated)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, current)
}

type badRequest struct{ error }

// record returns the exception with its acceptance or revocation recorded,
// or nil when the operation is neither.
func (m *Mutator) record(ctx context.Context, req admission.Request) (*v1alpha1.ComplianceException, error) {
	ex, old, err := decode(m.Decoder, req)
	if err != nil {
		return nil, badRequest{err}
	}
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	op, d := classify(req, ex, old)
	switch {
	case d != nil:
		return nil, d
	case op == opRevocation:
		return revoke(req, ex, old, now())
	case !op.accepting():
		return nil, nil
	case op == opRenewalOfRevoked:
		// Before resolving anything: the renewal replaces the revocation
		// record, so its independent copy must already be durable.
		if err := renewable(ctx, m.Reader, m.HistoryNamespace, old); err != nil {
			return nil, err
		}
	}
	ns := &corev1.Namespace{}
	if err := m.Reader.Get(ctx, client.ObjectKey{Name: req.Namespace}, ns); err != nil {
		return nil, fmt.Errorf("read namespace identity: %w", err)
	}
	ref := targeting.NamespaceRef{Name: ns.Name, UID: ns.UID}
	res, err := m.Resolver.Resolve(ctx, ref, ex.Spec.Policy)
	if err != nil {
		return nil, fmt.Errorf("resolve policy contributions: %w", err)
	}
	el := res.Eligibility
	a := Acceptance{
		Revision:    ex.Spec.AcceptanceRevision,
		AcceptedAt:  metav1.NewTime(now().UTC().Truncate(time.Second)),
		Actor:       actorOf(req),
		Claim:       ex.Annotations[ClaimAnnotation],
		Cluster:     m.Cluster,
		Namespace:   ref,
		Policy:      ex.Spec.Policy,
		Eligibility: el,
	}
	if d := admissible(a, ex.Spec.ExpiresAt.Time, res.Restrictive); d != nil {
		return nil, d
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	updated := ex.DeepCopy()
	if updated.Annotations == nil {
		updated.Annotations = map[string]string{}
	}
	// Overwrites any caller-supplied value.
	updated.Annotations[AcceptanceAnnotation] = string(raw)
	if op == opRenewalOfRevoked {
		// The revoked revision's intent lives on in its independent record.
		delete(updated.Annotations, RevocationAnnotation)
	}
	return updated, nil
}

// Validator rejects acceptance and revocation records that do not belong to
// the operation: on an acceptance or a revocation the record must name the
// authenticated caller and the requested revision; on any other update both
// records, and the revocation finalizer, must be unchanged. Only the
// controller identity releases the finalizer, and only once the revocation
// is durably recorded independently; a renewal of a revoked revision needs
// that record too.
type Validator struct {
	Decoder admission.Decoder
	Cluster string
	Now     func() time.Time
	// Reader reads independent revocation records in HistoryNamespace. It
	// is used only for a renewal of a revoked revision and a finalizer
	// release; a revocation reads nothing.
	Reader           client.Reader
	HistoryNamespace string
	// Controller is the identity the Konstapel controller runs as.
	Controller *Identity
}

// acceptanceSkew bounds how far a recorded acceptance or revocation time may
// be from the validating webhook's clock in the same request.
const acceptanceSkew = 2 * time.Minute

// Handle implements admission.Handler.
func (v *Validator) Handle(ctx context.Context, req admission.Request) admission.Response {
	ex, old, err := decode(v.Decoder, req)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	if err := v.check(ctx, req, ex, old, now()); err != nil {
		return admission.Denied(err.Error())
	}
	return admission.Allowed("")
}

// controller reports whether the request comes from the controller
// identity. The identity is looked up only when the request releases the
// revocation finalizer, which no other identity may do; otherwise the
// cached identity is used, so a revocation still reads nothing.
func (v *Validator) controller(ctx context.Context, req admission.Request, ex, old *v1alpha1.ComplianceException) (bool, error) {
	identity := v.Controller.Cached()
	releases := old != nil && slices.Contains(old.Finalizers, RevocationFinalizer) && !slices.Contains(ex.Finalizers, RevocationFinalizer)
	if identity == "" && releases {
		var err error
		if identity, err = v.Controller.Get(ctx); err != nil {
			return false, fmt.Errorf("finalizer %s is released only by the Konstapel controller, whose identity is unknown: %w", RevocationFinalizer, err)
		}
	}
	return identity != "" && req.UserInfo.Username == identity, nil
}

func (v *Validator) check(ctx context.Context, req admission.Request, ex, old *v1alpha1.ComplianceException, now time.Time) error {
	op, d := classify(req, ex, old)
	if d != nil {
		return d
	}
	isController, err := v.controller(ctx, req, ex, old)
	switch {
	case err != nil:
		return err
	case isController && old == nil:
		return &Denial{ReasonProtectedField, "the Konstapel controller identity cannot create an exception"}
	case isController:
		return checkController(ctx, v.Reader, v.HistoryNamespace, req.UserInfo.Username, op, ex, old)
	case op == opRenewalOfRevoked:
		if err := renewable(ctx, v.Reader, v.HistoryNamespace, old); err != nil {
			return err
		}
	}
	if err := checkRevocation(req, op, ex, old, now); err != nil {
		return err
	}
	cluster := v.Cluster
	got, present := ex.Annotations[AcceptanceAnnotation]
	if !op.accepting() {
		was, wasPresent := old.Annotations[AcceptanceAnnotation]
		if got != was || present != wasPresent {
			return fmt.Errorf("%s is protected: it changes only with an explicit renewal (spec.acceptanceRevision + 1)", AcceptanceAnnotation)
		}
		return nil
	}
	if !present {
		return fmt.Errorf("%s is missing: the exception acceptance webhook did not record this acceptance", AcceptanceAnnotation)
	}
	var a Acceptance
	if err := json.Unmarshal([]byte(got), &a); err != nil {
		return fmt.Errorf("%s is not a valid acceptance record: %w", AcceptanceAnnotation, err)
	}
	actor := actorOf(req)
	switch {
	case a.Revision != ex.Spec.AcceptanceRevision:
		return fmt.Errorf("%s records revision %d, not %d", AcceptanceAnnotation, a.Revision, ex.Spec.AcceptanceRevision)
	case a.Actor.Username != actor.Username || a.Actor.UID != actor.UID || !slices.Equal(a.Actor.Groups, actor.Groups):
		return fmt.Errorf("%s does not name the authenticated caller", AcceptanceAnnotation)
	case a.Namespace.Name != req.Namespace:
		return fmt.Errorf("%s records namespace %q, not %q", AcceptanceAnnotation, a.Namespace.Name, req.Namespace)
	case a.Policy != ex.Spec.Policy:
		return fmt.Errorf("%s records policy %q, not %q", AcceptanceAnnotation, a.Policy, ex.Spec.Policy)
	case a.Claim != ex.Annotations[ClaimAnnotation]:
		return fmt.Errorf("%s records a different claim than %s", AcceptanceAnnotation, ClaimAnnotation)
	case a.Cluster != cluster:
		return fmt.Errorf("%s records cluster %q, not %q", AcceptanceAnnotation, a.Cluster, cluster)
	case a.AcceptedAt.Time.Sub(now).Abs() > acceptanceSkew:
		return fmt.Errorf("%s acceptance time %s is not this request's", AcceptanceAnnotation, a.AcceptedAt.UTC().Format(time.RFC3339))
	}
	// The record must itself be admissible, so an acceptance never stands on
	// an ineligible or over-long record even without the mutating webhook.
	if d := admissible(a, ex.Spec.ExpiresAt.Time, nil); d != nil {
		return d
	}
	return nil
}

func actorOf(req admission.Request) Actor {
	return Actor{Username: req.UserInfo.Username, UID: req.UserInfo.UID, Groups: slices.Clone(req.UserInfo.Groups)}
}

func decode(d admission.Decoder, req admission.Request) (ex, old *v1alpha1.ComplianceException, err error) {
	ex = &v1alpha1.ComplianceException{}
	if err := d.Decode(req, ex); err != nil {
		return nil, nil, err
	}
	if req.Operation == admissionv1.Update {
		old = &v1alpha1.ComplianceException{}
		if err := d.DecodeRaw(req.OldObject, old); err != nil {
			return nil, nil, err
		}
	}
	return ex, old, nil
}

// ClusterResolver resolves eligibility from the live profiles and bindings
// through the targeting resolver, exactly as the binding controller does.
type ClusterResolver struct {
	Reader  client.Reader
	Content targeting.ContentSource
	Cluster string
}

// Resolve implements Resolver.
func (r *ClusterResolver) Resolve(ctx context.Context, ns targeting.NamespaceRef, policy string) (Resolution, error) {
	el, restrictive, err := r.resolve(ctx, ns, policy)
	return Resolution{Eligibility: el, Restrictive: restrictive}, err
}

func (r *ClusterResolver) resolve(ctx context.Context, ns targeting.NamespaceRef, policy string) (*targeting.Eligibility, []string, error) {
	namespace := &corev1.Namespace{}
	if err := r.Reader.Get(ctx, client.ObjectKey{Name: ns.Name}, namespace); err != nil {
		return nil, nil, err
	}
	if namespace.UID != ns.UID {
		return nil, nil, fmt.Errorf("namespace %s was recreated during admission", ns.Name)
	}
	in := targeting.Input{Cluster: r.Cluster, Namespaces: []targeting.Namespace{{Name: namespace.Name, UID: namespace.UID, Labels: namespace.Labels}}}
	var bindings v1alpha1.ComplianceBindingList
	if err := r.Reader.List(ctx, &bindings); err != nil {
		return nil, nil, err
	}
	var profiles v1alpha1.ComplianceProfileList
	if err := r.Reader.List(ctx, &profiles); err != nil {
		return nil, nil, err
	}
	in.Bindings, in.Profiles = bindings.Items, profiles.Items
	// Content is resolved once per name and digest, the resolution identity:
	// a reference that does not resolve (for example an unconfigured name
	// pinning a digest another name also pins) makes only its own consumers
	// unresolved, and never stands in for, or hides, another name's content.
	seen := map[v1alpha1.BundleReference]bool{}
	for _, p := range profiles.Items {
		if seen[p.Spec.Bundle] {
			continue
		}
		seen[p.Spec.Bundle] = true
		c, err := r.Content.Content(ctx, p.Spec.Bundle)
		switch {
		case errors.Is(err, targeting.ErrContentUnavailable):
			// The resolver reports ContentUnavailable, which forbids exceptions.
		case err != nil:
			return nil, nil, err
		default:
			in.Bundles = append(in.Bundles, c.Bundle)
		}
	}
	res := targeting.Resolve(in)
	var restrictive []string
	var errs []targeting.ResolutionError
	for _, b := range res.Bindings {
		if !slices.ContainsFunc(b.Targets, func(t targeting.NamespaceRef) bool { return t.UID == ns.UID }) {
			continue
		}
		for _, c := range b.Contributions {
			if c.Policy == policy && (c.Exceptions.Eligibility != v1alpha1.ExceptionsSelfService || c.Exceptions.MaxLifetime == nil) {
				restrictive = append(restrictive, b.Binding.Name)
			}
		}
		for _, e := range b.Errors {
			if e.Policy == "" || e.Policy == policy {
				errs = append(errs, e)
			}
		}
	}
	slices.Sort(restrictive)
	restrictive = slices.Compact(restrictive)
	for _, e := range res.Eligibility {
		if e.Namespace.UID == ns.UID && e.Policy == policy {
			return &e, restrictive, nil
		}
	}
	if len(errs) > 0 {
		// A binding that targets the namespace failed to resolve (for
		// example its content is unavailable), so the policy may apply here:
		// that is unresolved eligibility, not an unapplied policy.
		return &targeting.Eligibility{Namespace: ns, Policy: policy, Effective: v1alpha1.ExceptionsForbidden,
			Contributors: []targeting.ContributionRef{}, Errors: errs}, restrictive, nil
	}
	return nil, restrictive, nil
}

// NewHandlers builds the mutating and validating handlers. historyNamespace
// holds the independent revocation records; controller is the identity the
// Konstapel controller runs as.
func NewHandlers(scheme *runtime.Scheme, reader client.Reader, content targeting.ContentSource, cluster, historyNamespace string, controller *Identity) (*Mutator, *Validator) {
	d := admission.NewDecoder(scheme)
	return &Mutator{Reader: reader, Resolver: &ClusterResolver{Reader: reader, Content: content, Cluster: cluster}, Cluster: cluster, Decoder: d, HistoryNamespace: historyNamespace},
		&Validator{Decoder: d, Cluster: cluster, Reader: reader, HistoryNamespace: historyNamespace, Controller: controller}
}

// Register adds both handlers to a webhook server.
func Register(srv webhook.Server, m *Mutator, v *Validator) {
	srv.Register(MutatePath, &webhook.Admission{Handler: m})
	srv.Register(ValidatePath, &webhook.Admission{Handler: v})
}
