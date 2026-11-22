package preview

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/exception"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// This file is the read-only cluster observation (tasks 2.1 to 2.3, with the
// named Secret reads of 4.3 and the exception revocation inputs of 2.5). It reads the selected cluster with the caller's
// own credentials, using only GET requests: discovery, get and list. It never
// writes, never watches and never sends server-side dry-run or authorization
// probes. The only Secrets it requests are those the observed bundle-source
// configuration references, each by name in the controller namespace; it never
// lists Secrets, and their values never reach a report.

// ObserveLimits bounds one observation. Hitting any limit, a timeout or a
// cancellation makes the snapshot incomplete; nothing is silently truncated.
type ObserveLimits struct {
	// Timeout bounds the whole observation, rechecks and recaptures included.
	Timeout time.Duration
	// MaxRecaptures bounds how often the whole capture is repeated after
	// relevant drift or expired pagination. The design allows at most two.
	MaxRecaptures int
	// MaxObjects bounds the objects collected by one capture.
	MaxObjects int
	// PageSize is the list page size (limit).
	PageSize int64
	// MaxPages bounds the requests of one capture, discovery excluded.
	MaxPages int
	// MaxResponseBytes bounds the response bytes read by one capture.
	MaxResponseBytes int64
}

// DefaultObserveLimits are the design limits: 60 seconds in total, at most two
// recaptures and 100,000 collected objects.
func DefaultObserveLimits() ObserveLimits {
	return ObserveLimits{Timeout: 60 * time.Second, MaxRecaptures: 2, MaxObjects: 100_000, PageSize: 500, MaxPages: 1_000, MaxResponseBytes: 512 << 20}
}

func (l ObserveLimits) withDefaults() (ObserveLimits, error) {
	d := DefaultObserveLimits()
	if l.Timeout <= 0 {
		l.Timeout = d.Timeout
	}
	if l.MaxRecaptures <= 0 {
		l.MaxRecaptures = d.MaxRecaptures
	}
	if l.MaxRecaptures > d.MaxRecaptures {
		return l, fmt.Errorf("at most %d recaptures are allowed", d.MaxRecaptures)
	}
	if l.MaxObjects <= 0 {
		l.MaxObjects = d.MaxObjects
	}
	if l.PageSize <= 0 {
		l.PageSize = d.PageSize
	}
	if l.MaxPages <= 0 {
		l.MaxPages = d.MaxPages
	}
	if l.MaxResponseBytes <= 0 {
		l.MaxResponseBytes = d.MaxResponseBytes
	}
	return l, nil
}

// ObserveOptions selects the cluster and the Konstapel installation to read.
type ObserveOptions struct {
	// Config is the caller's own identity, typically from RESTConfig. The
	// observation never substitutes another identity such as the
	// controller's ServiceAccount.
	Config *rest.Config
	// Context is the kubeconfig context name, recorded as provenance.
	Context string
	// Namespace is the Konstapel controller namespace (POD_NAMESPACE of the
	// controller). Acceptance snapshots and the bundle-source configuration
	// live there.
	Namespace string
	// SourcesConfigMap is the controller's --bundle-sources-configmap, or
	// empty when the controller serves only vendored content.
	SourcesConfigMap string
	Limits           ObserveLimits
	// Now is the clock; time.Now when nil.
	Now func() time.Time
}

// ObserveCode classifies an observation diagnostic.
type ObserveCode string

// Error codes make a snapshot incomplete.
const (
	ObserveAccessDenied      ObserveCode = "access-denied"
	ObserveUnauthorized      ObserveCode = "unauthorized"
	ObserveAPIUnavailable    ObserveCode = "api-unavailable"
	ObserveNotFound          ObserveCode = "not-found"
	ObservePaginationExpired ObserveCode = "pagination-expired"
	ObserveUnstable          ObserveCode = "unstable"
	ObserveObjectLimit       ObserveCode = "object-limit"
	ObservePageLimit         ObserveCode = "page-limit"
	ObserveByteLimit         ObserveCode = "byte-limit"
	ObserveTimeout           ObserveCode = "timeout"
	ObserveCanceled          ObserveCode = "canceled"
	ObserveRequestFailed     ObserveCode = "request-failed"
	ObserveInvalidObject     ObserveCode = "invalid-object"
	ObserveRefusedRequest    ObserveCode = "refused-request"
)

// Limitation codes are informational: they bound what a complete snapshot
// means without making it incomplete.
const (
	// LimitNoAtomicSnapshot: Kubernetes has no cross-resource transaction.
	LimitNoAtomicSnapshot ObserveCode = "no-atomic-snapshot"
	// Revocation limitations (observe_revocation.go), one per exception whose
	// current acceptance revision is revoked, by what the observation could
	// verify with the exception owner's own checks:
	//
	// LimitRevocationRecorded: spec.revoked, the admission-protected
	// revocation record and a matching independent revocation record agree.
	LimitRevocationRecorded ObserveCode = "exception-revocation-recorded"
	// LimitRevocationPending: no independent revocation record exists yet.
	LimitRevocationPending ObserveCode = "exception-revocation-pending"
	// LimitRevocationProcessingDisabled: no independent record exists, and
	// the controller reports that revocation processing is disabled.
	LimitRevocationProcessingDisabled ObserveCode = "exception-revocation-processing-disabled"
	// LimitRevocationConflict: the object at the record's name does not hold
	// this revocation.
	LimitRevocationConflict ObserveCode = "exception-revocation-conflict"
	// LimitRevocationInvalid: spec.revoked and the protected revocation
	// record do not form a recordable revocation of the current revision.
	LimitRevocationInvalid ObserveCode = "exception-revocation-invalid"
	// LimitRevocationRecordInvalid: a revocation record ConfigMap does not
	// verify against its recorded digest and format.
	LimitRevocationRecordInvalid ObserveCode = "exception-revocation-record-invalid"
	// LimitSourcesNotSelected: no bundle-source ConfigMap was named, so only
	// vendored content can be resolved.
	LimitSourcesNotSelected ObserveCode = "bundle-sources-not-selected"
	// LimitSecretNotRead: a source references a Secret that the caller may
	// not read. Content from that source cannot be resolved by this preview.
	LimitSecretNotRead ObserveCode = "secret-not-read"
	// LimitSourcesUnusable: the named source configuration is missing or
	// invalid, as the controller would also find it.
	LimitSourcesUnusable ObserveCode = "bundle-sources-unusable"
)

// Diagnostic is one coded observation error or limitation.
type Diagnostic struct {
	Code ObserveCode `json:"code"`
	// Resource is group/version/resource ("" group for core) when known.
	Resource  string `json:"resource,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
	Message   string `json:"message"`
}

func (d Diagnostic) Error() string {
	var b strings.Builder
	if d.Resource != "" {
		b.WriteString(d.Resource)
		if d.Namespace != "" {
			b.WriteString(" in " + d.Namespace)
		}
		if d.Name != "" {
			b.WriteString(" " + d.Name)
		}
		b.WriteString(": ")
	}
	fmt.Fprintf(&b, "%s [%s]", d.Message, d.Code)
	return b.String()
}

// IncompleteError is returned with an incomplete snapshot. It carries the
// snapshot's errors.
type IncompleteError struct{ Errors []Diagnostic }

func (e *IncompleteError) Error() string {
	parts := make([]string, len(e.Errors))
	for i, d := range e.Errors {
		parts[i] = d.Error()
	}
	return "incomplete cluster observation: " + strings.Join(parts, "; ")
}

// ObjectRef is the observed identity and revision of one object.
type ObjectRef struct {
	// Resource is group/version/resource ("" group for core).
	Resource        string    `json:"resource"`
	Namespace       string    `json:"namespace,omitempty"`
	Name            string    `json:"name"`
	UID             types.UID `json:"uid"`
	ResourceVersion string    `json:"resourceVersion"`
	Generation      int64     `json:"generation,omitempty"`
}

// Collection is the provenance of one list or get.
type Collection struct {
	Resource      string `json:"resource"`
	Namespace     string `json:"namespace,omitempty"`
	LabelSelector string `json:"labelSelector,omitempty"`
	// Name is set for a get of one named object.
	Name string `json:"name,omitempty"`
	// ResourceVersion is the list's resourceVersion from its first page,
	// which the following pages continue consistently.
	ResourceVersion string `json:"resourceVersion,omitempty"`
	Pages           int    `json:"pages"`
	Objects         int    `json:"objects"`
}

// ObservedNamespace is one namespace instance. Name and UID together identify
// it: a recreated namespace is a different instance.
type ObservedNamespace struct {
	Name            string            `json:"name"`
	UID             types.UID         `json:"uid"`
	ResourceVersion string            `json:"resourceVersion"`
	Labels          map[string]string `json:"labels"`
	Terminating     bool              `json:"terminating,omitempty"`
}

// Ownership of a Konstapel-labelled engine policy.
type Ownership string

const (
	// Owned: ownership labels and a controller reference agree on the UID of
	// an observed binding.
	Owned Ownership = "owned"
	// Orphaned: labels and controller reference agree, but no observed
	// binding has that UID (deleted or recreated). Such a policy may still
	// enforce until garbage collection removes it.
	Orphaned Ownership = "orphaned"
)

// AppliedPolicy is one observed engine policy owned through Konstapel's
// ownership rule (targeting.OwnedBy). Its provenance is read from the policy
// itself; it is observed state, never the desired configuration.
type AppliedPolicy struct {
	ObjectRef
	Ownership  Ownership `json:"ownership"`
	BindingUID types.UID `json:"bindingUID"`
	// Ready is the engine's acceptance (targeting.KyvernoReady).
	Ready bool `json:"ready"`
	// Contribution is the applied contribution recorded on the policy, or
	// nil with ProvenanceError when it cannot be read. Such a policy is
	// unknown applied state, not an absent one.
	Contribution    *targeting.Contribution `json:"contribution,omitempty"`
	ProvenanceError string                  `json:"provenanceError,omitempty"`
	Terminating     bool                    `json:"terminating,omitempty"`
}

// ObservedException is the acceptance-relevant projection of one
// ComplianceException. Free-text reasons, actors and claims are not kept.
type ObservedException struct {
	ObjectRef
	Policy             string      `json:"policy"`
	AcceptanceRevision int64       `json:"acceptanceRevision"`
	ExpiresAt          time.Time   `json:"expiresAt"`
	Terminating        bool        `json:"terminating,omitempty"`
	Acceptance         *Acceptance `json:"acceptance,omitempty"`
	// AcceptanceError is set when the protected acceptance record is present
	// but unreadable.
	AcceptanceError string `json:"acceptanceError,omitempty"`
	// Snapshot is the controller's status reference to the frozen snapshot.
	Snapshot *v1alpha1.AcceptanceSnapshotReference `json:"snapshot,omitempty"`
	// Revoked is spec.revoked.
	Revoked bool `json:"revoked,omitempty"`
	// Revocation is set when the current revision is revoked, or carries a
	// revocation record or finalizer.
	Revocation *ObservedRevocation `json:"revocation,omitempty"`
}

// RevocationState is what the observation verified about a revocation,
// with the exception owner's checks (exception.NewRevocationRecord and
// exception.VerifyHistory).
type RevocationState string

const (
	// RevocationRecorded: a durable independent record holds exactly this
	// revocation.
	RevocationRecorded RevocationState = "recorded"
	// RevocationPending: no independent record exists yet; the revocation is
	// recorded only on the resource.
	RevocationPending RevocationState = "pending"
	// RevocationConflict: the object at the record's name is not the
	// matching record.
	RevocationConflict RevocationState = "conflict"
	// RevocationInvalid: the revocation cannot be recorded (for example, the
	// protected revocation record is missing or names another revision).
	RevocationInvalid RevocationState = "invalid"
)

// ObservedRevocation is the revocation of an exception's current acceptance
// revision. The revoking actor and claim are not kept.
type ObservedRevocation struct {
	State RevocationState `json:"state"`
	// Revision and RequestedAt come from the admission-protected revocation
	// record, when it is readable. RequestedAt is when revocation was
	// requested, not when an engine stopped granting.
	Revision    int64      `json:"revision,omitempty"`
	RequestedAt *time.Time `json:"requestedAt,omitempty"`
	// Finalizer is true while the revocation finalizer holds the exception.
	Finalizer bool `json:"finalizer,omitempty"`
	// Record is the independent record's name in the controller namespace
	// (unset when invalid); RecordDigest is its digest once recorded.
	Record       string `json:"record,omitempty"`
	RecordDigest string `json:"recordDigest,omitempty"`
	// Owner is the controller's RevocationRecorded condition, without its
	// message and timestamps; nil when the exception has none.
	Owner *OwnerCondition `json:"owner,omitempty"`
}

// OwnerCondition is a condition as the owning controller reported it.
// Current is false when it describes an older generation of the object.
type OwnerCondition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	Reason             string `json:"reason"`
	ObservedGeneration int64  `json:"observedGeneration"`
	Current            bool   `json:"current"`
}

// ObservedRevocationRecord is one independent revocation record ConfigMap
// in the controller namespace, verified with exception.RevocationRecordFrom.
// The revoking actor and claim are not kept.
type ObservedRevocationRecord struct {
	ObjectRef
	Digest string `json:"digest,omitempty"`
	// VerifyError is set when the record does not verify; the identity
	// fields are then empty.
	VerifyError        string                                `json:"verifyError,omitempty"`
	Cluster            string                                `json:"cluster,omitempty"`
	ExceptionUID       types.UID                             `json:"exceptionUID,omitempty"`
	ExceptionName      string                                `json:"exceptionName,omitempty"`
	ExceptionNamespace string                                `json:"exceptionNamespace,omitempty"`
	AcceptanceRevision int64                                 `json:"acceptanceRevision,omitempty"`
	Namespace          targeting.NamespaceRef                `json:"namespace"`
	Policy             string                                `json:"policy,omitempty"`
	RequestedAt        *time.Time                            `json:"requestedAt,omitempty"`
	Acceptance         *v1alpha1.AcceptanceSnapshotReference `json:"acceptance,omitempty"`
}

// Acceptance is the identity part of the protected acceptance record.
type Acceptance struct {
	Revision     int64                  `json:"revision"`
	Cluster      string                 `json:"cluster"`
	Namespace    targeting.NamespaceRef `json:"namespace"`
	Policy       string                 `json:"policy"`
	AcceptedAt   time.Time              `json:"acceptedAt"`
	Contributors int                    `json:"contributors"`
}

// ObservedAcceptanceSnapshot is one frozen acceptance snapshot ConfigMap in
// the controller namespace, verified against its recorded digest.
type ObservedAcceptanceSnapshot struct {
	ObjectRef
	Digest string `json:"digest,omitempty"`
	// VerifyError is set when the document does not match its recorded
	// digest or cannot be decoded; the identity fields are then empty.
	VerifyError        string                 `json:"verifyError,omitempty"`
	Cluster            string                 `json:"cluster,omitempty"`
	ExceptionUID       types.UID              `json:"exceptionUID,omitempty"`
	ExceptionName      string                 `json:"exceptionName,omitempty"`
	ExceptionNamespace string                 `json:"exceptionNamespace,omitempty"`
	AcceptanceRevision int64                  `json:"acceptanceRevision,omitempty"`
	Namespace          targeting.NamespaceRef `json:"namespace"`
	Policy             string                 `json:"policy,omitempty"`
	ExpiresAt          time.Time              `json:"expiresAt"`
	// Eligibility is the frozen accepted contribution set.
	Eligibility *targeting.Eligibility `json:"eligibility,omitempty"`
}

// ObservedSources is the controller's central bundle-source configuration, as
// read from its ConfigMap. Referenced Secrets are read by name with the
// caller's identity; only their identity and access outcome are reported.
type ObservedSources struct {
	ConfigMap ObjectRef `json:"configMap"`
	// Missing is true when the named ConfigMap does not exist.
	Missing bool `json:"missing,omitempty"`
	// Digest identifies the ConfigMap data.
	Digest string `json:"digest,omitempty"`
	// ParseError is set when the document is invalid; Sources is then empty.
	ParseError string           `json:"parseError,omitempty"`
	Sources    []ObservedSource `json:"sources,omitempty"`
	// TrustConfigMaps are the referenced CA, trust-root and public-key
	// ConfigMaps, sorted by name and key.
	TrustConfigMaps []ObservedTrustObject `json:"trustConfigMaps,omitempty"`
	// Secrets are the referenced Secrets (credentials or trust material),
	// sorted by name: identity and access only, never their data.
	Secrets []ObservedSecret `json:"secrets,omitempty"`
	// UnreadSecrets names the referenced Secrets the caller may not read.
	UnreadSecrets []string `json:"unreadSecrets,omitempty"`
}

// SecretAccess is the outcome of reading one referenced Secret.
type SecretAccess string

const (
	// SecretRead: the caller read the Secret by name.
	SecretRead SecretAccess = "read"
	// SecretMissing: the Secret does not exist, as the controller would also
	// find.
	SecretMissing SecretAccess = "missing"
	// SecretDenied: the caller may not read the Secret (forbidden or
	// unauthorized). The preview never substitutes another identity.
	SecretDenied SecretAccess = "denied"
)

// ObservedSecret is one referenced Secret: its identity, the keys the
// sources reference and whether the caller could read it. Its data is
// held only in memory for the bundle content adapter and never reported.
type ObservedSecret struct {
	ObjectRef
	Keys   []string     `json:"keys"`
	Access SecretAccess `json:"access"`
}

// ObservedSource is the non-secret part of one source mapping.
type ObservedSource struct {
	Name       string `json:"name"`
	Repository string `json:"repository"`
	Publisher  string `json:"publisher"`
}

// ObservedTrustObject is one referenced non-secret trust ConfigMap key.
type ObservedTrustObject struct {
	ObjectRef
	Key     string `json:"key"`
	Missing bool   `json:"missing,omitempty"`
	Digest  string `json:"digest,omitempty"`
}

// Drift records the relevant objects that differed between two consecutive
// captures, which forced a recapture.
type Drift struct {
	// Capture is the 1-based capture that observed the change.
	Capture int `json:"capture"`
	// Changed lists "resource namespace/name" keys, sorted and bounded.
	Changed []string `json:"changed"`
	// Truncated counts changed keys beyond the listed ones.
	Truncated int `json:"truncated,omitempty"`
	// Reason is "drift" or "pagination-expired".
	Reason string `json:"reason"`
}

// Snapshot is one bounded, attributable observation. Only a Complete snapshot
// carries object sets; an incomplete one carries provenance and diagnostics
// only, so a partial read can never be compared as if it were the cluster.
type Snapshot struct {
	Complete bool `json:"complete"`
	// Cluster is the controller's cluster identity: "kube-system:<uid>".
	Cluster string `json:"cluster,omitempty"`
	Context string `json:"context,omitempty"`
	// Server is the API server host (scheme and userinfo removed).
	Server    string    `json:"server,omitempty"`
	Namespace string    `json:"namespace"`
	Start     time.Time `json:"start"`
	End       time.Time `json:"end"`
	// Captures counts capture passes: the first, its recheck, and any
	// recapture, including passes that expired pagination cut short.
	Captures int     `json:"captures"`
	Drift    []Drift `json:"drift,omitempty"`
	// Collections is the provenance of the final capture's reads.
	Collections []Collection `json:"collections"`
	// Objects is the identity and revision of every observed object of the
	// final capture, sorted by resource, namespace and name.
	Objects    []ObjectRef         `json:"objects,omitempty"`
	Live       Live                `json:"-"`
	Namespaces []ObservedNamespace `json:"namespaces,omitempty"`
	Applied    []AppliedPolicy     `json:"applied,omitempty"`
	// Unowned are Konstapel-labelled engine policies without a matching
	// controller reference. They are never treated as owned.
	Unowned             []ObjectRef                  `json:"unowned,omitempty"`
	Exceptions          []ObservedException          `json:"exceptions,omitempty"`
	AcceptanceSnapshots []ObservedAcceptanceSnapshot `json:"acceptanceSnapshots,omitempty"`
	// RevocationRecords are the independent revocation records in the
	// controller namespace, of every revision ever revoked.
	RevocationRecords []ObservedRevocationRecord `json:"revocationRecords,omitempty"`
	Sources           *ObservedSources           `json:"sources,omitempty"`
	// Evidence is every live binding's recorded evidence state
	// (evidence.go), informational and not rechecked.
	Evidence []ObservedEvidence `json:"evidence,omitempty"`
	// inputs is the observed source configuration and the referenced
	// objects' values, for the bundle content adapter (content.go). It holds
	// Secret data: it is never serialized and formats as redacted.
	inputs *sourceInputs
	// Contracts records the consumed contract versions.
	Contracts   map[string]int `json:"contracts"`
	Limitations []Diagnostic   `json:"limitations,omitempty"`
	Errors      []Diagnostic   `json:"errors,omitempty"`
}

// TargetingNamespaces returns the namespaces in the resolver's input form.
func (s *Snapshot) TargetingNamespaces() []targeting.Namespace {
	out := make([]targeting.Namespace, 0, len(s.Namespaces))
	for _, n := range s.Namespaces {
		out = append(out, targeting.Namespace{Name: n.Name, UID: n.UID, Labels: n.Labels})
	}
	return out
}

// Resources the observation reads.
var (
	gvrNamespaces   = schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}
	gvrConfigMaps   = schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}
	gvrSecrets      = schema.GroupVersionResource{Version: "v1", Resource: "secrets"}
	gvrProfiles     = v1alpha1.GroupVersion.WithResource("complianceprofiles")
	gvrBindings     = v1alpha1.GroupVersion.WithResource("compliancebindings")
	gvrExceptions   = v1alpha1.GroupVersion.WithResource("complianceexceptions")
	gvrEnginePolicy = schema.GroupVersionResource{Group: targeting.ValidatingPolicyGVK.Group, Version: targeting.ValidatingPolicyGVK.Version, Resource: "validatingpolicies"}
)

func resourceString(g schema.GroupVersionResource) string {
	return g.Group + "/" + g.Version + "/" + g.Resource
}

// Observe reads one snapshot. It returns the snapshot together with an
// *IncompleteError when the snapshot is incomplete; invalid options return
// only an error. The context bounds the observation in addition to
// Limits.Timeout.
func Observe(ctx context.Context, opts ObserveOptions) (*Snapshot, error) {
	lim, err := opts.Limits.withDefaults()
	if err != nil {
		return nil, err
	}
	if opts.Config == nil {
		return nil, errors.New("a Kubernetes client configuration is required")
	}
	if opts.Namespace == "" {
		return nil, errors.New("the Konstapel controller namespace is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	r, err := newReader(opts.Config, lim, opts.Namespace)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, lim.Timeout)
	defer cancel()

	snap := &Snapshot{Context: opts.Context, Server: serverHost(opts.Config.Host), Namespace: opts.Namespace, Start: now().UTC(),
		Contracts: map[string]int{"targeting": targeting.ContractVersion, "acceptanceSnapshot": exception.SnapshotVersion,
			"revocationRecord": exception.RevocationRecordVersion}}
	finish := func(final *capture, errs []Diagnostic) (*Snapshot, error) {
		snap.End = now().UTC()
		if final != nil {
			snap.Collections = final.collections
		}
		if len(errs) > 0 {
			snap.Errors = sortDiagnostics(errs)
			return snap, &IncompleteError{Errors: snap.Errors}
		}
		final.fill(snap, opts)
		snap.Complete = true
		return snap, nil
	}

	if d := r.discover(ctx); d != nil {
		return finish(nil, []Diagnostic{*d})
	}
	// Each capture is a complete, paginated read of every relevant
	// projection. The first is rechecked by the second; relevant drift (or an
	// expired continuation) forces another capture, at most MaxRecaptures
	// times. Only relevant projections are compared, so a status timestamp
	// that changes on every read cannot force endless retries.
	var prev *capture
	recaptures := 0
	for {
		cur, diag := r.capture(ctx, opts)
		if diag != nil && diag.Code != ObservePaginationExpired {
			return finish(cur, []Diagnostic{*diag})
		}
		snap.Captures++
		if diag == nil && prev != nil {
			changed := diffProjections(prev.projections, cur.projections)
			if len(changed) == 0 {
				return finish(cur, nil)
			}
			snap.Drift = append(snap.Drift, newDrift(snap.Captures, "drift", changed))
		}
		if diag != nil {
			snap.Drift = append(snap.Drift, Drift{Capture: snap.Captures, Reason: "pagination-expired", Changed: []string{diag.Resource}})
			cur = nil
		} else if prev == nil {
			prev = cur
			continue // the recheck is not a recapture
		}
		if recaptures == lim.MaxRecaptures {
			last := snap.Drift[len(snap.Drift)-1]
			code, msg := ObserveUnstable, fmt.Sprintf("relevant configuration kept changing during observation after %d recaptures: %s", recaptures, strings.Join(last.Changed, ", "))
			if last.Reason == "pagination-expired" {
				code, msg = ObservePaginationExpired, fmt.Sprintf("list continuation expired and the read could not be completed after %d recaptures", recaptures)
			}
			return finish(cur, []Diagnostic{{Code: code, Resource: diagResource(diag), Message: msg}})
		}
		recaptures++
		if cur != nil {
			prev = cur
		}
	}
}

func diagResource(d *Diagnostic) string {
	if d == nil {
		return ""
	}
	return d.Resource
}

const maxDriftListed = 20

func newDrift(captureN int, reason string, changed []string) Drift {
	d := Drift{Capture: captureN, Reason: reason, Changed: changed}
	if len(changed) > maxDriftListed {
		d.Changed, d.Truncated = changed[:maxDriftListed], len(changed)-maxDriftListed
	}
	return d
}

func diffProjections(a, b map[string]string) []string {
	var out []string
	for k, v := range a {
		if b[k] != v {
			out = append(out, k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

func sortDiagnostics(ds []Diagnostic) []Diagnostic {
	slices.SortStableFunc(ds, func(a, b Diagnostic) int {
		return strings.Compare(string(a.Code)+"\x00"+a.Resource+"\x00"+a.Namespace+"\x00"+a.Name,
			string(b.Code)+"\x00"+b.Resource+"\x00"+b.Namespace+"\x00"+b.Name)
	})
	return slices.CompactFunc(ds, func(a, b Diagnostic) bool { return a == b })
}
