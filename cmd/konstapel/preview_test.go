package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/yaml"

	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"

	"github.com/backend-bunny/Konstapel/internal/preview"
)

// Command tests of `konstapel preview` (add-policy-change-preview 6.1 to
// 6.4). They run the real command against a recording Kubernetes API test
// server reached through a kubeconfig file, with the real vendored content
// tree, and replace the other commands' startup with hooks that fail the
// test if the preview ever reaches them.

var updateGolden = flag.Bool("update", false, "rewrite the preview golden reports")

// TestMain lets a test re-execute this binary as `konstapel` (process
// boundary tests): with KONSTAPEL_TEST_MAIN=1 it runs main with the given
// arguments instead of the tests.
func TestMain(m *testing.M) {
	if os.Getenv("KONSTAPEL_TEST_MAIN") == "1" {
		os.Args = append([]string{"konstapel"}, os.Args[1:]...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

const (
	pathNamespaces = "/api/v1/namespaces"
	pathProfiles   = "/apis/compliance.erenius.io/v1alpha1/complianceprofiles"
	pathBindings   = "/apis/compliance.erenius.io/v1alpha1/compliancebindings"
	pathExceptions = "/apis/compliance.erenius.io/v1alpha1/complianceexceptions"
	pathPolicies   = "/apis/policies.kyverno.io/v1/validatingpolicies"
	pathSnapshots  = "/api/v1/namespaces/konstapel-system/configmaps"
)

// fakeCluster is a small recording API server with fixed objects and
// revisions. It answers every non-GET request with 405 and records it.
type fakeCluster struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	lists    map[string][]map[string]any
	requests []string
	deny     map[string]bool
	delay    map[string]time.Duration
}

func vendoredDigest(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../content/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func obj(t *testing.T, doc string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func ns(name, uid, rv string, labels string) string {
	return fmt.Sprintf("{apiVersion: v1, kind: Namespace, metadata: {name: %s, uid: %s, resourceVersion: %q, labels: {%s}}}", name, uid, rv, labels)
}

const assessmentDefaults = "assessment: {interval: 24h, maxEvidenceAge: 2h, collectionTimeout: 5m, retention: 2160h}"

// newFakeCluster serves the shared world: namespaces prod and staging, the
// profile baseline (two vendored policies) used by the bindings deny-prod
// (Deny, env=production) and audit-all (Audit, every namespace).
func newFakeCluster(t *testing.T) *fakeCluster {
	t.Helper()
	d := vendoredDigest(t)
	f := &fakeCluster{t: t, deny: map[string]bool{}, delay: map[string]time.Duration{}, lists: map[string][]map[string]any{
		pathNamespaces: {
			obj(t, ns("konstapel-system", "ns-konstapel", "2", "")),
			obj(t, ns("kube-system", "ks-0001", "1", "")),
			obj(t, ns("prod", "ns-prod", "3", "env: production")),
			obj(t, ns("staging", "ns-staging", "4", "env: staging")),
		},
		pathProfiles: {obj(t, `{apiVersion: compliance.erenius.io/v1alpha1, kind: ComplianceProfile,
  metadata: {name: baseline, uid: p-baseline, resourceVersion: "11", generation: 1},
  spec: {bundle: {name: konstapel-vendored, digest: "`+d+`"}, policies: [
    {name: disallow-privileged-containers, exceptions: {eligibility: Forbidden}},
    {name: disallow-privilege-escalation, exceptions: {eligibility: Forbidden}}]}}`)},
		pathBindings: {
			obj(t, `{apiVersion: compliance.erenius.io/v1alpha1, kind: ComplianceBinding,
  metadata: {name: audit-all, uid: b-audit-all, resourceVersion: "12", generation: 1},
  spec: {profileRef: {name: baseline}, namespaceSelector: {}, mode: Audit, enforcementEpoch: 1, `+assessmentDefaults+`}}`),
			obj(t, `{apiVersion: compliance.erenius.io/v1alpha1, kind: ComplianceBinding,
  metadata: {name: deny-prod, uid: b-deny-prod, resourceVersion: "13", generation: 1},
  spec: {profileRef: {name: baseline}, namespaceSelector: {matchLabels: {env: production}}, mode: Deny, enforcementEpoch: 1, `+assessmentDefaults+`}}`),
		},
		pathExceptions: {},
		pathPolicies:   {},
		pathSnapshots:  {},
	}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// addException adds a ComplianceException in prod for the privileged
// container policy, without an acceptance record.
func (f *fakeCluster) addException() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lists[pathExceptions] = append(f.lists[pathExceptions], obj(f.t, `{apiVersion: compliance.erenius.io/v1alpha1, kind: ComplianceException,
  metadata: {name: legacy-app, namespace: prod, uid: ex-legacy, resourceVersion: "21", generation: 1},
  spec: {policy: disallow-privileged-containers, workloadSelector: {matchLabels: {app: legacy}}, reason: "migration", expiresAt: "2027-01-01T00:00:00Z", acceptanceRevision: 1}}`))
}

// Owner-recorded current evidence (status.assessment.current) for
// setEvidence, relative to fixedNow, the observation clock.
const (
	// evidenceCurrent: Complete, expires after the observation.
	evidenceCurrent = `{evidence: {completeness: Complete, expected: 4, attributable: 4, missing: 0, rejected: 0, unresolved: 0},
  outcomes: {pass: 3, fail: 1, error: 0, skip: 0, acceptedRisk: 0, notApplicable: 0, unknown: 0},
  evaluatedAt: "2026-11-20T09:00:00Z", oldestEvaluation: "2026-11-20T08:40:00Z", nextExpiry: "2026-11-20T10:40:00Z"}`
	// evidenceExpired: was Complete, its next expiry passed before the observation.
	evidenceExpired = `{evidence: {completeness: Complete, expected: 4, attributable: 4, missing: 0, rejected: 0, unresolved: 0},
  outcomes: {pass: 4, fail: 0, error: 0, skip: 0, acceptedRisk: 0, notApplicable: 0, unknown: 0},
  evaluatedAt: "2026-11-20T05:00:00Z", oldestEvaluation: "2026-11-20T04:00:00Z", nextExpiry: "2026-11-20T06:00:00Z",
  limitations: ["policy reports unavailable"]}`
	// evidenceInconsistent: counts that do not add up.
	evidenceInconsistent = `{evidence: {completeness: Complete, expected: 4, attributable: 3, missing: 0, rejected: 0, unresolved: 0},
  outcomes: {pass: 3, fail: 0, error: 0, skip: 0, acceptedRisk: 0, notApplicable: 0, unknown: 0},
  evaluatedAt: "2026-11-20T09:00:00Z", nextExpiry: "2026-11-20T10:40:00Z"}`
)

// setEvidence records a binding's status as its controllers would: the
// targeting controller's observedGeneration and, unless current is empty,
// the assessment owner's status.assessment.current.
func (f *fakeCluster) setEvidence(binding string, observedGeneration int64, current string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range f.lists[pathBindings] {
		if b["metadata"].(map[string]any)["name"] != binding {
			continue
		}
		st := map[string]any{"observedGeneration": observedGeneration}
		if current != "" {
			st["assessment"] = map[string]any{"current": obj(f.t, current)}
		}
		b["status"] = st
	}
}

func (f *fakeCluster) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

func (f *fakeCluster) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	deny, delay := f.deny[r.URL.Path], f.delay[r.URL.Path]
	f.mu.Unlock()
	status := func(code int, reason metav1.StatusReason) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(metav1.Status{TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: metav1.StatusFailure, Code: int32(code), Reason: reason, Message: string(reason)})
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}
	switch {
	case r.Method != http.MethodGet:
		status(http.StatusMethodNotAllowed, metav1.StatusReasonMethodNotAllowed)
		return
	case deny:
		status(http.StatusForbidden, metav1.StatusReasonForbidden)
		return
	}
	verbs := []string{"get", "list", "watch", "create", "update", "patch", "delete"}
	discovery := map[string][]string{
		"/api/v1":                              {"namespaces", "configmaps", "secrets"},
		"/apis/compliance.erenius.io/v1alpha1": {"complianceprofiles", "compliancebindings", "complianceexceptions"},
		"/apis/policies.kyverno.io/v1":         {"validatingpolicies"},
	}
	w.Header().Set("Content-Type", "application/json")
	if names, ok := discovery[r.URL.Path]; ok {
		var res []metav1.APIResource
		for _, n := range names {
			res = append(res, metav1.APIResource{Name: n, Namespaced: n == "configmaps" || n == "secrets" || n == "complianceexceptions", Verbs: verbs})
		}
		_ = json.NewEncoder(w).Encode(metav1.APIResourceList{TypeMeta: metav1.TypeMeta{Kind: "APIResourceList", APIVersion: "v1"},
			GroupVersion: strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/apis/"), "/api/"), APIResources: res})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if items, ok := f.lists[r.URL.Path]; ok {
		_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "List", "metadata": map[string]any{"resourceVersion": "100"}, "items": items})
		return
	}
	if r.URL.Path == pathNamespaces+"/kube-system" {
		_ = json.NewEncoder(w).Encode(f.lists[pathNamespaces][1])
		return
	}
	status(http.StatusNotFound, metav1.StatusReasonNotFound)
}

// kubeconfig writes a kubeconfig whose contexts staging (current) and
// production reach the fake cluster, and elsewhere reaches nothing.
func (f *fakeCluster) kubeconfig(t *testing.T) string {
	t.Helper()
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters["fake"] = &clientcmdapi.Cluster{Server: f.srv.URL}
	cfg.Clusters["nowhere"] = &clientcmdapi.Cluster{Server: "http://127.0.0.1:1"}
	cfg.AuthInfos["reader"] = &clientcmdapi.AuthInfo{Token: "reader-token"}
	cfg.Contexts["staging"] = &clientcmdapi.Context{Cluster: "fake", AuthInfo: "reader"}
	cfg.Contexts["production"] = &clientcmdapi.Context{Cluster: "fake", AuthInfo: "reader"}
	cfg.Contexts["elsewhere"] = &clientcmdapi.Context{Cluster: "nowhere", AuthInfo: "reader"}
	cfg.CurrentContext = "staging"
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := clientcmd.WriteToFile(*cfg, path); err != nil {
		t.Fatal(err)
	}
	return path
}

var fixedNow = time.Date(2026, 11, 20, 9, 30, 0, 0, time.UTC)

// noOtherStartup makes every other command's startup fail the test.
func noOtherStartup(t *testing.T) {
	t.Helper()
	savedC, savedP, savedNow := startController, startProvider, previewNow
	t.Cleanup(func() { startController, startProvider, previewNow = savedC, savedP, savedNow })
	startController = func([]string) error {
		t.Error("the preview started the controller manager")
		return errors.New("controller started")
	}
	startProvider = func(string, map[string]string) (policy.Provider, error) {
		t.Error("the preview started the C2P provider")
		return nil, errors.New("provider started")
	}
	previewNow = func() time.Time { return fixedNow }
}

type cliResult struct {
	code           int
	stdout, stderr string
}

func runCLI(t *testing.T, stdin string, args ...string) cliResult {
	t.Helper()
	noOtherStartup(t)
	var out, errOut bytes.Buffer
	code := dispatch(context.Background(), append([]string{"preview"}, args...), strings.NewReader(stdin), &out, &errOut)
	return cliResult{code, out.String(), errOut.String()}
}

func decodeReport(t *testing.T, raw string) *preview.Report {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var r preview.Report
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("stdout is not one JSON report: %v\n%s", err, raw)
	}
	if dec.More() {
		t.Fatalf("stdout has more than the report:\n%s", raw)
	}
	if r.Kind != preview.ReportKind || r.SchemaVersion != 1 {
		t.Fatalf("report identity %q v%d", r.Kind, r.SchemaVersion)
	}
	return &r
}

func codes(ds []preview.ReportDiagnostic) []string {
	var out []string
	for _, d := range ds {
		out = append(out, string(d.Code))
	}
	return out
}

func fixture(name string) string { return "../../testdata/preview/cli/" + name }

// base are the arguments of every run against the fake cluster.
func base(kc string) []string { return []string{"--kubeconfig", kc, "--content-root", "../../content"} }

// reorderedProfile writes the live profile with its policies swapped: the
// same configuration, stored differently, so every revision rotates.
func reorderedProfile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "reordered.yaml")
	doc := `apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceProfile
metadata:
  name: baseline
spec:
  bundle:
    name: konstapel-vendored
    digest: "` + vendoredDigest(t) + `"
  policies:
    - name: disallow-privilege-escalation
    - name: disallow-privileged-containers
`
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func ociProfile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "oci.yaml")
	doc := `apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceProfile
metadata:
  name: baseline
spec:
  bundle:
    name: acme-hardening
    digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  policies:
    - name: disallow-privileged-containers
`
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestPreviewExitMatrix is the full flag/outcome matrix of task 6.3: each
// scenario runs with and without --fail-on-impact, and the report always
// states the outcome the status reflects.
func TestPreviewExitMatrix(t *testing.T) {
	for _, tc := range []struct {
		name string
		// setup prepares the cluster and returns the scenario arguments.
		setup         func(t *testing.T, f *fakeCluster) []string
		plain, gated  int
		complete      bool
		impacts       bool
		errors        []string
		check         func(t *testing.T, r *preview.Report)
		noObservation bool
	}{
		{name: "complete without impacts", setup: func(*testing.T, *fakeCluster) []string { return []string{"-f", fixture("unchanged.yaml")} },
			plain: 0, gated: 0, complete: true,
			check: func(t *testing.T, r *preview.Report) {
				// No evidence is recorded: an informational limitation,
				// never a failure on its own.
				if !slices.Contains(codes(r.Limitations), "evidence-missing") || r.Evidence.Analysis != preview.AnalysisAvailable ||
					len(r.Evidence.Bindings) != 1 || r.Evidence.Bindings[0].State != preview.EvidenceMissing || len(r.Evidence.Entries) != 2 {
					t.Errorf("evidence: %v %+v", codes(r.Limitations), r.Evidence)
				}
				for _, e := range r.Evidence.Entries {
					if e.Proposed != preview.ProposalUnchanged || e.State != preview.EvidenceMissing || e.ObservedRevision == "" {
						t.Errorf("entry %+v", e)
					}
				}
			}},
		{name: "evidence-only: current evidence of a reporting-only edit", setup: func(_ *testing.T, f *fakeCluster) []string {
			f.setEvidence("deny-prod", 1, evidenceCurrent)
			return []string{"-f", fixture("reporting-only.yaml")}
		}, plain: 0, gated: 0, complete: true,
			check: func(t *testing.T, r *preview.Report) {
				b := r.Evidence.Bindings
				if len(b) != 1 || b[0].State != preview.EvidenceCurrent || b[0].Current == nil || b[0].Current.Outcomes.Fail != 1 {
					t.Fatalf("bindings %+v", b)
				}
				for _, e := range r.Evidence.Entries {
					// The reporting-only edit keeps the revision, so the
					// evidence still describes the proposal.
					if e.Proposed != preview.ProposalUnchanged || e.State != preview.EvidenceCurrent || e.EvaluatedAt == nil ||
						!e.EvaluatedAt.Equal(time.Date(2026, 11, 20, 8, 40, 0, 0, time.UTC)) {
						t.Errorf("entry %+v", e)
					}
				}
				if slices.ContainsFunc(r.Limitations, func(d preview.ReportDiagnostic) bool {
					return d.Stage == preview.StageEvidence && d.Code != "evidence-per-binding"
				}) {
					t.Errorf("limitations %v", codes(r.Limitations))
				}
			}},
		{name: "evidence-only: stale evidence", setup: func(_ *testing.T, f *fakeCluster) []string {
			f.setEvidence("deny-prod", 1, evidenceExpired)
			return []string{"-f", fixture("unchanged.yaml")}
		}, plain: 0, gated: 0, complete: true,
			check: func(t *testing.T, r *preview.Report) {
				if b := r.Evidence.Bindings; len(b) != 1 || b[0].State != preview.EvidenceStale || b[0].Current.OwnerLimitations != 1 ||
					!slices.Contains(codes(r.Limitations), "evidence-stale") {
					t.Errorf("evidence %+v %v", b, codes(r.Limitations))
				}
				for _, e := range r.Evidence.Entries {
					if e.State != preview.EvidenceStale || e.EvaluatedAt != nil {
						t.Errorf("entry %+v", e)
					}
				}
			}},
		{name: "evidence-only: unattributable evidence", setup: func(_ *testing.T, f *fakeCluster) []string {
			f.setEvidence("deny-prod", 1, evidenceInconsistent)
			return []string{"-f", fixture("unchanged.yaml")}
		}, plain: 0, gated: 0, complete: true,
			check: func(t *testing.T, r *preview.Report) {
				if b := r.Evidence.Bindings; len(b) != 1 || b[0].State != preview.EvidenceUnattributable || !slices.Contains(codes(r.Limitations), "evidence-unattributable") {
					t.Errorf("evidence %+v %v", b, codes(r.Limitations))
				}
			}},
		{name: "evidence-only: controller behind the binding", setup: func(_ *testing.T, f *fakeCluster) []string {
			f.setEvidence("deny-prod", 0, evidenceCurrent)
			return []string{"-f", fixture("unchanged.yaml")}
		}, plain: 0, gated: 0, complete: true,
			check: func(t *testing.T, r *preview.Report) {
				if b := r.Evidence.Bindings; len(b) != 1 || b[0].State != preview.EvidenceUnattributable {
					t.Errorf("evidence %+v", b)
				}
			}},
		{name: "current evidence is never attached to a new revision", setup: func(_ *testing.T, f *fakeCluster) []string {
			f.setEvidence("deny-prod", 1, evidenceCurrent)
			return []string{"-f", fixture("proposed.yaml")}
		}, plain: 0, gated: 2, complete: true, impacts: true,
			check: func(t *testing.T, r *preview.Report) {
				got := map[string]preview.EvidenceProposal{}
				for _, e := range r.Evidence.Entries {
					got[e.Key.Policy+"/"+e.Namespace.Name] = e.Proposed
					switch e.Namespace.Name {
					case "prod": // observed revision, leaving the proposal
						if e.State != preview.EvidenceCurrent || e.ObservedRevision == "" || e.Proposed != preview.ProposalWithdrawn {
							t.Errorf("prod %+v", e)
						}
					case "staging": // proposed only: nothing describes it
						if e.State != preview.EvidenceNotObserved || e.ObservedRevision != "" || e.EvaluatedAt != nil || e.Proposed != preview.ProposalNotEvaluated {
							t.Errorf("staging %+v", e)
						}
					default:
						t.Errorf("unexpected entry %+v", e)
					}
				}
				if len(got) != 4 || !slices.Contains(codes(r.Limitations), "evidence-not-evaluated") {
					t.Errorf("entries %v limitations %v", got, codes(r.Limitations))
				}
			}},
		{name: "failure after impacts: undetermined exception despite current evidence", setup: func(_ *testing.T, f *fakeCluster) []string {
			f.addException()
			f.setEvidence("deny-prod", 1, evidenceCurrent)
			return []string{"-f", fixture("proposed.yaml")}
		}, plain: 1, gated: 1, impacts: true, errors: []string{"exception-impact-undetermined"},
			check: func(t *testing.T, r *preview.Report) {
				// Evidence adds no error; the exception input decides.
				if len(r.Errors) != 1 || r.Evidence.Bindings[0].State != preview.EvidenceCurrent {
					t.Errorf("errors %v evidence %+v", codes(r.Errors), r.Evidence.Bindings)
				}
			}},
		{name: "reporting-only change", setup: func(*testing.T, *fakeCluster) []string { return []string{"-f", fixture("reporting-only.yaml")} },
			plain: 0, gated: 0, complete: true,
			check: func(t *testing.T, r *preview.Report) {
				if r.Summary.ReportingOnly != 1 || len(r.Changes.Contributions) != 0 {
					t.Errorf("reporting-only: %+v contributions %d", r.Summary, len(r.Changes.Contributions))
				}
			}},
		{name: "evidence-only context with an untouched exception", setup: func(_ *testing.T, f *fakeCluster) []string {
			f.addException()
			return []string{"-f", fixture("reporting-only.yaml")}
		}, plain: 0, gated: 0, complete: true,
			check: func(t *testing.T, r *preview.Report) {
				if r.Exceptions.Observed == nil || *r.Exceptions.Observed != 1 || len(r.Exceptions.PotentiallyAffected) != 0 {
					t.Errorf("exceptions: %+v", r.Exceptions)
				}
			}},
		{name: "complete with impacts", setup: func(*testing.T, *fakeCluster) []string { return []string{"-f", fixture("proposed.yaml")} },
			plain: 0, gated: 2, complete: true, impacts: true},
		{name: "declared removal", setup: func(*testing.T, *fakeCluster) []string {
			return []string{"--before", fixture("previous.yaml"), "-f", fixture("proposed.yaml")}
		}, plain: 0, gated: 2, complete: true, impacts: true,
			check: func(t *testing.T, r *preview.Report) {
				removed := slices.ContainsFunc(r.Changes.Objects, func(o preview.ObjectChange) bool {
					return o.Identity == "ComplianceBinding/audit-all" && o.Disposition == preview.Removed
				})
				if !removed {
					t.Errorf("audit-all removal missing: %+v", r.Changes.Objects)
				}
			}},
		{name: "equivalent but rotating", setup: func(t *testing.T, _ *fakeCluster) []string { return []string{"-f", reorderedProfile(t)} },
			plain: 0, gated: 2, complete: true, impacts: true,
			check: func(t *testing.T, r *preview.Report) {
				// Decision: rows that replace real revisions count, and are labelled.
				if r.Summary.EquivalentReplacements == 0 || r.Summary.EquivalentReplacements != r.Summary.ContributionImpacts {
					t.Errorf("equivalent replacements: %+v", r.Summary)
				}
				for _, c := range r.Changes.Contributions {
					if !c.SemanticallyEquivalent || c.RevisionEffect != preview.RevisionReplacement {
						t.Errorf("row %+v", c.Key)
					}
				}
			}},
		{name: "invalid input", setup: func(*testing.T, *fakeCluster) []string { return []string{"-f", fixture("invalid.yaml")} },
			plain: 1, gated: 1, errors: []string{"unknown-field"}, noObservation: true},
		{name: "standard input used twice", setup: func(*testing.T, *fakeCluster) []string { return []string{"-f", "-", "--before", "-"} },
			plain: 1, gated: 1, errors: []string{"stdin-used-twice"}, noObservation: true},
		{name: "unknown context", setup: func(*testing.T, *fakeCluster) []string {
			return []string{"-f", fixture("proposed.yaml"), "--context", "missing"}
		}, plain: 1, gated: 1, errors: []string{"kubeconfig-invalid"}, noObservation: true},
		{name: "unreachable cluster", setup: func(*testing.T, *fakeCluster) []string {
			return []string{"-f", fixture("proposed.yaml"), "--context", "elsewhere", "--timeout", "5s"}
		}, plain: 1, gated: 1, errors: []string{"request-failed"}},
		{name: "denied required read", setup: func(_ *testing.T, f *fakeCluster) []string {
			f.deny[pathBindings] = true
			return []string{"-f", fixture("proposed.yaml")}
		}, plain: 1, gated: 1, errors: []string{"access-denied"}},
		{name: "timeout", setup: func(_ *testing.T, f *fakeCluster) []string {
			f.delay[pathBindings] = 3 * time.Second
			return []string{"-f", fixture("proposed.yaml"), "--timeout", "300ms"}
		}, plain: 1, gated: 1, errors: []string{"timeout"}},
		{name: "failure after impacts: undetermined exception", setup: func(_ *testing.T, f *fakeCluster) []string {
			f.addException()
			return []string{"-f", fixture("proposed.yaml")}
		}, plain: 1, gated: 1, impacts: true, errors: []string{"exception-impact-undetermined"},
			check: func(t *testing.T, r *preview.Report) {
				if len(r.Exceptions.PotentiallyAffected) != 1 || r.Exceptions.PotentiallyAffected[0].Name != "legacy-app" || len(r.Exceptions.Consequences) != 0 {
					t.Errorf("exceptions: %+v", r.Exceptions)
				}
			}},
		{name: "failure after impacts: OCI pin without named sources", setup: func(t *testing.T, _ *fakeCluster) []string {
			return []string{"-f", ociProfile(t)}
		}, plain: 1, gated: 1, impacts: true, errors: []string{"bundle-sources-required"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, gated := range []bool{false, true} {
				f := newFakeCluster(t)
				args := append(base(f.kubeconfig(t)), tc.setup(t, f)...)
				args = append(args, "--format", "json")
				want := tc.plain
				if gated {
					args, want = append(args, "--fail-on-impact"), tc.gated
				}
				res := runCLI(t, "", args...)
				if res.code != want {
					t.Fatalf("gated=%t: exit %d, want %d\nstderr: %s\nstdout: %s", gated, res.code, want, res.stderr, res.stdout)
				}
				r := decodeReport(t, res.stdout)
				if r.Complete != tc.complete || (r.ImpactCount > 0) != tc.impacts {
					t.Fatalf("complete %t impacts %d; errors %v", r.Complete, r.ImpactCount, codes(r.Errors))
				}
				for _, c := range tc.errors {
					if !slices.Contains(codes(r.Errors), c) {
						t.Errorf("errors %v lack %s", codes(r.Errors), c)
					}
				}
				if len(tc.errors) == 0 && len(r.Errors) != 0 {
					t.Errorf("unexpected errors %v", codes(r.Errors))
				}
				if (r.Observation == nil) != tc.noObservation {
					t.Errorf("observation present %t", r.Observation != nil)
				}
				if !r.Complete && (want != 1 || !strings.Contains(res.stderr, "incomplete")) {
					t.Errorf("incomplete report: exit %d stderr %q", want, res.stderr)
				}
				if tc.check != nil {
					tc.check(t, r)
				}
				for _, req := range f.recorded() {
					if !strings.HasPrefix(req, "GET ") {
						t.Errorf("non-GET request %s", req)
					}
				}
			}
		})
	}
}

// TestPreviewFlags covers help, malformed and unknown flags, and option
// validation: each is stderr-only (or help on stdout) and never observes.
func TestPreviewFlags(t *testing.T) {
	f := newFakeCluster(t)
	kc := f.kubeconfig(t)
	p := fixture("proposed.yaml")
	for _, tc := range []struct {
		name   string
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{name: "help", args: []string{"-h"}, code: 0, stdout: "Usage: konstapel preview"},
		{name: "long help", args: []string{"--help"}, code: 0, stdout: "--fail-on-impact"},
		{name: "unknown flag", args: []string{"-f", p, "--bogus"}, code: 1, stderr: "flag provided but not defined: -bogus"},
		{name: "malformed timeout", args: []string{"-f", p, "--timeout", "soon"}, code: 1, stderr: "invalid value \"soon\" for flag -timeout"},
		{name: "malformed bool", args: []string{"-f", p, "--fail-on-impact=maybe"}, code: 1, stderr: "invalid boolean value"},
		{name: "unknown format", args: []string{"-f", p, "--format", "yaml"}, code: 1, stderr: `--format "yaml" must be text or json`},
		{name: "no proposed input", args: []string{"--before", p}, code: 1, stderr: "at least one proposed input"},
		{name: "positional argument", args: []string{"-f", p, "extra.yaml"}, code: 1, stderr: `unexpected argument "extra.yaml"`},
		{name: "zero timeout", args: []string{"-f", p, "--timeout", "0s"}, code: 1, stderr: "must be positive"},
		{name: "bad namespace", args: []string{"-f", p, "--controller-namespace", "Konstapel_System"}, code: 1, stderr: "not a namespace name"},
		{name: "bad sources name", args: []string{"-f", p, "--bundle-sources-configmap", "Bad_Name"}, code: 1, stderr: "not a ConfigMap name"},
		{name: "cache without sources", args: []string{"-f", p, "--bundle-cache-dir", "/tmp/x"}, code: 1, stderr: "requires --bundle-sources-configmap"},
		{name: "sources with a development release", args: []string{"-f", p, "--bundle-sources-configmap", "sources", "--controller-version", "dev"}, code: 1, stderr: "--controller-version"},
		{name: "empty output", args: []string{"-f", p, "--output", ""}, code: 1, stderr: "--output must not be empty"},
		{name: "long and short file flags", args: []string{"--file", p, "-f", fixture("unchanged.yaml")}, code: 1, stdout: "[duplicate-identity] input", stderr: "incomplete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(f.recorded())
			res := runCLI(t, "", append(base(kc), tc.args...)...)
			if res.code != tc.code || !strings.Contains(res.stdout, tc.stdout) || !strings.Contains(res.stderr, tc.stderr) {
				t.Fatalf("exit %d\nstdout: %s\nstderr: %s", res.code, res.stdout, res.stderr)
			}
			if tc.code == 1 && tc.stdout == "" && res.stdout != "" {
				t.Errorf("flag error wrote to stdout: %s", res.stdout)
			}
			if len(f.recorded()) != before {
				t.Errorf("a flag error reached the cluster: %v", f.recorded()[before:])
			}
		})
	}
}

// TestPreviewKubeconfigSelection: an explicit or standard kubeconfig and a
// named or current context; never an in-cluster ServiceAccount.
func TestPreviewKubeconfigSelection(t *testing.T) {
	f := newFakeCluster(t)
	kc := f.kubeconfig(t)
	run := func(t *testing.T, args ...string) *preview.Report {
		t.Helper()
		res := runCLI(t, "", append([]string{"--content-root", "../../content", "--format", "json", "-f", fixture("unchanged.yaml")}, args...)...)
		return decodeReport(t, res.stdout)
	}
	t.Run("current context", func(t *testing.T) {
		if r := run(t, "--kubeconfig", kc); !r.Complete || r.Observation.Context != "staging" {
			t.Fatalf("%+v %v", r.Observation, codes(r.Errors))
		}
	})
	t.Run("named context", func(t *testing.T) {
		if r := run(t, "--kubeconfig", kc, "--context", "production"); !r.Complete || r.Observation.Context != "production" {
			t.Fatalf("%+v", r.Observation)
		}
	})
	t.Run("KUBECONFIG", func(t *testing.T) {
		t.Setenv("KUBECONFIG", kc)
		if r := run(t); !r.Complete || r.Observation.Context != "staging" || r.Observation.Cluster != "kube-system:ks-0001" {
			t.Fatalf("%+v", r.Observation)
		}
	})
	t.Run("no in-cluster fallback", func(t *testing.T) {
		t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "absent"))
		t.Setenv("HOME", t.TempDir())
		t.Setenv("KUBERNETES_SERVICE_HOST", "127.0.0.1")
		t.Setenv("KUBERNETES_SERVICE_PORT", strings.TrimPrefix(f.srv.URL[strings.LastIndex(f.srv.URL, ":"):], ":"))
		before := len(f.recorded())
		r := run(t)
		if r.Complete || r.Observation != nil || !slices.Contains(codes(r.Errors), "kubeconfig-invalid") || len(f.recorded()) != before {
			t.Fatalf("fell back: %+v %v", r.Observation, codes(r.Errors))
		}
	})
	t.Run("standard input", func(t *testing.T) {
		raw, _ := os.ReadFile(fixture("proposed.yaml"))
		res := runCLI(t, string(raw), "--kubeconfig", kc, "--content-root", "../../content", "--format", "json", "-f", "-")
		r := decodeReport(t, res.stdout)
		if res.code != 0 || !r.Complete || r.ImpactCount == 0 || r.Inputs.Streams[0].Path != "-" || !r.Inputs.Streams[0].Read {
			t.Fatalf("exit %d %+v", res.code, r.Inputs)
		}
	})
}

// normalize replaces the values that differ per run or per content release.
func normalize(t *testing.T, f *fakeCluster, s string) string {
	return strings.NewReplacer(strings.TrimPrefix(f.srv.URL, "http://"), "apiserver.test", vendoredDigest(t), "sha256:<vendored-digest>").Replace(s)
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "preview", name)
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from the golden report (run with -update after review):\n%s", name, got)
	}
}

// TestPreviewGoldenReports pins report v1 for a complete and an incomplete
// preview, in both formats, and shows that the text is rendered from the
// same model as the JSON: the text of the decoded JSON is the text output.
func TestPreviewGoldenReports(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(f *fakeCluster)
		args  []string
	}{
		{name: "complete", setup: func(f *fakeCluster) {
			f.setEvidence("deny-prod", 1, evidenceCurrent)
			f.setEvidence("audit-all", 1, evidenceExpired)
		}, args: []string{"--before", fixture("previous.yaml"), "-f", fixture("proposed.yaml")}},
		{name: "incomplete", setup: func(f *fakeCluster) { f.addException() }, args: []string{"-f", fixture("proposed.yaml")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeCluster(t)
			if tc.setup != nil {
				tc.setup(f)
			}
			args := append(base(f.kubeconfig(t)), tc.args...)
			js := runCLI(t, "", append(args, "--format", "json")...)
			again := runCLI(t, "", append(args, "--format", "json")...)
			txt := runCLI(t, "", args...)
			if js.stdout != again.stdout {
				t.Fatal("the same captured inputs gave different JSON")
			}
			if js.code != txt.code {
				t.Fatalf("formats disagree on the outcome: %d vs %d", js.code, txt.code)
			}
			r := decodeReport(t, js.stdout)
			if got := string(preview.RenderText(r)); got != txt.stdout {
				t.Errorf("text is not the rendering of the JSON model:\n%s\n---\n%s", got, txt.stdout)
			}
			golden(t, tc.name+".json", normalize(t, f, js.stdout))
			golden(t, tc.name+".txt", normalize(t, f, txt.stdout))
		})
	}
}

// TestPreviewReportOrdering: every list of the report is in its stable
// order, so consumers can diff saved reports.
func TestPreviewReportOrdering(t *testing.T) {
	f := newFakeCluster(t)
	f.addException()
	res := runCLI(t, "", append(base(f.kubeconfig(t)), "--before", fixture("previous.yaml"), "-f", fixture("proposed.yaml"), "--format", "json")...)
	r := decodeReport(t, res.stdout)
	sorted := func(name string, keys []string) {
		if !slices.IsSorted(keys) {
			t.Errorf("%s not sorted: %v", name, keys)
		}
	}
	var k []string
	for _, c := range r.Changes.Contributions {
		k = append(k, c.Key.Binding+"\x00"+c.Key.Policy)
	}
	sorted("contributions", k)
	k = nil
	for _, n := range r.Changes.Namespaces {
		k = append(k, n.Namespace.Name+"\x00"+string(n.Namespace.UID)+"\x00"+n.Policy)
	}
	sorted("namespaces", k)
	k = nil
	for _, o := range r.Changes.Objects {
		k = append(k, o.Identity)
	}
	sorted("objects", k)
	// Diagnostics are grouped by stage in pipeline order; their full order
	// is TestReportOrdersDiagnostics in internal/preview.
	for _, l := range [][]preview.ReportDiagnostic{r.Errors, r.Limitations} {
		if !slices.IsSortedFunc(l, func(a, b preview.ReportDiagnostic) int {
			return strings.Compare(stageRank(a.Stage), stageRank(b.Stage))
		}) {
			t.Errorf("diagnostics not grouped by stage: %v", codes(l))
		}
	}
}

func stageRank(s preview.Stage) string {
	return strconv.Itoa(slices.Index([]preview.Stage{preview.StageInput, preview.StageKubeconfig, preview.StageObservation, preview.StageContent,
		preview.StageComparison, preview.StageExceptions, preview.StageEvidence}, s))
}

// TestPreviewOutputErrors: a report that cannot be written exits 1 even
// when the preview is complete or has gated impacts; a file receives
// exactly the stdout report.
func TestPreviewOutputErrors(t *testing.T) {
	f := newFakeCluster(t)
	args := append(base(f.kubeconfig(t)), "-f", fixture("proposed.yaml"), "--format", "json")
	out := filepath.Join(t.TempDir(), "preview.json")
	ok := runCLI(t, "", append(args, "--output", out)...)
	raw, _ := os.ReadFile(out)
	if ok.code != 0 || ok.stdout != "" || !decodeReport(t, string(raw)).Complete {
		t.Fatalf("file output: exit %d stdout %q", ok.code, ok.stdout)
	}
	for _, extra := range [][]string{{"--output", t.TempDir()}, {"--output", filepath.Join(t.TempDir(), "missing", "x.json"), "--fail-on-impact"}} {
		res := runCLI(t, "", append(args, extra...)...)
		if res.code != 1 || !strings.Contains(res.stderr, "writing the report") {
			t.Errorf("%v: exit %d stderr %q", extra, res.code, res.stderr)
		}
	}
	var w failingWriter
	noOtherStartup(t)
	var errOut bytes.Buffer
	if code := dispatch(context.Background(), append([]string{"preview"}, args...), nil, &w, &errOut); code != 1 || !strings.Contains(errOut.String(), "writing the report") {
		t.Errorf("stdout write error: exit %d %q", code, errOut.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// TestPreviewProcessBoundary runs the real main: a closed stdout or a full
// device is an output error with exit status 1 (not a SIGPIPE death), and
// statuses 0 and 2 survive main unchanged.
func TestPreviewProcessBoundary(t *testing.T) {
	f := newFakeCluster(t)
	kc := f.kubeconfig(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	start := func(stdout *os.File, args ...string) (int, string) {
		cmd := exec.Command(exe, append(append([]string{"preview"}, base(kc)...), args...)...)
		cmd.Env = append(os.Environ(), "KONSTAPEL_TEST_MAIN=1")
		var errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = stdout, &errOut
		err := cmd.Run()
		var exitErr *exec.ExitError
		switch {
		case err == nil:
			return 0, errOut.String()
		case errors.As(err, &exitErr):
			if !exitErr.Exited() {
				t.Fatalf("killed instead of exiting: %v (stderr %s)", err, errOut.String())
			}
			return exitErr.ExitCode(), errOut.String()
		}
		t.Fatal(err)
		return -1, ""
	}
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	if code, se := start(devnull, "-f", fixture("proposed.yaml")); code != 0 {
		t.Errorf("default: exit %d %s", code, se)
	}
	if code, se := start(devnull, "-f", fixture("proposed.yaml"), "--fail-on-impact"); code != 2 {
		t.Errorf("gated: exit %d %s", code, se)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close() // the consumer went away before the report
	code, se := start(w, "-f", fixture("proposed.yaml"), "--format", "json", "--fail-on-impact")
	_ = w.Close()
	if code != 1 || !strings.Contains(se, "writing the report") {
		t.Errorf("closed stdout: exit %d stderr %q", code, se)
	}
	if _, err := os.Stat("/dev/full"); err == nil {
		if code, se := start(devnull, "-f", fixture("proposed.yaml"), "--output", "/dev/full"); code != 1 || !strings.Contains(se, "writing the report") {
			t.Errorf("/dev/full: exit %d stderr %q", code, se)
		}
	}
}

// TestPreviewStartsNothingElse: the preview command does not reach the
// other commands' startup (asserted by the hooks of every test here), and
// neither its source nor the preview package can reach the manager,
// delivery, metrics or the provider.
func TestPreviewStartsNothingElse(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "preview.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range file.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		for _, banned := range []string{"internal/controller", "controller-runtime", "compliance-to-policy-go", "internal/observability", "internal/download"} {
			if strings.Contains(p, banned) {
				t.Errorf("preview.go imports %s", p)
			}
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && id.Name == "assessment" && x.Sel.Name != "ShippedPolicies" {
				t.Errorf("preview.go uses assessment.%s; only the shipped policy map is data it may read", x.Sel.Name)
			}
		case *ast.Ident:
			if slices.Contains([]string{"startProvider", "startController", "runController", "runDownload", "runEvidence"}, x.Name) {
				t.Errorf("preview.go refers to %s", x.Name)
			}
		}
		return true
	})
	out, err := exec.Command("go", "list", "-deps", "../../internal/preview").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if strings.HasSuffix(dep, "/internal/controller") || dep == "sigs.k8s.io/controller-runtime" ||
			slices.ContainsFunc([]string{"/pkg/manager", "controller-runtime/pkg/leaderelection", "/internal/observability", "/pkg/metrics/server"}, func(s string) bool { return strings.Contains(dep, s) }) {
			t.Errorf("internal/preview depends on %s", dep)
		}
	}
}

// TestExistingCommandsKeepTheirBehavior: no arguments and other commands
// still fail with exit 1 and their own messages; `controller` still goes to
// the manager startup and the prototype commands to the provider.
func TestExistingCommandsKeepTheirBehavior(t *testing.T) {
	savedC, savedP := startController, startProvider
	t.Cleanup(func() { startController, startProvider = savedC, savedP })
	var started []string
	startController = func([]string) error {
		started = append(started, "controller")
		return errors.New("manager not started in tests")
	}
	startProvider = func(string, map[string]string) (policy.Provider, error) {
		started = append(started, "provider")
		return nil, errors.New("provider not started in tests")
	}
	t.Chdir(t.TempDir())
	for _, tc := range []struct {
		args    []string
		stderr  string
		started string
	}{
		{nil, "usage: konstapel controller|download-server|evidence|preview|", ""},
		{[]string{"controller", "--leader-elect=false"}, "manager not started in tests", "controller"},
		{[]string{"generate", "--bogus"}, "flag provided but not defined: -bogus", ""},
		{[]string{"validate"}, "", ""},
		{[]string{"bogus"}, "", ""},
	} {
		started = nil
		var out, errOut bytes.Buffer
		code := dispatch(context.Background(), tc.args, nil, &out, &errOut)
		if code != 1 || !strings.Contains(errOut.String(), tc.stderr) {
			t.Errorf("%v: exit %d stderr %q", tc.args, code, errOut.String())
		}
		if tc.started != "" && !slices.Contains(started, tc.started) {
			t.Errorf("%v did not reach %s: %v", tc.args, tc.started, started)
		}
	}
}
