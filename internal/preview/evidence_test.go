package preview

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// --- 5.3: evidence context from the owners' contracts ---

func mt(t time.Time) *metav1.Time { v := metav1.NewTime(t); return &v }

// ownerEvidence is the owner's current evidence of n attributable passes.
func ownerEvidence(n int32, completeness v1alpha1.EvidenceCompleteness, expiry time.Time) *v1alpha1.CurrentEvidence {
	c := &v1alpha1.CurrentEvidence{Evidence: v1alpha1.EvidenceSummary{Completeness: completeness, Expected: n, Attributable: n},
		Outcomes: v1alpha1.OutcomeCounts{Pass: n}, EvaluatedAt: metav1.NewTime(fixedNow.Add(-time.Hour)), OldestEvaluation: mt(fixedNow.Add(-90 * time.Minute)),
		NextExpiry: mt(expiry)}
	if completeness == v1alpha1.EvidenceCompleteness("Incomplete") {
		c.Evidence.Attributable, c.Evidence.Missing, c.Outcomes.Pass = n-1, 1, n-1
	}
	return c
}

// Each binding state follows the owner's precedence: nothing recorded,
// expiry, then whether the record can describe the observed revisions.
func TestJudgeEvidenceFollowsTheOwnersRules(t *testing.T) {
	at, later := fixedNow, fixedNow.Add(time.Hour)
	subjects := &bindingSubjects{subjects: []targeting.EvidenceSubject{{Namespace: "prod"}}}
	none := &bindingSubjects{}
	ob := func(gen, observed int64, c *v1alpha1.CurrentEvidence) *ObservedEvidence {
		return &ObservedEvidence{Binding: "b", Generation: gen, ObservedGeneration: observed, Current: c}
	}
	inconsistent := ownerEvidence(4, "Complete", later)
	inconsistent.Outcomes.Fail = 1
	miscounted := ownerEvidence(4, "Complete", later)
	miscounted.Evidence.Attributable = 3
	ownerStale := ownerEvidence(4, "Incomplete", later)
	ownerStale.Evidence.StaleScopes = 1
	noExpiry := ownerEvidence(4, "Complete", later)
	noExpiry.NextExpiry = nil
	for _, tc := range []struct {
		name string
		ob   *ObservedEvidence
		bs   *bindingSubjects
		want EvidenceState
	}{
		{"current", ob(3, 3, ownerEvidence(4, "Complete", later)), subjects, EvidenceCurrent},
		{"current without a recorded expiry", ob(3, 3, noExpiry), subjects, EvidenceCurrent},
		{"incomplete", ob(3, 3, ownerEvidence(4, "Incomplete", later)), subjects, EvidenceIncomplete},
		{"nothing recorded", ob(3, 3, nil), subjects, EvidenceMissing},
		{"invalid record", &ObservedEvidence{Generation: 3, ObservedGeneration: 3, Invalid: "unknown field"}, subjects, EvidenceUnattributable},
		{"expired at the end of the observation", ob(3, 3, ownerEvidence(4, "Complete", at)), subjects, EvidenceStale},
		{"expired and the controller is behind", ob(3, 2, ownerEvidence(4, "Complete", at)), subjects, EvidenceStale},
		{"controller behind the binding", ob(3, 2, ownerEvidence(4, "Complete", later)), subjects, EvidenceUnattributable},
		{"subjects not derivable", ob(3, 3, ownerEvidence(4, "Complete", later)), &bindingSubjects{err: errors.New("no content")}, EvidenceUnattributable},
		{"observed stale scope", ob(3, 3, ownerEvidence(4, "Complete", later)), &bindingSubjects{stale: []EvidenceStaleScope{{Reason: targeting.ReasonContentUnavailable}}}, EvidenceUnattributable},
		{"owner stale scope", ob(3, 3, ownerStale), subjects, EvidenceUnattributable},
		{"outcomes do not add up", ob(3, 3, inconsistent), subjects, EvidenceUnattributable},
		{"evidence does not add up", ob(3, 3, miscounted), subjects, EvidenceUnattributable},
		{"no targets, none expected", ob(3, 3, ownerEvidence(0, "NoTargets", later)), none, EvidenceNoTargets},
		{"no targets, subjects expected", ob(3, 3, ownerEvidence(0, "NoTargets", later)), subjects, EvidenceUnattributable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := judgeEvidence(tc.ob, tc.bs, at)
			if got != tc.want || reason == "" {
				t.Fatalf("%s (%q), want %s", got, reason, tc.want)
			}
		})
	}
}

// The owner's status is read with the binding, never makes the observation
// incomplete, and its churn (re-evaluations, changing counts) never forces a
// recapture: the snapshot carries the final capture's record.
func TestObserveReadsOwnerEvidenceWithoutRechecking(t *testing.T) {
	f := baseline(t)
	last := 0
	f.onCapture = func(n int) {
		last = n
		f.mutate(pathBindings, "b-prod", func(m map[string]any) {
			raw, _ := json.Marshal(ownerEvidence(int32(n+1), "Complete", fixedNow.Add(time.Hour)))
			var cur map[string]any
			_ = json.Unmarshal(raw, &cur)
			m["status"] = map[string]any{"observedGeneration": int64(1), "assessment": map[string]any{"current": cur}}
		})
		f.mutate(pathBindings, "b-dev", func(m map[string]any) {
			m["status"] = map[string]any{"assessment": map[string]any{"current": map[string]any{"evidence": map[string]any{"completeness": "Complete"}, "surprise": n}}}
		})
	}
	s, err := observe(t, f, nil)
	mustComplete(t, s, err)
	if s.Captures != 2 || len(s.Drift) != 0 {
		t.Fatalf("evidence churn forced recapture: captures=%d drift=%+v", s.Captures, s.Drift)
	}
	got := map[string]ObservedEvidence{}
	for _, e := range s.Evidence {
		got[e.Binding] = e
	}
	if e := got["b-prod"]; e.Current == nil || e.Current.Evidence.Expected != int32(last+1) || e.ObservedGeneration != 1 || e.Invalid != "" {
		t.Fatalf("b-prod evidence is not the final capture's: %+v", e)
	}
	if e := got["b-dev"]; e.Current != nil || !strings.Contains(e.Invalid, "surprise") {
		t.Fatalf("an unsupported record is kept as invalid: %+v", e)
	}
	if len(got) != len(s.Live.Bindings) {
		t.Fatalf("evidence of %d bindings, %d observed", len(got), len(s.Live.Bindings))
	}
}

// evidenceReport runs the report's evidence part over a comparison of w.
func evidenceReport(t *testing.T, w *world, doc string, ev ...ObservedEvidence) *Report {
	t.Helper()
	w.snap.End = fixedNow
	w.snap.Evidence = ev
	c := w.compare(mustSet(t, doc), nil)
	if !c.Complete {
		t.Fatal(c.Errors)
	}
	r := newReport()
	r.fillComparison(c, nil)
	r.fillEvidence(w.snap, c)
	return r.finish()
}

func current(binding string, gen int64) ObservedEvidence {
	return ObservedEvidence{Binding: binding, Generation: gen, ObservedGeneration: gen, Current: ownerEvidence(4, "Complete", fixedNow.Add(time.Hour))}
}

// Old results are never attached to new revisions: a subject whose proposed
// revision differs is not-evaluated, whatever the observed revision's
// evidence says, and a subject only the proposal has carries no observed
// revision, state or time. An unchanged revision keeps its evidence.
func TestEvidenceIsNeverAttachedToANewRevision(t *testing.T) {
	newDeny := bindingWith("deny", "shared", "Audit", revisionSelector)
	for _, tc := range []struct {
		name string
		doc  string
		// want maps binding/policy/namespace to the proposal.
		want map[string]EvidenceProposal
	}{
		{"reporting only", bindingWith("deny", "shared", "Deny", revisionSelector) + "  assessment: {interval: 12h}\n",
			map[string]EvidenceProposal{"deny/privileged/prod": ProposalUnchanged, "deny/run-as-non-root/prod": ProposalUnchanged}},
		{"mode change", newDeny,
			map[string]EvidenceProposal{"deny/privileged/prod": ProposalNotEvaluated, "deny/run-as-non-root/prod": ProposalNotEvaluated}},
		{"scope moves", bindingWith("deny", "shared", "Deny", "{matchLabels: {env: staging}}"),
			map[string]EvidenceProposal{"deny/privileged/prod": ProposalWithdrawn, "deny/run-as-non-root/prod": ProposalWithdrawn,
				"deny/privileged/staging": ProposalNotEvaluated, "deny/run-as-non-root/staging": ProposalNotEvaluated}},
		{"new binding", bindingWith("fresh", "shared", "Deny", "{}"),
			map[string]EvidenceProposal{"fresh/privileged/prod": ProposalNotEvaluated, "fresh/run-as-non-root/prod": ProposalNotEvaluated,
				"fresh/privileged/staging": ProposalNotEvaluated, "fresh/run-as-non-root/staging": ProposalNotEvaluated}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := revisionWorld(t).ns("staging", "staging-uid", map[string]string{"env": "staging"})
			r := evidenceReport(t, w, tc.doc, current("deny", 4), current("audit", 1), current("legacy", 6))
			if r.Evidence.Analysis != AnalysisAvailable || !r.Complete {
				t.Fatalf("%+v %v", r.Evidence, r.Errors)
			}
			live := map[string]string{}
			for _, c := range resolveLive(w).Bindings {
				for _, k := range c.Contributions {
					live[c.Binding.Name+"/"+k.Policy] = k.Revision
				}
			}
			got := map[string]EvidenceProposal{}
			for _, e := range r.Evidence.Entries {
				k := e.Key.Binding + "/" + e.Key.Policy
				got[k+"/"+e.Namespace.Name] = e.Proposed
				switch e.State {
				case EvidenceNotObserved:
					if e.ObservedRevision != "" || e.EvaluatedAt != nil || e.Proposed != ProposalNotEvaluated {
						t.Errorf("a proposed-only subject carries observed evidence: %+v", e)
					}
				case EvidenceCurrent:
					// The observed revision is the one the controller
					// computes from the live configuration, never a
					// provisional one.
					if e.ObservedRevision != live[k] || e.EvaluatedAt == nil {
						t.Errorf("entry %+v, live revision %s", e, live[k])
					}
				default:
					t.Errorf("state %s", e.State)
				}
			}
			if len(got) != len(tc.want) {
				t.Fatalf("entries %v, want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("%s: %s, want %s", k, got[k], v)
				}
			}
			wantLimit := false
			for _, v := range tc.want {
				wantLimit = wantLimit || v == ProposalNotEvaluated
			}
			if got := slices.ContainsFunc(r.Limitations, func(d ReportDiagnostic) bool { return d.Code == LimitEvidenceNotEvaluated }); got != wantLimit {
				t.Errorf("not-evaluated limitation %v, want %v", got, wantLimit)
			}
		})
	}
}

// Missing, stale and unattributable evidence are informational: the report
// stays complete with the same impacts, and each binding's state is a coded
// limitation of the evidence stage, never an error.
func TestEvidenceGapsAreInformational(t *testing.T) {
	doc := bindingWith("deny", "shared", "Audit", revisionSelector)
	baseImpacts := evidenceReport(t, revisionWorld(t), doc, current("deny", 4)).ImpactCount
	stale := current("deny", 4)
	stale.Current.NextExpiry = mt(fixedNow.Add(-time.Minute))
	behind := current("deny", 4)
	behind.ObservedGeneration = 3
	for _, tc := range []struct {
		name string
		ev   []ObservedEvidence
		want ObserveCode
	}{
		{"missing", nil, LimitEvidenceMissing},
		{"stale", []ObservedEvidence{stale}, LimitEvidenceStale},
		{"unattributable", []ObservedEvidence{behind}, LimitEvidenceUnattributable},
		{"invalid", []ObservedEvidence{{Binding: "deny", Generation: 4, ObservedGeneration: 4, Invalid: "x"}}, LimitEvidenceUnattributable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := tc.ev
			if ev == nil {
				ev = []ObservedEvidence{{Binding: "deny", Generation: 4, ObservedGeneration: 4}}
			}
			r := evidenceReport(t, revisionWorld(t), doc, ev...)
			if !r.Complete || len(r.Errors) != 0 || r.ImpactCount != baseImpacts {
				t.Fatalf("complete %v errors %v impacts %d (want %d)", r.Complete, r.Errors, r.ImpactCount, baseImpacts)
			}
			if !slices.ContainsFunc(r.Limitations, func(d ReportDiagnostic) bool {
				return d.Code == tc.want && d.Stage == StageEvidence && d.Name == "deny"
			}) {
				t.Fatalf("limitations %+v", r.Limitations)
			}
		})
	}
}

// The subjects come from targeting.ExpectedEvidence on the observed
// configuration, so they are exactly the owner's: per namespace UID, with the
// controller's revision, and an observed binding whose configuration does not
// resolve has stale scopes instead of subjects.
func TestEvidenceSubjectsAreTheOwnersExpectedEvidence(t *testing.T) {
	w := revisionWorld(t)
	r := evidenceReport(t, w, bindingWith("deny", "shared", "Audit", revisionSelector), current("deny", 4))
	want, _, err := targeting.ExpectedEvidence(resolveLive(w), w.content)
	if err != nil {
		t.Fatal(err)
	}
	var fromOwner, fromReport []string
	for _, s := range want {
		if s.BindingName == "deny" {
			fromOwner = append(fromOwner, s.LogicalPolicy+"/"+string(s.NamespaceUID)+"/"+s.Revision)
		}
	}
	for _, e := range r.Evidence.Entries {
		fromReport = append(fromReport, e.Key.Policy+"/"+string(e.Namespace.UID)+"/"+e.ObservedRevision)
	}
	slices.Sort(fromOwner)
	slices.Sort(fromReport)
	if len(fromOwner) == 0 || !slices.Equal(fromOwner, fromReport) {
		t.Fatalf("report subjects %v, owner's %v", fromReport, fromOwner)
	}
	if b := r.Evidence.Bindings; len(b) != 1 || b[0].ExpectedSubjects != len(fromOwner) || len(b[0].StaleScopes) != 0 {
		t.Fatalf("bindings %+v", b)
	}

	// A live binding whose profile pins content the source does not serve
	// resolves to a stale scope; the proposal that touches it gets no
	// subject from it and unattributable evidence.
	w = revisionWorld(t).live(profileWith("gone", "sha256:"+strings.Repeat("9", 64), polRun), "p-gone", 1, 0).
		live(bindingWith("orphan", "gone", "Audit", "{}"), "b-orphan", 1, 1)
	w.snap.End = fixedNow
	w.snap.Evidence = []ObservedEvidence{current("orphan", 1)}
	c := w.compare(mustSet(t, bindingWith("orphan", "gone", "Audit", "{}")+"  assessment: {interval: 12h}\n"), nil)
	rep := newReport()
	rep.fillComparison(c, nil)
	rep.fillEvidence(w.snap, c)
	if b := rep.Evidence.Bindings; len(b) != 1 || b[0].State != EvidenceUnattributable || len(b[0].StaleScopes) == 0 || b[0].ExpectedSubjects != 0 {
		t.Fatalf("bindings %+v", b)
	}
}
