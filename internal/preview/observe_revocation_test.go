package preview

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/exception"
)

var continueRevision = regexp.MustCompile(`continue=[0-9]+%3A`)

// The revoking request's claim, which must never reach an observation.
const revocationClaim = "REVOCATION-CLAIM-MUST-NOT-LEAK"

// storedException returns the typed exception the fake API holds.
func storedException(t *testing.T, f *fakeAPI, name string) *v1alpha1.ComplianceException {
	t.Helper()
	f.mu.Lock()
	m := runtime.DeepCopyJSON(f.colls[pathExceptions][name])
	f.mu.Unlock()
	ex := &v1alpha1.ComplianceException{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(m, ex); err != nil {
		t.Fatal(err)
	}
	return ex
}

// revoke applies what admission records for a revocation of the current
// revision (exception.revoke): spec.revoked, the protected revocation record
// and the finalizer, at a new generation.
func revoke(t *testing.T, f *fakeAPI, name string) *v1alpha1.ComplianceException {
	t.Helper()
	ex := storedException(t, f, name)
	raw, err := json.Marshal(exception.Revocation{ExceptionUID: ex.UID, Revision: ex.Spec.AcceptanceRevision,
		RequestedAt: metav1.NewTime(fixedNow.Add(-time.Minute)), Actor: exception.Actor{Username: actorName, Groups: []string{"team-a"}}, Claim: revocationClaim})
	if err != nil {
		t.Fatal(err)
	}
	ex.Spec.Revoked = true
	ex.Generation++
	ex.Annotations[exception.RevocationAnnotation] = string(raw)
	ex.Finalizers = append(ex.Finalizers, exception.RevocationFinalizer)
	f.put(pathExceptions, ex)
	return ex
}

// record writes the controller's independent revocation record of ex.
func record(t *testing.T, f *fakeAPI, ex *v1alpha1.ComplianceException) (*corev1.ConfigMap, string) {
	t.Helper()
	rec, err := exception.NewRevocationRecord(ex, ctrlNS)
	if err != nil {
		t.Fatal(err)
	}
	cm, digest, err := rec.ConfigMap(ctrlNS)
	if err != nil {
		t.Fatal(err)
	}
	f.put(pathConfigMaps(ctrlNS), cm)
	return cm, digest
}

// ownerReports sets the controller's RevocationRecorded condition.
func ownerReports(t *testing.T, f *fakeAPI, name string, status metav1.ConditionStatus, reason string, generation int64) {
	t.Helper()
	f.mutate(pathExceptions, name, func(m map[string]any) {
		st, _ := m["status"].(map[string]any)
		if st == nil {
			st = map[string]any{}
			m["status"] = st
		}
		st["conditions"] = []any{
			map[string]any{"type": v1alpha1.ConditionAcceptanceRecorded, "status": "True", "reason": "Recorded", "message": "m", "lastTransitionTime": "2026-11-19T09:00:00Z"},
			map[string]any{"type": v1alpha1.ConditionRevocationRecorded, "status": string(status), "reason": reason, "observedGeneration": generation,
				"message": "owner message " + actorName, "lastTransitionTime": "2026-11-19T09:00:00Z"},
		}
	})
}

func limitationsOf(s *Snapshot, prefix string) []Diagnostic {
	var out []Diagnostic
	for _, l := range s.Limitations {
		if strings.HasPrefix(string(l.Code), prefix) {
			out = append(out, l)
		}
	}
	return out
}

// assertNoRevocationLeak asserts that neither the revoking actor nor the
// claim nor the owner's free-text message reaches the snapshot.
func assertNoRevocationLeak(t *testing.T, s *Snapshot) {
	t.Helper()
	raw, _ := json.Marshal(s)
	for _, leak := range []string{actorName, "team-a", revocationClaim, "owner message"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("snapshot JSON carries %q: %s", leak, raw)
		}
	}
}

// 2.5: every revocation state is read from the owner's records, verified
// with the owner's checks and reported as what it is.
func TestObserveRevocationStates(t *testing.T) {
	recordName := exception.RevocationRecordName("uid-ex", 1)
	for name, tc := range map[string]struct {
		setup      func(t *testing.T, f *fakeAPI)
		state      RevocationState
		code       ObserveCode
		recordLims int    // exception-revocation-record-invalid limitations
		mention    string // owner text in the exception's limitation
		namedGet   bool   // the record name was read by name
	}{
		"recorded": {setup: func(t *testing.T, f *fakeAPI) {
			record(t, f, revoke(t, f, "allow-debug"))
			ownerReports(t, f, "allow-debug", metav1.ConditionTrue, v1alpha1.ReasonRevocationRecorded, 2)
		}, state: RevocationRecorded, code: LimitRevocationRecorded, mention: "RevocationRecorded=True (Recorded)"},
		"recorded and released": {setup: func(t *testing.T, f *fakeAPI) {
			ex := revoke(t, f, "allow-debug")
			record(t, f, ex)
			ex.Finalizers = nil
			f.put(pathExceptions, ex)
		}, state: RevocationRecorded, code: LimitRevocationRecorded, mention: "reports no RevocationRecorded condition"},
		"pending": {setup: func(t *testing.T, f *fakeAPI) {
			revoke(t, f, "allow-debug")
			ownerReports(t, f, "allow-debug", metav1.ConditionFalse, v1alpha1.ReasonRevocationHistoryPending, 2)
		}, state: RevocationPending, code: LimitRevocationPending, mention: "RevocationRecorded=False (RevocationHistoryPending)", namedGet: true},
		"protection unverified": {setup: func(t *testing.T, f *fakeAPI) {
			revoke(t, f, "allow-debug")
			ownerReports(t, f, "allow-debug", metav1.ConditionFalse, v1alpha1.ReasonRevocationProtectionUnverified, 2)
		}, state: RevocationPending, code: LimitRevocationPending, mention: "RevocationRecorded=False (RevocationProtectionUnverified)", namedGet: true},
		"processing disabled": {setup: func(t *testing.T, f *fakeAPI) {
			revoke(t, f, "allow-debug")
			ownerReports(t, f, "allow-debug", metav1.ConditionFalse, v1alpha1.ReasonRevocationProcessingDisabled, 2)
		}, state: RevocationPending, code: LimitRevocationProcessingDisabled, mention: "RevocationRecorded=False (RevocationProcessingDisabled)", namedGet: true},
		// A verdict about an older generation is not the owner's verdict
		// about this revocation.
		"processing disabled, stale condition": {setup: func(t *testing.T, f *fakeAPI) {
			revoke(t, f, "allow-debug")
			ownerReports(t, f, "allow-debug", metav1.ConditionFalse, v1alpha1.ReasonRevocationProcessingDisabled, 1)
		}, state: RevocationPending, code: LimitRevocationPending, mention: "describes generation 1", namedGet: true},
		"not reconciled": {setup: func(t *testing.T, f *fakeAPI) { revoke(t, f, "allow-debug") },
			state: RevocationPending, code: LimitRevocationPending, mention: "reports no RevocationRecorded condition", namedGet: true},
		"tampered record": {setup: func(t *testing.T, f *fakeAPI) {
			cm, _ := record(t, f, revoke(t, f, "allow-debug"))
			f.mutate(pathConfigMaps(ctrlNS), cm.Name, func(m map[string]any) {
				d := m["data"].(map[string]any)
				d[exception.RevocationRecordDataKey] = strings.Replace(d[exception.RevocationRecordDataKey].(string), `"acceptanceRevision":1`, `"acceptanceRevision":2`, 1)
			})
			// The owner's earlier verdict does not override the
			// observation's own verification.
			ownerReports(t, f, "allow-debug", metav1.ConditionTrue, v1alpha1.ReasonRevocationRecorded, 2)
		}, state: RevocationConflict, code: LimitRevocationConflict, recordLims: 1, mention: "RevocationRecorded=True (Recorded)"},
		"record of another revocation": {setup: func(t *testing.T, f *fakeAPI) {
			ex := revoke(t, f, "allow-debug")
			other := ex.DeepCopy()
			var r exception.Revocation
			_ = json.Unmarshal([]byte(other.Annotations[exception.RevocationAnnotation]), &r)
			r.RequestedAt = metav1.NewTime(r.RequestedAt.Add(-time.Hour))
			raw, _ := json.Marshal(r)
			other.Annotations[exception.RevocationAnnotation] = string(raw)
			record(t, f, other)
			ownerReports(t, f, "allow-debug", metav1.ConditionFalse, v1alpha1.ReasonRevocationRecordConflict, 2)
		}, state: RevocationConflict, code: LimitRevocationConflict, mention: "RevocationRecorded=False (RevocationRecordConflict)"},
		// An object at the record's name without the record labels is not
		// listed; the named read finds it as the controller would.
		"unlabelled object at the record name": {setup: func(t *testing.T, f *fakeAPI) {
			revoke(t, f, "allow-debug")
			f.put(pathConfigMaps(ctrlNS), &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: recordName}, Data: map[string]string{"x": "y"}})
		}, state: RevocationConflict, code: LimitRevocationConflict, namedGet: true},
		"revoked without the protected record": {setup: func(t *testing.T, f *fakeAPI) {
			ex := revoke(t, f, "allow-debug")
			delete(ex.Annotations, exception.RevocationAnnotation)
			f.put(pathExceptions, ex)
			ownerReports(t, f, "allow-debug", metav1.ConditionFalse, v1alpha1.ReasonRevocationInvalid, 2)
		}, state: RevocationInvalid, code: LimitRevocationInvalid, mention: "RevocationRecorded=False (RevocationInvalid)"},
		"protected record of another revision": {setup: func(t *testing.T, f *fakeAPI) {
			ex := revoke(t, f, "allow-debug")
			ex.Annotations[exception.RevocationAnnotation] = strings.Replace(ex.Annotations[exception.RevocationAnnotation], `"revision":1`, `"revision":7`, 1)
			f.put(pathExceptions, ex)
		}, state: RevocationInvalid, code: LimitRevocationInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			f := baseline(t)
			tc.setup(t, f)
			s, err := observe(t, f, nil)
			mustComplete(t, s, err)
			if s.Captures != 2 || len(s.Drift) != 0 {
				t.Fatalf("captures=%d drift=%+v", s.Captures, s.Drift)
			}
			ex := s.Exceptions[0]
			if !ex.Revoked || ex.Revocation == nil || ex.Revocation.State != tc.state {
				t.Fatalf("revocation: %+v %+v", ex, ex.Revocation)
			}
			lims := limitationsOf(s, "exception-revocation-")
			var onException, onRecords []Diagnostic
			for _, l := range lims {
				if l.Code == LimitRevocationRecordInvalid {
					onRecords = append(onRecords, l)
				} else {
					onException = append(onException, l)
				}
			}
			if len(onException) != 1 || onException[0].Code != tc.code || onException[0].Name != "allow-debug" || onException[0].Namespace != "prod" ||
				!strings.Contains(onException[0].Message, tc.mention) || len(onRecords) != tc.recordLims {
				t.Fatalf("limitations: %+v", lims)
			}
			switch tc.state {
			case RevocationRecorded:
				if len(s.RevocationRecords) != 1 || s.RevocationRecords[0].VerifyError != "" || ex.Revocation.RecordDigest != s.RevocationRecords[0].Digest ||
					ex.Revocation.Record != recordName || s.RevocationRecords[0].ExceptionUID != "uid-ex" || s.RevocationRecords[0].RequestedAt == nil {
					t.Fatalf("records: %+v %+v", s.RevocationRecords, ex.Revocation)
				}
			case RevocationInvalid:
				if ex.Revocation.Record != "" {
					t.Fatalf("an invalid revocation names a record: %+v", ex.Revocation)
				}
			default:
				if ex.Revocation.RecordDigest != "" {
					t.Fatalf("an unverified record has a digest: %+v", ex.Revocation)
				}
			}
			if tc.recordLims > 0 && (len(s.RevocationRecords) != 1 || s.RevocationRecords[0].VerifyError == "" || s.RevocationRecords[0].ExceptionUID != "") {
				t.Fatalf("tampered record: %+v", s.RevocationRecords)
			}
			// Records are listed by label in the controller namespace; only
			// an unlisted record name is read by name; nothing else is read.
			var listed, named int
			for _, r := range f.recorded() {
				if r.Path == pathConfigMaps(ctrlNS) && strings.Contains(r.Query, "labelSelector=app.kubernetes.io%2Fcomponent%3Drevocation-record%2Capp.kubernetes.io%2Fmanaged-by%3Dkonstapel") {
					listed++
				}
				if r.Path == pathConfigMaps(ctrlNS)+"/"+recordName {
					named++
				}
			}
			if listed != 2 || (named == 2) != tc.namedGet || (named != 0 && named != 2) {
				t.Fatalf("revocation record reads: listed=%d named=%d", listed, named)
			}
			assertReadOnly(t, f.recorded())
			assertNoRevocationLeak(t, s)
		})
	}
}

// 2.5: a revocation that lands, is recorded or is released during the
// observation forces a recapture, and the final snapshot is the stable state.
func TestObserveRecapturesOnRevocationChange(t *testing.T) {
	for name, tc := range map[string]struct {
		before func(t *testing.T, f *fakeAPI)
		change func(t *testing.T, f *fakeAPI)
		state  RevocationState
	}{
		"revocation lands": {
			change: func(t *testing.T, f *fakeAPI) { revoke(t, f, "allow-debug") },
			state:  RevocationPending,
		},
		"record written": {
			before: func(t *testing.T, f *fakeAPI) { revoke(t, f, "allow-debug") },
			change: func(t *testing.T, f *fakeAPI) { record(t, f, storedException(t, f, "allow-debug")) },
			state:  RevocationRecorded,
		},
		"finalizer released": {
			before: func(t *testing.T, f *fakeAPI) { record(t, f, revoke(t, f, "allow-debug")) },
			change: func(t *testing.T, f *fakeAPI) {
				ex := storedException(t, f, "allow-debug")
				ex.Finalizers = nil
				f.put(pathExceptions, ex)
			},
			state: RevocationRecorded,
		},
		"owner verdict": {
			before: func(t *testing.T, f *fakeAPI) {
				revoke(t, f, "allow-debug")
				ownerReports(t, f, "allow-debug", metav1.ConditionFalse, v1alpha1.ReasonRevocationHistoryPending, 2)
			},
			change: func(t *testing.T, f *fakeAPI) {
				ownerReports(t, f, "allow-debug", metav1.ConditionFalse, v1alpha1.ReasonRevocationProcessingDisabled, 2)
			},
			state: RevocationPending,
		},
		// Only the protected record changes, and the state stays pending:
		// the record content itself is part of the projection.
		"protected record replaced": {
			before: func(t *testing.T, f *fakeAPI) { revoke(t, f, "allow-debug") },
			change: func(t *testing.T, f *fakeAPI) {
				f.mutate(pathExceptions, "allow-debug", func(m map[string]any) {
					ann := m["metadata"].(map[string]any)["annotations"].(map[string]any)
					var r exception.Revocation
					_ = json.Unmarshal([]byte(ann[exception.RevocationAnnotation].(string)), &r)
					r.RequestedAt = metav1.NewTime(r.RequestedAt.Add(time.Second))
					raw, _ := json.Marshal(r)
					ann[exception.RevocationAnnotation] = string(raw)
				})
			},
			state: RevocationPending,
		},
		"unlabelled object appears at the record name": {
			before: func(t *testing.T, f *fakeAPI) { revoke(t, f, "allow-debug") },
			change: func(t *testing.T, f *fakeAPI) {
				f.put(pathConfigMaps(ctrlNS), &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: exception.RevocationRecordName("uid-ex", 1)}, Data: map[string]string{"x": "y"}})
			},
			state: RevocationConflict,
		},
		"record tampered": {
			before: func(t *testing.T, f *fakeAPI) { record(t, f, revoke(t, f, "allow-debug")) },
			change: func(t *testing.T, f *fakeAPI) {
				f.mutate(pathConfigMaps(ctrlNS), exception.RevocationRecordName("uid-ex", 1), func(m map[string]any) {
					m["metadata"].(map[string]any)["annotations"].(map[string]any)[exception.AnnotationRecordDigest] = digestB
				})
			},
			state: RevocationConflict,
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := baseline(t)
			if tc.before != nil {
				tc.before(t, f)
			}
			f.onCapture = func(n int) {
				if n == 2 {
					tc.change(t, f)
				}
			}
			s, err := observe(t, f, nil)
			mustComplete(t, s, err)
			if s.Captures != 3 || len(s.Drift) != 1 || len(s.Drift[0].Changed) == 0 {
				t.Fatalf("captures=%d drift=%+v", s.Captures, s.Drift)
			}
			if r := s.Exceptions[0].Revocation; r == nil || r.State != tc.state {
				t.Fatalf("the final snapshot is not the stable state: %+v", r)
			}
			assertReadOnly(t, f.recorded())
		})
	}

	// A revocation state that keeps changing is incomplete, never a result
	// assembled from incompatible states.
	t.Run("persistent", func(t *testing.T) {
		f := baseline(t)
		revoke(t, f, "allow-debug")
		f.onCapture = func(n int) {
			if n >= 2 {
				ownerReports(t, f, "allow-debug", metav1.ConditionFalse, []string{v1alpha1.ReasonRevocationHistoryPending, v1alpha1.ReasonRevocationProtectionUnverified}[n%2], 2)
			}
		}
		s, err := observe(t, f, nil)
		mustIncomplete(t, s, err, ObserveUnstable)
		if !strings.Contains(s.Errors[0].Message, "complianceexceptions prod/allow-debug") {
			t.Fatalf("errors: %+v", s.Errors)
		}
	})
}

// 2.5: revocation records are required inputs, read like acceptance
// snapshots: a denied list or named read is incomplete, never "no record".
func TestObserveRevocationReadsFailClosed(t *testing.T) {
	forbidden := status(http.StatusForbidden, metav1.StatusReasonForbidden)
	for name, match := range map[string]func(*http.Request) bool{
		"record list denied": func(r *http.Request) bool {
			return r.URL.Path == pathConfigMaps(ctrlNS) && strings.Contains(r.URL.RawQuery, exception.ComponentRevocation)
		},
		"record read denied": func(r *http.Request) bool {
			return r.URL.Path == pathConfigMaps(ctrlNS)+"/"+exception.RevocationRecordName("uid-ex", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := baseline(t)
			revoke(t, f, "allow-debug")
			f.hook = func(w http.ResponseWriter, r *http.Request) bool {
				if match(r) {
					forbidden(w)
					return true
				}
				return false
			}
			s, err := observe(t, f, nil)
			mustIncomplete(t, s, err, ObserveAccessDenied)
			if s.Errors[0].Resource != "/v1/configmaps" || s.Errors[0].Namespace != ctrlNS {
				t.Fatalf("errors: %+v", s.Errors)
			}
			assertReadOnly(t, f.recorded())
		})
	}
}

// 2.5: the revocation inputs add no Secret read, no read outside the
// controller namespace and no other request shape: with a revoked exception
// the requests are those of an unrevoked observation plus the named read of
// the missing record.
func TestObserveRevocationAddsNoOtherReads(t *testing.T) {
	plain := baseline(t)
	s, err := observe(t, plain, nil)
	mustComplete(t, s, err)
	revoked := baseline(t)
	revoke(t, revoked, "allow-debug")
	s, err = observe(t, revoked, nil)
	mustComplete(t, s, err)
	paths := func(reqs []recorded) []string {
		var out []string
		for _, r := range reqs {
			// Continuation tokens carry the store revision, which the
			// revocation writes advance.
			q := continueRevision.ReplaceAllString(r.Query, "continue=")
			out = append(out, r.Method+" "+r.Path+"?"+q)
		}
		slices.Sort(out)
		return out
	}
	got := slices.DeleteFunc(paths(revoked.recorded()), func(p string) bool {
		return p == "GET "+pathConfigMaps(ctrlNS)+"/"+exception.RevocationRecordName("uid-ex", 1)+"?"
	})
	if want := paths(plain.recorded()); !slices.Equal(got, want) {
		t.Fatalf("requests differ:\n%v\n%v", got, want)
	}
	// In the controller namespace: one labelled list of acceptance
	// snapshots and one of revocation records per capture, and the named
	// read of the missing record; nothing else.
	counts := map[string]int{}
	for _, r := range revoked.recorded() {
		if !strings.HasPrefix(r.Path, pathNamespaces+"/"+ctrlNS+"/") {
			continue
		}
		switch {
		case r.Path == pathConfigMaps(ctrlNS) && strings.Contains(r.Query, "labelSelector="+url.QueryEscape(snapshotSelector)+"&"):
			counts["snapshots"]++
		case r.Path == pathConfigMaps(ctrlNS) && strings.Contains(r.Query, "labelSelector="+url.QueryEscape(revocationSelector)+"&"):
			counts["records"]++
		case r.Path == pathConfigMaps(ctrlNS)+"/"+exception.RevocationRecordName("uid-ex", 1) && r.Query == "":
			counts["named"]++
		default:
			t.Fatalf("unexpected controller-namespace read: %+v", r)
		}
	}
	if counts["snapshots"] != 2 || counts["records"] != 2 || counts["named"] != 2 {
		t.Fatalf("controller-namespace reads: %v", counts)
	}
	assertReadOnly(t, revoked.recorded())
}

// 2.5: the guide documents every revocation state the observation reports.
func TestRevocationStatesAreDocumented(t *testing.T) {
	doc, err := os.ReadFile("../../docs/policy-preview.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []ObserveCode{LimitRevocationRecorded, LimitRevocationPending, LimitRevocationProcessingDisabled,
		LimitRevocationConflict, LimitRevocationInvalid, LimitRevocationRecordInvalid} {
		if !strings.Contains(string(doc), "`"+string(code)+"`") {
			t.Errorf("docs/policy-preview.md does not document %s", code)
		}
	}
	if strings.Contains(string(doc), "exception-revocation-unavailable") {
		t.Error("docs/policy-preview.md still describes revocation as unavailable")
	}
}
