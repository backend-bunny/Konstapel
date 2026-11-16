package coverage

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Evidence fixtures: frozen collector captures built with the owner's own
// inventory derivation (collector.BuildInventory) and evaluated with the
// owner's own rules (CaptureV2.Evaluate). Coverage only consumes them.

const (
	evCluster = "cluster-1"
	evNS      = "team-a"
	evNSUID   = "ns-uid-a"
	evMaxAge  = time.Hour
)

var (
	evStarted = time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	evClosed  = evStarted.Add(10 * time.Minute)
)

// contrib is one binding contribution of a fixture capture.
type contrib struct {
	binding, revision, policy string
	bundle                    v1alpha1.BundleReference
	// validations is the engine policy's number of sub-validations.
	validations int
}

func (c contrib) enginePolicy() string {
	return "konstapel-" + c.binding + "-" + c.policy + "-" + c.revision
}

func (c contrib) subject() targeting.EvidenceSubject {
	return targeting.EvidenceSubject{Cluster: evCluster, Namespace: evNS, NamespaceUID: types.UID(evNSUID), BindingName: c.binding,
		BindingUID: types.UID(c.binding), Revision: c.revision, EnginePolicy: c.enginePolicy(), LogicalPolicy: c.policy, Mode: v1alpha1.ModeAudit,
		Checks: []string{}, Resources: []string{"/v1/pods"}, BundleName: c.bundle.Name, BundleDigest: c.bundle.Digest,
		ConfigurationDigest: "sha256:config-" + c.revision, SourceDigest: "sha256:source-" + c.policy}
}

func pod(name string) collector.Workload {
	return collector.Workload{Resource: "/v1/pods", Namespace: evNS, NamespaceUID: evNSUID, Name: name, UID: "uid-" + name, StateSHA256: "state-" + name}
}

// capture freezes the contributions against the pods.
func capture(t *testing.T, contribs []contrib, pods ...collector.Workload) collector.CaptureV2 {
	t.Helper()
	c := collector.CaptureV2{Version: collector.CaptureV2Version, Cluster: evCluster, Window: collector.CaptureWindow{Started: evStarted, Closed: evClosed},
		MappingSHA256: "sha256:mapping", Subjects: []targeting.EvidenceSubject{}, Stale: []targeting.StaleScope{},
		Checks: []collector.Check{}, Workloads: pods, Reports: []assessment.Object{}}
	for _, x := range contribs {
		c.Subjects = append(c.Subjects, x.subject())
		n := max(x.validations, 1)
		for i := range n {
			c.Checks = append(c.Checks, collector.Check{EnginePolicy: x.enginePolicy(), Index: i, SHA256: "check-" + x.enginePolicy() + "-" + strconv.Itoa(i)})
		}
	}
	var err error
	if c.Expected, err = collector.BuildInventory(c.Subjects, c.Checks, c.Workloads, c.MappingSHA256); err != nil {
		t.Fatal(err)
	}
	return c
}

// result is one Kyverno report result for a workload and sub-validation.
func result(engine string, index int, w collector.Workload, outcome string, at time.Time) assessment.Object {
	return assessment.Object{"apiVersion": "wgpolicyk8s.io/v1alpha2", "kind": "PolicyReport",
		"metadata": assessment.Object{"uid": "report-" + w.Name, "namespace": evNS},
		"scope":    assessment.Object{"apiVersion": "v1", "kind": "Pod", "namespace": evNS, "uid": w.UID},
		"results": []any{assessment.Object{"policy": engine, "result": outcome, "source": "KyvernoValidatingPolicy",
			"properties": assessment.Object{"cel.validationIndex": strconv.Itoa(index)},
			"timestamp":  assessment.Object{"seconds": float64(at.Unix()), "nanos": float64(0)}}}}
}

// reportAll reports outcome for every expected observation at time at.
func reportAll(c *collector.CaptureV2, at time.Time, outcome string) {
	for _, e := range c.Expected {
		c.Reports = append(c.Reports, result(e.Check.EnginePolicy, e.Check.Index, e.Workload, outcome, at))
	}
}

// evaluated is the owner's evaluation of c at closure.
func evaluated(t *testing.T, c collector.CaptureV2, age time.Duration) *Evidence {
	t.Helper()
	ev, err := c.Evaluate(nil, age)
	if err != nil {
		t.Fatal(err)
	}
	return &Evidence{Capture: c, Evaluation: ev}
}

// observationsOf are a check's referenced keys across contributions.
func observationsOf(ch CheckCoverage) []string {
	var out []string
	if ch.Evidence == nil {
		return nil
	}
	for _, c := range ch.Evidence.Contributions {
		out = append(out, c.Observations...)
	}
	return out
}

// record is the report's record of the observation with key k.
func record(t *testing.T, r *Report, k string) ObservationRecord {
	t.Helper()
	for _, o := range r.TechnicalEvidence.Observations {
		if o.Observation.Key == k {
			return o
		}
	}
	t.Fatalf("no observation record %q", k)
	return ObservationRecord{}
}

// clone deep-copies v through JSON.
func clone[T any](v T) T {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var x T
	if err := json.Unmarshal(b, &x); err != nil {
		panic(err)
	}
	return x
}
