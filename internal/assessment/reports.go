package assessment

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
)

type Resource struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
}

func (r Resource) Key(cluster string) string {
	return cluster + "/" + r.APIVersion + "/" + r.Kind + "/" + r.Namespace + "/" + r.Name + "/" + r.UID
}

type Capture struct {
	Version          int        `json:"version"`
	Cluster          string     `json:"cluster"`
	Context          string     `json:"context"`
	Boundary         time.Time  `json:"evaluationBoundary"`
	Collected        time.Time  `json:"collected"`
	Policy           Object     `json:"policy"`
	PolicyDigest     string     `json:"policySpecSha256"`
	MappingDigest    string     `json:"mappingSha256"`
	Expected         []Resource `json:"expected"`
	Reports          []Object   `json:"reports"`
	CollectionErrors []string   `json:"collectionErrors,omitempty"`
}
type Evaluation struct {
	Resource   Resource  `json:"resource"`
	Outcome    string    `json:"sourceOutcome"`
	Normalized string    `json:"normalizedOutcome"`
	Reason     string    `json:"reason"`
	Evaluated  time.Time `json:"evaluated"`
	Report     string    `json:"report"`
	Index      int       `json:"resultIndex"`
	Rule       string    `json:"rule"`
}
type Evidence struct {
	Complete    bool         `json:"complete"`
	Coverage    string       `json:"coverage"`
	Missing     []string     `json:"missing"`
	Rejected    []string     `json:"rejected"`
	Evaluations []Evaluation `json:"evaluations"`
}

func Normalize(s string) policy.Result {
	switch s {
	case "pass":
		return policy.ResultPass
	case "fail":
		return policy.ResultFail
	case "warn", "warning":
		return policy.ResultWarning
	default:
		return policy.ResultError
	}
}

// Reconcile supports wgpolicyk8s.io/v1alpha2 reports only, with either report-level
// scope or result-level resources. Unknown layouts fail closed, never disappear.
func Reconcile(c Capture) (Evidence, policy.PVPResult, error) {
	ev := Evidence{Coverage: Coverage, Missing: []string{}, Rejected: []string{}}
	if c.Version != 1 || c.Cluster == "" || c.Boundary.IsZero() || c.Collected.Before(c.Boundary) || len(c.Expected) == 0 {
		return ev, policy.PVPResult{}, fmt.Errorf("invalid capture identity, time boundary, or empty expected inventory")
	}
	if c.Policy["apiVersion"] != "policies.kyverno.io/v1" || c.Policy["kind"] != "ValidatingPolicy" || Str(At(c.Policy, "metadata", "name")) != PolicyName || Str(At(c.Policy, "metadata", "uid")) == "" || c.PolicyDigest != Digest(c.Policy["spec"]) || c.MappingDigest == "" {
		return ev, policy.PVPResult{}, fmt.Errorf("invalid captured policy identity/revision")
	}
	expected := map[string]Resource{}
	for _, r := range c.Expected {
		if r.UID == "" || r.Name == "" || r.Kind == "" || r.APIVersion == "" {
			return ev, policy.PVPResult{}, fmt.Errorf("incomplete resource identity")
		}
		expected[r.Key(c.Cluster)] = r
	}
	best := map[string]Evaluation{}
	bad := map[string]bool{}
	for _, report := range c.Reports {
		if report["apiVersion"] != "wgpolicyk8s.io/v1alpha2" || (report["kind"] != "PolicyReport" && report["kind"] != "ClusterPolicyReport") {
			return ev, policy.PVPResult{}, fmt.Errorf("unsupported report layout %v/%v", report["apiVersion"], report["kind"])
		}
		reportID := Str(At(report, "metadata", "uid"))
		if reportID == "" {
			return ev, policy.PVPResult{}, fmt.Errorf("report missing UID")
		}
		results, ok := report["results"].([]any)
		if !ok {
			return ev, policy.PVPResult{}, fmt.Errorf("report results must be an array")
		}
		for index, raw := range results {
			result := Map(raw)
			if result == nil {
				return ev, policy.PVPResult{}, fmt.Errorf("malformed report result")
			}
			if Str(result["policy"]) != PolicyName {
				continue
			}
			if result["source"] != "KyvernoValidatingPolicy" {
				return ev, policy.PVPResult{}, fmt.Errorf("unsupported source for matching policy: %v", result["source"])
			}
			refs, ok := result["resources"].([]any)
			if !ok {
				if scope := Map(report["scope"]); scope != nil {
					refs = []any{scope}
				} else {
					return ev, policy.PVPResult{}, fmt.Errorf("matching result has no resource scope")
				}
			}
			if len(refs) == 0 {
				return ev, policy.PVPResult{}, fmt.Errorf("empty result resources")
			}
			stamp := Map(result["timestamp"])
			seconds, ok := stamp["seconds"].(float64)
			if !ok {
				return ev, policy.PVPResult{}, fmt.Errorf("missing source evaluation timestamp")
			}
			nanos, _ := stamp["nanos"].(float64)
			if math.Trunc(seconds) != seconds || math.Trunc(nanos) != nanos || nanos < 0 || nanos >= 1e9 {
				return ev, policy.PVPResult{}, fmt.Errorf("invalid source timestamp")
			}
			t := time.Unix(int64(seconds), int64(nanos)).UTC()
			outcome := Str(result["result"])
			if outcome == "" {
				return ev, policy.PVPResult{}, fmt.Errorf("missing source outcome")
			}
			for _, ref := range refs {
				b := Map(ref)
				r := Resource{APIVersion: Str(b["apiVersion"]), Kind: Str(b["kind"]), Namespace: Str(b["namespace"]), Name: Str(b["name"]), UID: Str(b["uid"])}
				key := r.Key(c.Cluster)
				if _, ok := expected[key]; !ok {
					ev.Rejected = append(ev.Rejected, "unmatched resource UID: "+key)
					continue
				}
				if t.Before(c.Boundary) || t.After(c.Collected) {
					ev.Rejected = append(ev.Rejected, "outside evaluation boundary: "+key)
					continue
				}
				rule := Str(result["rule"])
				if rule == "" {
					rule = Str(At(result, "properties", "cel.validationIndex"))
				}
				e := Evaluation{r, outcome, Normalize(outcome).String(), Str(result["message"]), t, reportID, index, rule}
				if old, ok := best[key]; ok && old.Evaluated.Equal(t) && (old.Outcome != e.Outcome || old.Rule != e.Rule) {
					bad[key] = true
					ev.Rejected = append(ev.Rejected, "ambiguous concurrent results: "+key)
				}
				if old, ok := best[key]; !ok || old.Evaluated.Before(t) {
					best[key] = e
				}
			}
		}
	}
	keys := make([]string, 0, len(expected))
	for k := range expected {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	obs := policy.ObservationByCheck{Title: PolicyName, Description: Coverage, CheckID: PolicyName, Methods: []string{"TEST"}, Collected: c.Collected, RelevantEvidences: []policy.Link{{Href: "capture.json", Description: "Raw reports, applied policy, independent inventory and evaluation boundary"}}}
	for _, key := range keys {
		r := expected[key]
		e, ok := best[key]
		if !ok || bad[key] {
			ev.Missing = append(ev.Missing, key)
			continue
		}
		ev.Evaluations = append(ev.Evaluations, e)
		props := []policy.Property{{Name: "cluster-id", Value: c.Cluster}, {Name: "resource-uid", Value: r.UID}, {Name: "source-outcome", Value: e.Outcome}, {Name: "policy-name", Value: PolicyName}, {Name: "policy-uid", Value: Str(At(c.Policy, "metadata", "uid"))}, {Name: "policy-spec-sha256", Value: c.PolicyDigest}, {Name: "mapping-sha256", Value: c.MappingDigest}, {Name: "source-report-uid", Value: e.Report}, {Name: "source-result-index", Value: fmt.Sprint(e.Index)}, {Name: "source-rule", Value: e.Rule}}
		obs.Subjects = append(obs.Subjects, policy.Subject{Title: r.Kind + " " + r.Namespace + "/" + r.Name, Type: "inventory-item", ResourceID: key, Result: Normalize(e.Outcome), EvaluatedOn: e.Evaluated, Reason: e.Reason, Props: props})
	}
	ev.Complete = len(ev.Missing) == 0 && len(c.CollectionErrors) == 0
	// Missing observations are represented as errors with no invented evaluation time.
	for _, key := range ev.Missing {
		obs.Subjects = append(obs.Subjects, policy.Subject{Title: "Missing current evidence", Type: "inventory-item", ResourceID: key, Result: policy.ResultError, Reason: "No unambiguous current result; assessment incomplete", Props: []policy.Property{{Name: "source-outcome", Value: "missing"}, {Name: "cluster-id", Value: c.Cluster}}})
	}
	return ev, policy.PVPResult{ObservationsByCheck: []policy.ObservationByCheck{obs}}, nil
}
