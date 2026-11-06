package exception

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/yaml"
)

// The lifecycle fixture format. testdata/exceptions/README.md documents it.
// Inputs are deliberately abstract (no API types yet): groups 2-5 map each
// case onto the ComplianceException API, the controller and the evidence
// pipeline, and assert the same expectations.

type matrix struct {
	Cases []fixtureCase `json:"cases"`
}

type fixtureCase struct {
	ID         string       `json:"id"`
	Category   string       `json:"category"`
	Boundaries []string     `json:"boundaries"`
	Scenarios  []string     `json:"scenarios"`
	Setup      fixtureSetup `json:"setup"`
	Steps      []step       `json:"steps"`
}

type fixtureSetup struct {
	Namespaces        []namespace    `json:"namespaces"`
	Contributions     []contribution `json:"contributions"`
	EngineReady       bool           `json:"engineReady"`
	ExistingWorkloads []workload     `json:"existingWorkloads,omitempty"`
	Acceptances       []acceptance   `json:"acceptances,omitempty"`
}

type namespace struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}

type contribution struct {
	Binding     string `json:"binding"`
	Policy      string `json:"policy"`
	Revision    string `json:"revision"`
	Eligibility string `json:"eligibility"`
	MaxLifetime string `json:"maxLifetime,omitempty"`
	// Generation is binding provenance only; acceptance compares Revision.
	Generation int `json:"generation,omitempty"`
}

type workload struct {
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels"`
}

type acceptance struct {
	Exception  string `json:"exception"`
	Revision   int    `json:"revision"`
	ValidFrom  string `json:"validFrom"`
	ValidUntil string `json:"validUntil"`
	Snapshot   string `json:"snapshot"`
}

type actor struct {
	Username string   `json:"username"`
	UID      string   `json:"uid"`
	Groups   []string `json:"groups"`
}

type exceptionInput struct {
	Name      string             `json:"name,omitempty"`
	Namespace string             `json:"namespace,omitempty"`
	Policy    string             `json:"policy,omitempty"`
	Selector  *map[string]string `json:"selector"`
	Reason    *string            `json:"reason,omitempty"`
	ExpiresAt string             `json:"expiresAt,omitempty"`
}

type renewal struct {
	AcceptanceRevision int    `json:"acceptanceRevision"`
	Reason             string `json:"reason"`
	ExpiresAt          string `json:"expiresAt"`
}

type nativeWrite struct {
	Verb       string `json:"verb"`
	APIVersion string `json:"apiVersion"`
	Namespace  string `json:"namespace"`
	Change     string `json:"change,omitempty"`
}

type report struct {
	Result        string   `json:"result"`
	EvaluatedAt   string   `json:"evaluatedAt"`
	ExceptionRefs []string `json:"exceptionRefs"`
}

type step struct {
	At                   string          `json:"at"`
	Action               string          `json:"action"`
	Note                 string          `json:"note,omitempty"`
	DryRun               bool            `json:"dryRun,omitempty"`
	Stale                bool            `json:"stale,omitempty"`
	Actor                *actor          `json:"actor,omitempty"`
	ForgedAttribution    *actor          `json:"forgedAttribution,omitempty"`
	ClaimedBy            string          `json:"claimedBy,omitempty"`
	Exception            *exceptionInput `json:"exception,omitempty"`
	Renewal              *renewal        `json:"renewal,omitempty"`
	Contributions        []contribution  `json:"contributions,omitempty"`
	Namespaces           []namespace     `json:"namespaces,omitempty"`
	Native               *nativeWrite    `json:"native,omitempty"`
	Report               *report         `json:"report,omitempty"`
	EngineExpiryVerified *bool           `json:"engineExpiryVerified,omitempty"`
	Expect               map[string]any  `json:"expect"`
}

var (
	categories = []string{"acceptance", "renewal", "revocation", "report", "native"}
	boundaries = []string{"namespace", "revision", "eligibility", "attribution", "lifetime",
		"expired-context", "missing-context", "native-governance", "engine"}
	actions = []string{"create", "renew", "metadata-edit", "change-scope", "revoke", "expire",
		"change-contribution", "recreate-namespace", "namespace-identity-unavailable", "native-write",
		"unmanaged-collision", "engine-converged", "engine-unavailable", "stop-controller",
		"start-controller", "engine-runtime-check", "report", "delete-live-history"}
	eligibilities = []string{"SelfService", "Forbidden", "Unresolved"}
	// Closed vocabularies for expectation keys whose values are enumerable.
	enums = map[string][]string{
		"admission":             {"admitted", "rejected"},
		"grant":                 {"none", "active", "withdrawal-pending", "withdrawn"},
		"snapshot":              {"none", "recorded", "new", "unchanged", "retained"},
		"previousSnapshot":      {"retained"},
		"eligibility":           {"Eligible", "Ineligible"},
		"engineObserved":        {"True", "False", "Unknown"},
		"rawResult":             {"pass", "fail", "skip"},
		"disposition":           {"unexcepted", "accepted-risk", "unresolved"},
		"backgroundDisposition": {"unexcepted", "accepted-risk", "unresolved"},
		"offlineInterpretation": {"unexcepted", "accepted-risk", "unresolved"},
		"controlCoverage":       {"unchanged"},
	}
	// Every expectation key must be one of these, so a typo cannot silently
	// turn an assertion into an ignored field.
	expectKeys = []string{"admission", "reason", "acceptanceRevision", "snapshot", "previousSnapshot",
		"snapshotActor", "snapshotClaim", "acceptedRevisions", "grant", "approvalRequired", "workload",
		"restrictiveContribution", "effectiveMaxLifetime", "eligibility", "engineObserved",
		"existingWorkloadsRetained", "backgroundDisposition", "featureEnabled", "nativeNamespaceUID",
		"native", "unmanagedUntouched", "rawResult", "disposition", "countsAsPass", "fabricatedFailure",
		"dispositionReason", "dispositionActor", "exceptionRefs", "controlCoverage", "packagedSnapshot",
		"offlineInterpretation"}
)

func loadMatrix(t *testing.T) matrix {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/exceptions/lifecycle-matrix.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var m matrix
	if err := yaml.UnmarshalStrict(raw, &m); err != nil {
		t.Fatalf("lifecycle-matrix.yaml: %v", err)
	}
	if len(m.Cases) == 0 {
		t.Fatal("no cases")
	}
	return m
}

// specScenarios returns the scenario names of the policy-exceptions spec,
// whether the change is still open or already archived into openspec/specs.
func specScenarios(t *testing.T) []string {
	t.Helper()
	for _, p := range []string{
		"../../openspec/changes/add-self-service-policy-exceptions/specs/policy-exceptions/spec.md",
		"../../openspec/specs/policy-exceptions/spec.md",
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var out []string
		for _, m := range regexp.MustCompile(`(?m)^#### Scenario: (.+)$`).FindAllStringSubmatch(string(b), -1) {
			out = append(out, strings.TrimSpace(m[1]))
		}
		return out
	}
	t.Fatal("policy-exceptions spec not found")
	return nil
}

func TestLifecycleMatrixCoversEveryScenario(t *testing.T) {
	m := loadMatrix(t)
	spec := specScenarios(t)
	covered := map[string]int{}
	for _, c := range m.Cases {
		for _, s := range c.Scenarios {
			if !slices.Contains(spec, s) {
				t.Errorf("case %s cites %q, which is not a policy-exceptions scenario", c.ID, s)
			}
			covered[s]++
		}
	}
	for _, s := range spec {
		if covered[s] == 0 {
			t.Errorf("scenario %q has no fixture case with an explicit expected outcome", s)
		}
	}
}

// Task 1.1 names the axes the matrix must span.
func TestLifecycleMatrixSpansRequiredAxes(t *testing.T) {
	m := loadMatrix(t)
	seenCategory, seenBoundary := map[string]bool{}, map[string]bool{}
	for _, c := range m.Cases {
		seenCategory[c.Category] = true
		for _, b := range c.Boundaries {
			seenBoundary[b] = true
		}
	}
	for _, want := range categories {
		if !seenCategory[want] {
			t.Errorf("no %s case", want)
		}
	}
	for _, want := range boundaries {
		if !seenBoundary[want] {
			t.Errorf("no case exercises the %s boundary", want)
		}
	}
}

func TestLifecycleMatrixIsWellFormed(t *testing.T) {
	m := loadMatrix(t)
	ids := map[string]bool{}
	for _, c := range m.Cases {
		t.Run(c.ID, func(t *testing.T) {
			if c.ID == "" || ids[c.ID] {
				t.Fatalf("missing or duplicate id %q", c.ID)
			}
			ids[c.ID] = true
			if !slices.Contains(categories, c.Category) {
				t.Errorf("unknown category %q", c.Category)
			}
			if len(c.Boundaries) == 0 || len(c.Scenarios) == 0 || len(c.Steps) == 0 {
				t.Fatal("a case needs boundaries, scenarios and steps")
			}
			for _, b := range c.Boundaries {
				if !slices.Contains(boundaries, b) {
					t.Errorf("unknown boundary %q", b)
				}
			}
			if len(c.Setup.Namespaces) == 0 || len(c.Setup.Contributions) == 0 {
				t.Error("setup needs namespaces and contributions")
			}
			checkContributions(t, c.Setup.Contributions)
			for _, a := range c.Setup.Acceptances {
				from, until := parseTime(t, a.ValidFrom), parseTime(t, a.ValidUntil)
				if !until.After(from) {
					t.Errorf("acceptance %s has an empty validity interval", a.Exception)
				}
			}
			var last time.Time
			for i, s := range c.Steps {
				at := parseTime(t, s.At)
				if at.Before(last) {
					t.Errorf("step %d goes back in time", i)
				}
				last = at
				checkStep(t, i, s)
			}
		})
	}
}

func checkContributions(t *testing.T, cs []contribution) {
	t.Helper()
	for _, c := range cs {
		if c.Binding == "" || c.Policy == "" || c.Revision == "" {
			t.Errorf("contribution %+v needs binding, policy and revision", c)
		}
		if !slices.Contains(eligibilities, c.Eligibility) {
			t.Errorf("contribution %s/%s: unknown eligibility %q", c.Binding, c.Policy, c.Eligibility)
		}
		if c.Eligibility == "SelfService" {
			if _, err := time.ParseDuration(c.MaxLifetime); err != nil {
				t.Errorf("SelfService contribution %s/%s needs a maxLifetime: %v", c.Binding, c.Policy, err)
			}
		}
	}
}

func checkStep(t *testing.T, i int, s step) {
	t.Helper()
	if !slices.Contains(actions, s.Action) {
		t.Errorf("step %d: unknown action %q", i, s.Action)
	}
	if len(s.Expect) == 0 {
		t.Errorf("step %d (%s): no explicit expected outcome", i, s.Action)
	}
	for k, v := range s.Expect {
		if !slices.Contains(expectKeys, k) {
			t.Errorf("step %d: unknown expectation %q", i, k)
			continue
		}
		if allowed, ok := enums[k]; ok {
			if str, _ := v.(string); !slices.Contains(allowed, str) {
				t.Errorf("step %d: %s=%v, want one of %v", i, k, v, allowed)
			}
		}
	}
	// Operations by a caller must say who the authenticated caller is, and a
	// rejection must say why.
	switch s.Action {
	case "create", "renew", "metadata-edit", "change-scope", "revoke", "native-write":
		if s.Actor == nil || s.Actor.Username == "" {
			t.Errorf("step %d (%s): no authenticated actor", i, s.Action)
		}
		if _, ok := s.Expect["admission"]; !ok {
			t.Errorf("step %d (%s): no expected admission outcome", i, s.Action)
		}
	}
	if s.Expect["admission"] == "rejected" && s.Expect["reason"] == nil {
		t.Errorf("step %d: a rejection needs a reason", i)
	}
	switch s.Action {
	case "create":
		if s.Exception == nil || s.Exception.Namespace == "" || s.Exception.Policy == "" {
			t.Errorf("step %d: create needs an exception with namespace and policy", i)
		}
	case "renew":
		if s.Renewal == nil {
			t.Errorf("step %d: renew needs a renewal", i)
		}
	case "change-contribution":
		if len(s.Contributions) == 0 {
			t.Errorf("step %d: change-contribution needs the new contribution set", i)
		}
		checkContributions(t, s.Contributions)
	case "native-write":
		if s.Native == nil {
			t.Errorf("step %d: native-write needs the attempted write", i)
		}
	case "report":
		if s.Report == nil {
			t.Errorf("step %d: report needs a report", i)
		} else {
			parseTime(t, s.Report.EvaluatedAt)
			if _, ok := s.Expect["disposition"]; !ok {
				t.Errorf("step %d: a report needs an expected disposition", i)
			}
		}
	}
}

func parseTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Errorf("time %q: %v", s, err)
	}
	return v
}
