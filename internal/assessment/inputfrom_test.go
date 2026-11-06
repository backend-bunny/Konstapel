package assessment

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func planControls(t *testing.T, rules []string) (string, []string) {
	t.Helper()
	in, plan, err := InputFrom("../..", ComponentDefinitions, rules)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := in.Store().FindByComponent(context.Background(), "konstapel-kyverno")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rs {
		got = append(got, r.Rule.ID)
	}
	slices.Sort(got)
	b, _ := json.Marshal(plan)
	return string(b), got
}

// The merged input covers every shipped check once, and scoping keeps only
// the assessed checks' rules and controls.
func TestInputFromScopesChecksAndControls(t *testing.T) {
	plan, rules := planControls(t, nil)
	if len(rules) != 5 || !strings.Contains(plan, `"cm-7"`) || !strings.Contains(plan, `"ac-6"`) {
		t.Fatalf("unscoped: rules %v", rules)
	}
	plan, rules = planControls(t, []string{PolicyName})
	if !slices.Equal(rules, []string{PolicyName}) || strings.Contains(plan, `"cm-6"`) || strings.Contains(plan, `"cm-7"`) {
		t.Fatalf("privileged only: rules %v", rules)
	}
	plan, rules = planControls(t, []string{"restrict-seccomp-strict"})
	if !slices.Equal(rules, []string{"restrict-seccomp-strict"}) || strings.Contains(plan, `"ac-6"`) || !strings.Contains(plan, `"cm-6"`) || !strings.Contains(plan, `"cm-7"`) {
		t.Fatalf("seccomp only: rules %v", rules)
	}
	// The first-loop path is unchanged.
	in, _, err := Input("../..")
	if err != nil {
		t.Fatal(err)
	}
	if rs, _ := in.Store().FindByComponent(context.Background(), "konstapel-kyverno"); len(rs) != 1 || rs[0].Rule.ID != PolicyName {
		t.Fatalf("Input changed: %v", rs)
	}
}
