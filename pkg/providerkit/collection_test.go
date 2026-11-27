package providerkit

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
)

func TestCheckInventory(t *testing.T) {
	if err := CheckInventory(testInventory, testScope, DefaultMaxSubjects); err != nil {
		t.Fatalf("the test inventory: %v", err)
	}
	for name, tc := range map[string]struct {
		mutate func(*providerv1.Inventory)
		reason providerv1.ErrorReason
	}{
		"no subject":             {func(i *providerv1.Inventory) { i.Subjects = nil }, providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST},
		"supplements unset":      {func(i *providerv1.Inventory) { i.Supplements = 0 }, providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST},
		"supplements unknown":    {func(i *providerv1.Inventory) { i.Supplements = 9 }, providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST},
		"repeated uid":           {func(i *providerv1.Inventory) { i.Subjects[1].Uid = "ns-a-uid" }, providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST},
		"outside the scope":      {func(i *providerv1.Inventory) { i.Subjects[1].NamespaceUid = "ns-b-uid" }, providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST},
		"no uid":                 {func(i *providerv1.Inventory) { i.Subjects[1].Uid = "" }, providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST},
		"resource without group": {func(i *providerv1.Inventory) { i.Subjects[1].Resource = "deployments" }, providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST},
		"no name":                {func(i *providerv1.Inventory) { i.Subjects[1].Name = "" }, providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST},
		"no revision":            {func(i *providerv1.Inventory) { i.Subjects[1].Revision = "" }, providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST},
		"no checks":              {func(i *providerv1.Inventory) { i.Subjects[1].Checks = nil }, providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST},
		"repeated check":         {func(i *providerv1.Inventory) { i.Subjects[1].Checks = []string{"a", "a"} }, providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST},
		"too many checks":        {func(i *providerv1.Inventory) { i.Subjects[1].Checks = manyNames(MaxSubjectChecks + 1) }, providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST},
		"namespace of another name": {func(i *providerv1.Inventory) { i.Subjects[0].Name = "team-b" },
			providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST},
		"namespace subject not its own namespace": {func(i *providerv1.Inventory) { i.Subjects[0].Uid = "other" },
			providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST},
	} {
		inv := proto.CloneOf(testInventory)
		tc.mutate(inv)
		if got := ReasonOf(CheckInventory(inv, testScope, DefaultMaxSubjects)); got != tc.reason {
			t.Errorf("%s: %s, want %s", name, got, tc.reason)
		}
	}
	wantReason(t, CheckInventory(nil, testScope, DefaultMaxSubjects), providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST)
	// More subjects than the bound is refused, never truncated.
	wantReason(t, CheckInventory(testInventory, testScope, 1), providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED)
}

func manyNames(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "check-" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + strings.Repeat("y", i/26)
	}
	return out
}

func TestParseCollectionResult(t *testing.T) {
	r, err := ParseCollectionResult([]byte(testResult), nil)
	if err != nil || len(r.GetEvidence()) != 1 || r.GetEvidence()[0].GetDetails().GetFields()["verdict"].GetStringValue() != "PASSED" {
		t.Fatalf("parsed %v, %v", r, err)
	}
	if _, err := ParseCollectionResult([]byte(`{}`), nil); err != nil {
		t.Fatalf("an empty result is well-formed (and attributes nothing): %v", err)
	}
	item := func(extra string) string {
		return `{"evidence":[{"id":"e1","attributions":[{"subject":"w1","check":"posture"}],"observed":"2026-11-26T11:00:00Z"` + extra + `}]}`
	}
	for name, doc := range map[string]string{
		"not an object":         `[]`,
		"unknown field":         `{"evidence":[],"reports":[]}`,
		"unknown item field":    item(`,"verdict":"PASSED"`),
		"details not an object": item(`,"details":"PASSED"`),
		"no attribution":        `{"evidence":[{"id":"e1","observed":"2026-11-26T11:00:00Z"}]}`,
		"untimed":               `{"evidence":[{"id":"e1","attributions":[{"subject":"w1","check":"posture"}]}]}`,
		"invalid time":          `{"evidence":[{"id":"e1","attributions":[{"subject":"w1","check":"posture"}],"observed":"yesterday"}]}`,
		"repeated id":           `{"evidence":[` + strings.Repeat(`{"id":"e1","attributions":[{"subject":"w1","check":"posture"}],"observed":"2026-11-26T11:00:00Z"},`, 2) + `{"id":"e2","attributions":[{"subject":"w1","check":"posture"}],"observed":"2026-11-26T11:00:00Z"}]}`,
		"repeated attribution":  `{"evidence":[{"id":"e1","attributions":[{"subject":"w1","check":"posture"},{"subject":"w1","check":"posture"}],"observed":"2026-11-26T11:00:00Z"}]}`,
		"empty subject":         `{"evidence":[{"id":"e1","attributions":[{"check":"posture"}],"observed":"2026-11-26T11:00:00Z"}]}`,
		"supplement no parent":  `{"supplements":[{"id":"s1","kind":"container"}]}`,
		"repeated supplement":   `{"supplements":[{"id":"s1","parent":"w1","kind":"container"},{"id":"s1","parent":"w1","kind":"container"}]}`,
		"limitation no message": `{"limitations":[{"subject":"w1"}]}`,
		"trailing data":         testResult + `{}`,
		"trailing newline":      testResult + "\n",
		"leading space":         " " + testResult,
	} {
		if _, err := ParseCollectionResult([]byte(doc), nil); ReasonOf(err) != providerv1.ErrorReason_ERROR_REASON_INVALID_RESPONSE {
			t.Errorf("%s: %v", name, err)
		}
	}
	two := `{"evidence":[{"id":"e1","attributions":[{"subject":"w1","check":"posture"}],"observed":"2026-11-26T11:00:00Z"},{"id":"e2","attributions":[{"subject":"w1","check":"posture"}],"observed":"2026-11-26T11:00:00Z"}]}`
	_, err = ParseCollectionResult([]byte(two), &providerv1.Limits{MaxEvidence: 1})
	wantReason(t, err, providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED)
	_, err = ParseCollectionResult([]byte(two), &providerv1.Limits{MaxResultBytes: 16})
	wantReason(t, err, providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED)
	_, err = ParseCollectionResult([]byte(`{"supplements":[{"id":"s1","parent":"w1","kind":"c"},{"id":"s2","parent":"w1","kind":"c"}]}`), &providerv1.Limits{MaxSubjects: 1})
	wantReason(t, err, providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED)
}
