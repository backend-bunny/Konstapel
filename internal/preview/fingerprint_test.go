package preview

import (
	"strings"
	"testing"
)

func fp(t *testing.T, doc string) string {
	t.Helper()
	return mustSet(t, doc).Objects[0].Fingerprint
}

const profileHeader = "apiVersion: compliance.erenius.io/v1alpha1\nkind: ComplianceProfile\nmetadata:\n  name: p\n"
const bindingHeader = "apiVersion: compliance.erenius.io/v1alpha1\nkind: ComplianceBinding\nmetadata:\n  name: b\n"

func profileDoc(bundle, policies string) string {
	return profileHeader + "spec:\n  bundle: {name: " + bundle + ", digest: " + digestA + "}\n  policies:\n" + policies
}

func TestFingerprintEqualForEquivalentInputs(t *testing.T) {
	base := profileDoc("hard", "    - name: a\n      parameters: {x: 1, w: [1, 2], z: {k: v, j: w}}\n    - name: b\n")
	same := []string{
		// default written out
		profileDoc("hard", "    - name: a\n      parameters: {x: 1, w: [1, 2], z: {k: v, j: w}}\n      exceptions: {eligibility: Forbidden}\n    - name: b\n      exceptions: {}\n"),
		// policies and parameter keys reordered
		profileDoc("hard", "    - name: b\n    - name: a\n      parameters: {z: {j: w, k: v}, w: [1, 2], x: 1}\n"),
		// null parameters pruned like omitted
		profileDoc("hard", "    - name: a\n      parameters: {x: 1, w: [1, 2], z: {k: v, j: w}}\n    - name: b\n      parameters: null\n"),
		// metadata, status, server fields
		strings.Replace(base, "  name: p\n", "  name: p\n  uid: abc\n  labels: {a: b}\n  generation: 4\n", 1) + "status: {observedGeneration: 4}\n",
	}
	want := fp(t, base)
	for i, d := range same {
		if got := fp(t, d); got != want {
			t.Errorf("variant %d fingerprint differs:\n%s", i, d)
		}
	}
	bb := bindingHeader + "spec:\n  profileRef: {name: p}\n  mode: Audit\n  namespaceSelector:\n    matchLabels: {a: b, c: d}\n    matchExpressions:\n      - {key: x, operator: In, values: [2, 1]}\n      - {key: yy, operator: Exists}\n"
	bsame := []string{
		// defaults explicit, durations spelled differently, epoch given, reordered
		bindingHeader + "spec:\n  enforcementEpoch: 12\n  mode: Audit\n  assessment: {interval: 1440m, maxEvidenceAge: 2h, collectionTimeout: 300s, retention: 2160h}\n  namespaceSelector:\n    matchExpressions:\n      - {key: yy, operator: Exists}\n      - {key: x, operator: In, values: [\"1\", \"2\", \"1\"]}\n    matchLabels: {c: d, a: b}\n  profileRef: {name: p}\n",
	}
	bb = strings.ReplaceAll(bb, "values: [2, 1]", "values: [\"2\", \"1\"]")
	bwant := fp(t, bb)
	for i, d := range bsame {
		if got := fp(t, d); got != bwant {
			t.Errorf("binding variant %d fingerprint differs", i)
		}
	}
}

func TestFingerprintDiffersForEverySemanticField(t *testing.T) {
	base := profileDoc("hard", "    - name: a\n      parameters: {x: 1}\n")
	baseFP := fp(t, base)
	profileChanges := map[string]string{
		"bundle-name":                profileDoc("other", "    - name: a\n      parameters: {x: 1}\n"),
		"bundle-digest":              strings.Replace(base, digestA, digestB, 1),
		"parameter":                  profileDoc("hard", "    - name: a\n      parameters: {x: 2}\n"),
		"parameters-empty-vs-absent": profileDoc("hard", "    - name: a\n      parameters: {}\n"),
		"extra-policy":               base + "    - name: c\n",
		"eligibility":                profileDoc("hard", "    - name: a\n      parameters: {x: 1}\n      exceptions: {eligibility: SelfService, maxLifetime: 1h}\n"),
		"policy-name":                profileDoc("hard", "    - name: z\n      parameters: {x: 1}\n"),
	}
	for name, d := range profileChanges {
		if fp(t, d) == baseFP {
			t.Errorf("profile change %q not reflected", name)
		}
	}
	ss := func(life string) string {
		return profileDoc("hard", "    - name: a\n      exceptions: {eligibility: SelfService, maxLifetime: "+life+"}\n")
	}
	if fp(t, ss("1h")) == fp(t, ss("2h")) || fp(t, ss("1h")) != fp(t, ss("60m")) {
		t.Error("maxLifetime handling")
	}

	bind := func(spec string) string {
		return bindingHeader + "spec:\n  profileRef: {name: p}\n  mode: Audit\n" + spec
	}
	b0 := fp(t, bind("  namespaceSelector: {matchLabels: {a: b}}\n"))
	bindChanges := map[string]string{
		"selector-label": bind("  namespaceSelector: {matchLabels: {a: c}}\n"),
		"selector-empty": bind("  namespaceSelector: {}\n"),
		"expression":     bind("  namespaceSelector: {matchLabels: {a: b}, matchExpressions: [{key: k, operator: Exists}]}\n"),
		"mode":           strings.Replace(bind("  namespaceSelector: {matchLabels: {a: b}}\n"), "Audit", "Deny", 1),
		"profile":        strings.Replace(bind("  namespaceSelector: {matchLabels: {a: b}}\n"), "name: p}", "name: q}", 1),
		"interval":       bind("  namespaceSelector: {matchLabels: {a: b}}\n  assessment: {interval: 12h}\n"),
		"destination":    bind("  namespaceSelector: {matchLabels: {a: b}}\n  assessment: {destinationRef: {name: d, uid: u}}\n"),
	}
	for name, d := range bindChanges {
		if fp(t, d) == b0 {
			t.Errorf("binding change %q not reflected", name)
		}
	}
	// operator In vs NotIn with the same values differ.
	in := bind("  namespaceSelector: {matchExpressions: [{key: k, operator: In, values: [v]}]}\n")
	notIn := strings.Replace(in, "In,", "NotIn,", 1)
	if fp(t, in) == fp(t, notIn) {
		t.Error("In vs NotIn")
	}
	if fp(t, profileDoc("hard", "    - name: a\n")) == fp(t, strings.Replace(bind("  namespaceSelector: {}\n"), "x", "x", 1)) {
		t.Error("kinds collide")
	}
}

func TestFingerprintFormat(t *testing.T) {
	f := fp(t, profileDoc("hard", "    - name: a\n"))
	if !digestPattern.MatchString(f) {
		t.Fatal(f)
	}
	if Fingerprint(nil, nil) != "" {
		t.Fatal("nil fingerprint")
	}
}
