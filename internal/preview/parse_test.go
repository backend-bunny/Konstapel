package preview

import (
	"fmt"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

const digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func profileYAML(name string) string {
	return fmt.Sprintf(`apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceProfile
metadata:
  name: %s
spec:
  bundle:
    name: hardening
    digest: %s
  policies:
    - name: run-as-non-root
`, name, digestA)
}

func bindingYAML(name, profile, mode string) string {
	return fmt.Sprintf(`apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata:
  name: %s
spec:
  profileRef:
    name: %s
  namespaceSelector: {}
  mode: %s
`, name, profile, mode)
}

func codes(errs InputErrors) []Code {
	var out []Code
	for _, e := range errs {
		out = append(out, e.Code)
	}
	return out
}

func TestParseValidStreams(t *testing.T) {
	multi := profileYAML("base") + "---\n" + bindingYAML("audit", "base", "Audit") + "---\n# only a comment\n---\n" + "null\n"
	objs, errs := Parse("multi.yaml", []byte(multi), Limits{})
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if len(objs) != 2 || objs[0].Identity.String() != "ComplianceProfile/base" || objs[1].Identity.String() != "ComplianceBinding/audit" {
		t.Fatalf("objects: %+v", objs)
	}
	if objs[1].Document != 2 {
		t.Fatalf("document index = %d, want 2", objs[1].Document)
	}
	// Defaults are applied to the proposed value.
	if got := objs[0].Profile.Spec.Policies[0].Exceptions.Eligibility; got != v1alpha1.ExceptionsForbidden {
		t.Fatalf("eligibility = %q", got)
	}
	if a := objs[1].Binding.Spec.Assessment; a == nil || a.Interval != "24h" || a.Retention != "2160h" {
		t.Fatalf("assessment defaults: %+v", a)
	}
	if objs[1].Binding.Spec.NamespaceSelector == nil {
		t.Fatal("explicit {} selector lost")
	}

	for name, in := range map[string]string{
		"json":      `{"apiVersion":"compliance.erenius.io/v1alpha1","kind":"ComplianceBinding","metadata":{"name":"j"},"spec":{"profileRef":{"name":"p"},"namespaceSelector":{},"mode":"Deny"}}`,
		"json-tabs": "{\n\t\"apiVersion\": \"compliance.erenius.io/v1alpha1\",\n\t\"kind\": \"ComplianceBinding\",\n\t\"metadata\": {\"name\": \"j\"},\n\t\"spec\": {\"profileRef\": {\"name\": \"p\"}, \"namespaceSelector\": {}, \"mode\": \"Deny\"}\n}\n",
		"crlf":      strings.ReplaceAll(bindingYAML("c", "p", "Audit"), "\n", "\r\n"),
		"empty":     "",
		"comments":  "# nothing\n",
		"only-sep":  "---\n---\n",
	} {
		t.Run(name, func(t *testing.T) {
			objs, errs := Parse(name, []byte(in), Limits{})
			if len(errs) != 0 {
				t.Fatal(errs)
			}
			want := 1
			if name == "empty" || name == "comments" || name == "only-sep" {
				want = 0
			}
			if len(objs) != want {
				t.Fatalf("got %d objects, want %d", len(objs), want)
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	wrap := func(kind, meta, spec string) string {
		return "apiVersion: compliance.erenius.io/v1alpha1\nkind: " + kind + "\nmetadata:\n" + meta + "spec:\n" + spec
	}
	bindingSpec := func(extra string) string {
		return "  profileRef: {name: p}\n  mode: Audit\n" + extra
	}
	cases := []struct {
		name string
		in   string
		want Code
		sub  string
	}{
		{"namespace-kind", "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: x\n", CodeUnsupportedKind, "Namespace"},
		{"secret-kind", "apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\n", CodeUnsupportedKind, ""},
		{"exception-kind", "apiVersion: compliance.erenius.io/v1alpha1\nkind: ComplianceException\nmetadata:\n  name: x\n", CodeUnsupportedKind, ""},
		{"list-kind", "apiVersion: v1\nkind: List\nitems: []\n", CodeUnsupportedKind, ""},
		{"other-group-same-kind", "apiVersion: example.com/v1alpha1\nkind: ComplianceBinding\nmetadata:\n  name: x\n", CodeUnsupportedKind, ""},
		{"version-v1", "apiVersion: compliance.erenius.io/v1\nkind: ComplianceBinding\nmetadata:\n  name: x\n", CodeUnsupportedVersion, "v1alpha1"},
		{"no-group", "apiVersion: v1alpha1\nkind: ComplianceBinding\nmetadata:\n  name: x\n", CodeUnsupportedKind, ""},
		{"missing-kind", "apiVersion: compliance.erenius.io/v1alpha1\nmetadata:\n  name: x\n", CodeMissingType, ""},
		{"scalar-doc", "hello\n", CodeNotAnObject, ""},
		{"list-doc", "- a\n- b\n", CodeNotAnObject, ""},
		{"no-metadata", "apiVersion: compliance.erenius.io/v1alpha1\nkind: ComplianceBinding\nspec: {}\n", CodeInvalidMetadata, ""},
		{"generate-name", wrap("ComplianceBinding", "  generateName: x-\n", bindingSpec("  namespaceSelector: {}\n")), CodeInvalidMetadata, "generateName"},
		{"namespaced", wrap("ComplianceBinding", "  name: x\n  namespace: default\n", bindingSpec("  namespaceSelector: {}\n")), CodeInvalidMetadata, "cluster-scoped"},
		{"no-name", wrap("ComplianceBinding", "  labels: {a: b}\n", bindingSpec("  namespaceSelector: {}\n")), CodeInvalidName, ""},
		{"empty-name", wrap("ComplianceBinding", "  name: \"\"\n", bindingSpec("  namespaceSelector: {}\n")), CodeInvalidName, ""},
		{"bad-name", wrap("ComplianceBinding", "  name: Not_Valid\n", bindingSpec("  namespaceSelector: {}\n")), CodeInvalidName, ""},
		{"numeric-name", wrap("ComplianceBinding", "  name: 12\n", bindingSpec("  namespaceSelector: {}\n")), CodeInvalidName, ""},
		{"unknown-top-level", wrap("ComplianceBinding", "  name: x\n", bindingSpec("  namespaceSelector: {}\n")) + "extra: 1\n", CodeUnknownField, "extra"},
		{"unknown-spec-field", wrap("ComplianceBinding", "  name: x\n", bindingSpec("  namespaceSelector: {}\n  surprise: true\n")), CodeUnknownField, "surprise"},
		{"unknown-nested-field", wrap("ComplianceBinding", "  name: x\n", bindingSpec("  namespaceSelector: {matchLabels: {a: b}, matchFoo: 1}\n")), CodeUnknownField, "matchFoo"},
		{"missing-selector", wrap("ComplianceBinding", "  name: x\n", bindingSpec("")), CodeInvalidSpec, "select every namespace"},
		{"null-selector", wrap("ComplianceBinding", "  name: x\n", bindingSpec("  namespaceSelector: null\n")), CodeInvalidSpec, "required"},
		{"missing-mode", wrap("ComplianceBinding", "  name: x\n", "  profileRef: {name: p}\n  namespaceSelector: {}\n"), CodeInvalidSpec, "mode"},
		{"bad-mode", wrap("ComplianceBinding", "  name: x\n", "  profileRef: {name: p}\n  namespaceSelector: {}\n  mode: Enforce\n"), CodeInvalidSpec, "Audit or Deny"},
		{"in-without-values", wrap("ComplianceBinding", "  name: x\n", bindingSpec("  namespaceSelector: {matchExpressions: [{key: a, operator: In}]}\n")), CodeInvalidSpec, "In and NotIn"},
		{"exists-with-values", wrap("ComplianceBinding", "  name: x\n", bindingSpec("  namespaceSelector: {matchExpressions: [{key: a, operator: Exists, values: [b]}]}\n")), CodeInvalidSpec, "must not set values"},
		{"bad-operator", wrap("ComplianceBinding", "  name: x\n", bindingSpec("  namespaceSelector: {matchExpressions: [{key: a, operator: Gt, values: [b]}]}\n")), CodeInvalidSpec, "operator"},
		{"bad-label-key", wrap("ComplianceBinding", "  name: x\n", bindingSpec("  namespaceSelector: {matchLabels: {'not a key': b}}\n")), CodeInvalidSpec, "key"},
		{"bad-label-value", wrap("ComplianceBinding", "  name: x\n", bindingSpec("  namespaceSelector: {matchLabels: {a: '-b'}}\n")), CodeInvalidSpec, "value"},
		{"label-value-number", wrap("ComplianceBinding", "  name: x\n", bindingSpec("  namespaceSelector: {matchLabels: {a: 1}}\n")), CodeInvalidSpec, "not number"},
		{"empty-interval", wrap("ComplianceBinding", "  name: x\n", bindingSpec("  namespaceSelector: {}\n  assessment: {interval: ''}\n")), CodeInvalidSpec, "assessment.interval"},
		{"day-duration", wrap("ComplianceBinding", "  name: x\n", bindingSpec("  namespaceSelector: {}\n  assessment: {retention: 90d}\n")), CodeInvalidSpec, "days"},
		{"zero-duration", wrap("ComplianceBinding", "  name: x\n", bindingSpec("  namespaceSelector: {}\n  assessment: {interval: 0s}\n")), CodeInvalidSpec, "positive"},
		{"profile-no-policies", wrap("ComplianceProfile", "  name: x\n", "  bundle: {name: b, digest: "+digestA+"}\n  policies: []\n"), CodeInvalidSpec, "at least one"},
		{"profile-bad-digest", wrap("ComplianceProfile", "  name: x\n", "  bundle: {name: b, digest: sha256:ABC}\n  policies: [{name: a}]\n"), CodeInvalidSpec, "digest"},
		{"profile-dup-policy", wrap("ComplianceProfile", "  name: x\n", "  bundle: {name: b, digest: "+digestA+"}\n  policies: [{name: a}, {name: a}]\n"), CodeInvalidSpec, "duplicate policy"},
		{"profile-params-array", wrap("ComplianceProfile", "  name: x\n", "  bundle: {name: b, digest: "+digestA+"}\n  policies: [{name: a, parameters: [1]}]\n"), CodeInvalidSpec, "object"},
		{"selfservice-no-lifetime", wrap("ComplianceProfile", "  name: x\n", "  bundle: {name: b, digest: "+digestA+"}\n  policies: [{name: a, exceptions: {eligibility: SelfService}}]\n"), CodeInvalidSpec, "maxLifetime"},
		{"forbidden-with-lifetime", wrap("ComplianceProfile", "  name: x\n", "  bundle: {name: b, digest: "+digestA+"}\n  policies: [{name: a, exceptions: {maxLifetime: 1h}}]\n"), CodeInvalidSpec, "must not set maxLifetime"},
		{"empty-eligibility", wrap("ComplianceProfile", "  name: x\n", "  bundle: {name: b, digest: "+digestA+"}\n  policies: [{name: a, exceptions: {eligibility: ''}}]\n"), CodeInvalidSpec, "empty"},
		{"zero-lifetime", wrap("ComplianceProfile", "  name: x\n", "  bundle: {name: b, digest: "+digestA+"}\n  policies: [{name: a, exceptions: {eligibility: SelfService, maxLifetime: 0s}}]\n"), CodeInvalidSpec, "maxLifetime"},
		{"bad-lifetime", wrap("ComplianceProfile", "  name: x\n", "  bundle: {name: b, digest: "+digestA+"}\n  policies: [{name: a, exceptions: {eligibility: SelfService, maxLifetime: forever}}]\n"), CodeInvalidSpec, ""},
		{"duplicate-key-top", bindingYAML("x", "p", "Audit") + "kind: Other\n", CodeDuplicateKey, "kind"},
		{"duplicate-key-nested", wrap("ComplianceProfile", "  name: x\n", "  bundle: {name: b, digest: "+digestA+"}\n  policies: [{name: a, parameters: {k: 1, k: 2}}]\n"), CodeDuplicateKey, "k"},
		{"duplicate-key-json", `{"apiVersion":"v1","apiVersion":"v1","kind":"X"}`, CodeDuplicateKey, ""},
		{"alias", "a: &x 1\nb: *x\n", CodeAliasNotAllowed, ""},
		{"merge-key", "a: &x {k: v}\nb:\n  <<: *x\n", CodeAliasNotAllowed, ""},
		{"non-string-key", "1: a\n", CodeNonStringKey, ""},
		{"custom-tag", "apiVersion: !!binary aGk=\n", CodeUnsupportedTag, ""},
		{"inf-number", "apiVersion: compliance.erenius.io/v1alpha1\nkind: ComplianceProfile\nmetadata: {name: x}\nspec: {a: .inf}\n", CodeInvalidNumber, ""},
		{"syntax", "a: [1, 2\n", CodeSyntax, ""},
		{"tab-indent-yaml", "a:\n\tb: 1\n", CodeSyntax, ""},
		{"spec-missing", "apiVersion: compliance.erenius.io/v1alpha1\nkind: ComplianceBinding\nmetadata: {name: x}\n", CodeInvalidSpec, "spec"},
		{"spec-scalar", "apiVersion: compliance.erenius.io/v1alpha1\nkind: ComplianceBinding\nmetadata: {name: x}\nspec: 3\n", CodeInvalidSpec, ""},
		{"deep", "apiVersion: compliance.erenius.io/v1alpha1\nkind: ComplianceProfile\nmetadata: {name: x}\nspec: " + strings.Repeat("[", 200) + strings.Repeat("]", 200) + "\n", CodeTooDeep, ""},
		{"duplicate-identity", bindingYAML("x", "p", "Audit") + "---\n" + bindingYAML("x", "p", "Deny"), CodeDuplicateIdentity, "document 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			objs, errs := Parse("in.yaml", []byte(tc.in), Limits{})
			if len(errs) == 0 {
				t.Fatalf("accepted: %+v", objs)
			}
			found := false
			for _, e := range errs {
				if e.Code == tc.want && strings.Contains(e.Message+" "+e.Field, tc.sub) {
					found = true
				}
				if e.Source != "in.yaml" {
					t.Errorf("error without source: %+v", e)
				}
			}
			if !found {
				t.Fatalf("want code %s containing %q, got:\n%v", tc.want, tc.sub, errs)
			}
		})
	}
}

func TestParseValidThenInvalidKeepsAttribution(t *testing.T) {
	in := profileYAML("ok") + "---\n" + bindingYAML("bad", "ok", "Nope")
	_, errs := Parse("two.yaml", []byte(in), Limits{})
	if len(errs) != 1 || errs[0].Document != 2 || errs[0].Identity != "ComplianceBinding/bad" || errs[0].Field != "spec.mode" || errs[0].Line == 0 {
		t.Fatalf("errors = %+v", errs)
	}
}

func TestParseIgnoresExportedServerFields(t *testing.T) {
	in := `apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata:
  name: exported
  uid: 11111111-1111-1111-1111-111111111111
  resourceVersion: "42"
  generation: 7
  creationTimestamp: "2026-01-01T00:00:00Z"
  managedFields: [{manager: kubectl}]
  annotations: {x: z}
spec:
  profileRef: {name: p}
  namespaceSelector: {}
  mode: Audit
  enforcementEpoch: 9
status:
  observedGeneration: 7
  conditions: [{type: Resolved, status: "True"}]
  anything: [1, 2]
`
	objs, errs := Parse("export.yaml", []byte(in), Limits{})
	if len(errs) != 0 || len(objs) != 1 {
		t.Fatal(errs)
	}
	b := objs[0].Binding
	if b.UID != "" || b.Generation != 0 || b.ResourceVersion != "" || len(b.ManagedFields) != 0 || len(b.Annotations) != 0 {
		t.Fatalf("server metadata leaked: %+v", b.ObjectMeta)
	}
	if b.Spec.EnforcementEpoch != 0 || len(b.Status.Conditions) != 0 || b.Status.ObservedGeneration != 0 {
		t.Fatalf("server-owned fields leaked: epoch=%d status=%+v", b.Spec.EnforcementEpoch, b.Status)
	}
	want := []string{"metadata.annotations", "metadata.creationTimestamp", "metadata.generation", "metadata.managedFields", "metadata.resourceVersion", "metadata.uid", "spec.enforcementEpoch", "status"}
	if strings.Join(objs[0].Ignored, ",") != strings.Join(want, ",") {
		t.Fatalf("ignored = %v", objs[0].Ignored)
	}
}

func TestParseTooManyErrorsIsBounded(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 50; i++ {
		b.WriteString("---\napiVersion: v1\nkind: Secret\nmetadata: {name: s}\n")
	}
	_, errs := Parse("many.yaml", []byte(b.String()), Limits{MaxErrors: 5})
	if len(errs) != 6 || errs[5].Code != CodeTooManyErrors {
		t.Fatalf("errors: %v", codes(errs))
	}
}

func TestAliasBombIsRejectedWithoutExpansion(t *testing.T) {
	in := "a: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\nd: [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n"
	_, errs := Parse("bomb.yaml", []byte(in), Limits{})
	if len(errs) != 1 || errs[0].Code != CodeAliasNotAllowed {
		t.Fatalf("errors: %v", errs)
	}
}

func TestParseRejectsAmbiguousUnquotedScalars(t *testing.T) {
	for _, v := range []string{"y", "Y", "n", "yes", "Yes", "YES", "no", "No", "NO", "on", "On", "ON", "off", "OFF", "Off", "1:30", "12:00:00"} {
		doc := profileDoc("hard", "    - name: a\n      parameters: {k: "+v+"}\n")
		if _, errs := Parse("amb.yaml", []byte(doc), Limits{}); len(errs) != 1 || errs[0].Code != CodeAmbiguousScalar {
			t.Errorf("unquoted %s: %v", v, errs)
		}
		keyed := strings.Replace(doc, "{k: "+v+"}", "{"+v+": 1}", 1)
		if _, errs := Parse("amb.yaml", []byte(keyed), Limits{}); len(errs) != 1 || errs[0].Code != CodeAmbiguousScalar {
			t.Errorf("unquoted key %s: %v", v, errs)
		}
		for _, q := range []string{`"` + v + `"`, `'` + v + `'`} {
			quoted := strings.Replace(doc, "{k: "+v+"}", "{k: "+q+"}", 1)
			if _, errs := Parse("amb.yaml", []byte(quoted), Limits{}); len(errs) != 0 {
				t.Errorf("quoted %s: %v", q, errs)
			}
		}
	}
	// Ordinary strings that merely contain those words are fine.
	doc := profileDoc("hard", "    - name: a\n      parameters: {k: yes-please, m: nope, h: 10:00pm, id: 007}\n")
	if _, errs := Parse("ok.yaml", []byte(doc), Limits{}); len(errs) != 0 {
		t.Fatal(errs)
	}
}
