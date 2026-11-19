package preview

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var knownCodes = map[Code]bool{
	CodeNoProposedInput: true, CodeStdinTwice: true, CodeReadFailed: true, CodeInputTooLarge: true, CodeSyntax: true,
	CodeTooDeep: true, CodeAliasNotAllowed: true, CodeUnsupportedTag: true, CodeNonStringKey: true, CodeAmbiguousScalar: true, CodeInvalidNumber: true,
	CodeDuplicateKey: true, CodeNotAnObject: true, CodeMissingType: true, CodeUnsupportedKind: true, CodeUnsupportedVersion: true,
	CodeInvalidMetadata: true, CodeInvalidName: true, CodeUnknownField: true, CodeInvalidSpec: true, CodeDuplicateIdentity: true,
	CodeDuplicateLive: true, CodeProfileRemoved: true, CodeProfileNotFound: true, CodeTooManyErrors: true,
}

// FuzzParse feeds arbitrary bytes to the parser: it must never panic, be
// deterministic, report only known codes with a source, and every object it
// does return must be valid, defaulted, free of server identity, and carry a
// fingerprint that is stable under re-fingerprinting.
func FuzzParse(f *testing.F) {
	seeds := []string{
		"", "---\n", "null", "{}", "[]", "a: &x 1\nb: *x\n", "<<: {a: 1}", "\t{", "{\"a\":1,\"a\":2}",
		profileYAML("seed"), bindingYAML("seed", "p", "Deny"), profileYAML("a") + "---\n" + bindingYAML("b", "a", "Audit"),
		"apiVersion: v1\nkind: Secret\nmetadata: {name: s}\ndata: {k: dg==}\n",
		strings.Repeat("[", 5000), strings.Repeat("a: {", 300),
		bindingYAML("e", "p", "Audit") + "status: {x: .inf}\n",
	}
	for _, g := range []string{"valid", "invalid"} {
		files, _ := filepath.Glob("../../testdata/targeting/examples/" + g + "/*.yaml")
		for _, file := range files {
			if b, err := os.ReadFile(file); err == nil {
				seeds = append(seeds, string(b))
			}
		}
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		objs, errs := Parse("fuzz", data, Limits{})
		objs2, errs2 := Parse("fuzz", data, Limits{})
		if len(objs) != len(objs2) || !reflect.DeepEqual(errs, errs2) {
			t.Fatal("parse is not deterministic")
		}
		for _, e := range errs {
			if !knownCodes[e.Code] || e.Source != "fuzz" || e.Message == "" {
				t.Fatalf("bad error %+v", e)
			}
		}
		seen := map[Identity]bool{}
		for i, o := range objs {
			if seen[o.Identity] || o.Identity.Name == "" {
				t.Fatalf("duplicate or unnamed identity %+v", o.Identity)
			}
			seen[o.Identity] = true
			if o.Fingerprint != objs2[i].Fingerprint || o.Fingerprint != Fingerprint(o.Profile, o.Binding) || !digestPattern.MatchString(o.Fingerprint) {
				t.Fatalf("fingerprint of %s", o.Identity)
			}
			switch {
			case o.Profile != nil:
				if p := ValidateProfileSpec(&o.Profile.Spec); len(p) > 0 || o.Profile.UID != "" || o.Profile.Generation != 0 {
					t.Fatalf("returned profile invalid or decorated: %v", p)
				}
			case o.Binding != nil:
				if p := ValidateBindingSpec(&o.Binding.Spec); len(p) > 0 || o.Binding.UID != "" || o.Binding.Spec.EnforcementEpoch != 0 || o.Binding.Spec.NamespaceSelector == nil {
					t.Fatalf("returned binding invalid or decorated: %v", p)
				}
			default:
				t.Fatal("object without a typed value")
			}
		}
	})
}
