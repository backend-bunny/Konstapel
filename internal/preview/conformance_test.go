package preview

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/crdtest"
)

// The preview validates in Go, without a cluster, what the API server
// validates through the CRD schema and CEL rules. These tests pin the two
// together using the generated CRDs, so drift in either direction fails here.

type conformanceCase struct {
	name string
	doc  string
	// stricter: the preview deliberately rejects what the server would accept
	// by pruning or by loose format checks (never the reverse).
	stricter bool
}

const hdrP = "apiVersion: compliance.erenius.io/v1alpha1\nkind: ComplianceProfile\nmetadata: {name: p}\nspec:\n"
const hdrB = "apiVersion: compliance.erenius.io/v1alpha1\nkind: ComplianceBinding\nmetadata: {name: b}\nspec:\n"

func prof(bundle, policies string) string {
	return hdrP + "  bundle: " + bundle + "\n  policies: " + policies + "\n"
}

var goodBundle = "{name: hardening, digest: " + digestA + "}"

func bind(rest string) string { return hdrB + "  profileRef: {name: p}\n  mode: Audit\n" + rest }

func conformanceCases() []conformanceCase {
	manyPolicies := "[" + strings.TrimSuffix(strings.Repeat("{name: a}, ", 257), ", ") + "]"
	return []conformanceCase{
		{name: "profile-ok", doc: prof(goodBundle, "[{name: a}]")},
		{name: "profile-params-object", doc: prof(goodBundle, "[{name: a, parameters: {x: [1, {k: null}]}}]")},
		{name: "profile-params-null", doc: prof(goodBundle, "[{name: a, parameters: null}]")},
		{name: "profile-params-array", doc: prof(goodBundle, "[{name: a, parameters: [1]}]")},
		{name: "profile-params-string", doc: prof(goodBundle, "[{name: a, parameters: x}]")},
		{name: "profile-no-bundle", doc: hdrP + "  policies: [{name: a}]\n"},
		{name: "profile-bundle-name-upper", doc: prof("{name: Hard, digest: "+digestA+"}", "[{name: a}]")},
		{name: "profile-bundle-name-empty", doc: prof("{name: '', digest: "+digestA+"}", "[{name: a}]")},
		{name: "profile-digest-md5", doc: prof("{name: h, digest: md5:abc}", "[{name: a}]")},
		{name: "profile-digest-short", doc: prof("{name: h, digest: 'sha256:abc'}", "[{name: a}]")},
		{name: "profile-digest-upper", doc: prof("{name: h, digest: 'sha256:"+strings.Repeat("A", 64)+"'}", "[{name: a}]")},
		{name: "profile-digest-missing", doc: prof("{name: h}", "[{name: a}]")},
		{name: "profile-no-policies", doc: hdrP + "  bundle: " + goodBundle + "\n"},
		{name: "profile-empty-policies", doc: prof(goodBundle, "[]")},
		{name: "profile-256-policies", doc: prof(goodBundle, "["+strings.TrimSuffix(func() string {
			var b strings.Builder
			for i := 0; i < 256; i++ {
				b.WriteString("{name: p" + strings.Repeat("a", i%5) + string(rune('a'+i/26)) + string(rune('a'+i%26)) + "}, ")
			}
			return b.String()
		}(), ", ")+"]")},
		{name: "profile-257-policies", doc: prof(goodBundle, manyPolicies)},
		{name: "profile-dup-policy", doc: prof(goodBundle, "[{name: a}, {name: a}]")},
		{name: "profile-policy-upper", doc: prof(goodBundle, "[{name: A}]")},
		{name: "profile-policy-no-name", doc: prof(goodBundle, "[{parameters: {}}]")},
		{name: "exc-selfservice-ok", doc: prof(goodBundle, "[{name: a, exceptions: {eligibility: SelfService, maxLifetime: 720h}}]")},
		{name: "exc-selfservice-no-lifetime", doc: prof(goodBundle, "[{name: a, exceptions: {eligibility: SelfService}}]")},
		{name: "exc-selfservice-zero", doc: prof(goodBundle, "[{name: a, exceptions: {eligibility: SelfService, maxLifetime: 0s}}]")},
		{name: "exc-selfservice-negative", doc: prof(goodBundle, "[{name: a, exceptions: {eligibility: SelfService, maxLifetime: -1h}}]")},
		{name: "exc-forbidden-with-lifetime", doc: prof(goodBundle, "[{name: a, exceptions: {eligibility: Forbidden, maxLifetime: 1h}}]")},
		{name: "exc-default-with-lifetime", doc: prof(goodBundle, "[{name: a, exceptions: {maxLifetime: 1h}}]")},
		{name: "exc-empty", doc: prof(goodBundle, "[{name: a, exceptions: {}}]")},
		{name: "exc-null", doc: prof(goodBundle, "[{name: a, exceptions: null}]")},
		{name: "exc-bad-enum", doc: prof(goodBundle, "[{name: a, exceptions: {eligibility: Always}}]")},
		{name: "exc-explicit-empty-enum", doc: prof(goodBundle, "[{name: a, exceptions: {eligibility: ''}}]")},
		{name: "exc-lifetime-days-format", doc: prof(goodBundle, "[{name: a, exceptions: {eligibility: SelfService, maxLifetime: 1d}}]"), stricter: true},

		{name: "binding-all", doc: bind("  namespaceSelector: {}\n")},
		{name: "binding-missing-selector", doc: bind("")},
		{name: "binding-null-selector", doc: bind("  namespaceSelector: null\n")},
		{name: "binding-bad-mode", doc: strings.Replace(bind("  namespaceSelector: {}\n"), "Audit", "Warn", 1)},
		{name: "binding-no-mode", doc: hdrB + "  profileRef: {name: p}\n  namespaceSelector: {}\n"},
		{name: "binding-no-profile", doc: hdrB + "  mode: Deny\n  namespaceSelector: {}\n"},
		{name: "binding-empty-profile", doc: hdrB + "  profileRef: {name: ''}\n  mode: Deny\n  namespaceSelector: {}\n"},
		{name: "binding-labels", doc: bind("  namespaceSelector: {matchLabels: {env: prod, example.com/team: a-b}}\n")},
		{name: "binding-label-key-bad", doc: bind("  namespaceSelector: {matchLabels: {'a b': c}}\n")},
		{name: "binding-label-key-long-prefix", doc: bind("  namespaceSelector: {matchLabels: {'" + strings.Repeat("a", 260) + "/k': c}}\n")},
		{name: "binding-label-value-bad", doc: bind("  namespaceSelector: {matchLabels: {a: '-x'}}\n")},
		{name: "binding-label-value-long", doc: bind("  namespaceSelector: {matchLabels: {a: '" + strings.Repeat("x", 64) + "'}}\n")},
		{name: "binding-label-value-empty", doc: bind("  namespaceSelector: {matchLabels: {a: ''}}\n")},
		{name: "binding-in", doc: bind("  namespaceSelector: {matchExpressions: [{key: a, operator: In, values: [x, y]}]}\n")},
		{name: "binding-in-yaml11-bool-value", doc: bind("  namespaceSelector: {matchExpressions: [{key: a, operator: In, values: [x, y]}]}\n")},
		{name: "binding-in-quoted-y", doc: bind("  namespaceSelector: {matchExpressions: [{key: a, operator: In, values: [x, 'y', \"on\"]}]}\n")},
		{name: "profile-param-key-y", doc: prof(goodBundle, "[{name: a, parameters: {y: 1}}]"), stricter: true},
		{name: "profile-param-value-no", doc: prof(goodBundle, "[{name: a, parameters: {k: no}}]"), stricter: true},
		{name: "profile-param-sexagesimal", doc: prof(goodBundle, "[{name: a, parameters: {k: 1:30}}]"), stricter: true},
		{name: "binding-in-no-values", doc: bind("  namespaceSelector: {matchExpressions: [{key: a, operator: In}]}\n")},
		{name: "binding-in-empty-values", doc: bind("  namespaceSelector: {matchExpressions: [{key: a, operator: NotIn, values: []}]}\n")},
		{name: "binding-exists", doc: bind("  namespaceSelector: {matchExpressions: [{key: a, operator: Exists}]}\n")},
		{name: "binding-exists-values", doc: bind("  namespaceSelector: {matchExpressions: [{key: a, operator: DoesNotExist, values: [x]}]}\n")},
		{name: "binding-bad-operator", doc: bind("  namespaceSelector: {matchExpressions: [{key: a, operator: Equals, values: [x]}]}\n")},
		{name: "binding-expr-key-bad", doc: bind("  namespaceSelector: {matchExpressions: [{key: 'a b', operator: Exists}]}\n")},
		{name: "binding-expr-value-bad", doc: bind("  namespaceSelector: {matchExpressions: [{key: a, operator: In, values: ['-x']}]}\n")},
		{name: "binding-33-expressions", doc: bind("  namespaceSelector: {matchExpressions: [" + strings.TrimSuffix(strings.Repeat("{key: a, operator: Exists}, ", 33), ", ") + "]}\n")},
		{name: "binding-65-values", doc: bind("  namespaceSelector: {matchExpressions: [{key: a, operator: In, values: [" + strings.TrimSuffix(strings.Repeat("v, ", 65), ", ") + "]}]}\n")},
		{name: "assessment-ok", doc: bind("  namespaceSelector: {}\n  assessment: {interval: 12h, maxEvidenceAge: 30m, collectionTimeout: 90s, retention: 4320h}\n")},
		{name: "assessment-empty", doc: bind("  namespaceSelector: {}\n  assessment: {}\n")},
		{name: "assessment-null-fields", doc: bind("  namespaceSelector: {}\n  assessment: {interval: null, retention: null}\n")},
		{name: "assessment-days", doc: bind("  namespaceSelector: {}\n  assessment: {retention: 90d}\n")},
		{name: "assessment-zero", doc: bind("  namespaceSelector: {}\n  assessment: {interval: 0s}\n")},
		{name: "assessment-negative", doc: bind("  namespaceSelector: {}\n  assessment: {interval: -1h}\n")},
		{name: "assessment-empty-string", doc: bind("  namespaceSelector: {}\n  assessment: {interval: ''}\n")},
		{name: "assessment-cron", doc: bind("  namespaceSelector: {}\n  assessment: {interval: '*/5 * * * *'}\n")},
		{name: "assessment-compound", doc: bind("  namespaceSelector: {}\n  assessment: {interval: 1h30m}\n")},
		{name: "assessment-too-long", doc: bind("  namespaceSelector: {}\n  assessment: {interval: " + strings.Repeat("1h", 20) + "}\n")},
		{name: "assessment-dest", doc: bind("  namespaceSelector: {}\n  assessment: {destinationRef: {name: dest, uid: abc}}\n")},
		{name: "assessment-dest-no-uid", doc: bind("  namespaceSelector: {}\n  assessment: {destinationRef: {name: dest}}\n")},
		{name: "assessment-dest-bad-name", doc: bind("  namespaceSelector: {}\n  assessment: {destinationRef: {name: Dest, uid: abc}}\n")},
		{name: "assessment-dest-long-uid", doc: bind("  namespaceSelector: {}\n  assessment: {destinationRef: {name: d, uid: '" + strings.Repeat("u", 65) + "'}}\n")},
		{name: "binding-epoch-ignored", doc: bind("  namespaceSelector: {}\n  enforcementEpoch: 3\n")},
		{name: "binding-unknown-spec-field", doc: bind("  namespaceSelector: {}\n  surprise: 1\n"), stricter: true},
		{name: "profile-unknown-spec-field", doc: prof(goodBundle, "[{name: a, surprise: 1}]"), stricter: true},
	}
}

func TestPreviewValidationConformsToGeneratedCRDs(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	for _, tc := range conformanceCases() {
		t.Run(tc.name, func(t *testing.T) {
			var obj map[string]any
			if err := yaml.Unmarshal([]byte(tc.doc), &obj); err != nil {
				t.Fatal(err)
			}
			kind, _ := obj["kind"].(string)
			serverErrs := crds[kind].Validate(obj)
			objs, errs := Parse("case.yaml", []byte(tc.doc), Limits{})
			serverRejects, previewRejects := len(serverErrs) > 0, len(errs) > 0
			switch {
			case serverRejects && !previewRejects:
				t.Fatalf("API server rejects (%v) but the preview accepts", serverErrs.ToAggregate())
			case !serverRejects && previewRejects && !tc.stricter:
				t.Fatalf("API server accepts but the preview rejects: %v", errs)
			case !serverRejects && !previewRejects && tc.stricter:
				t.Fatal("case is marked stricter but both accept")
			case !serverRejects && !previewRejects:
				// Defaults: the server-defaulted object and the preview's
				// defaulted object have the same fingerprint.
				raw, _ := yaml.Marshal(obj)
				var fromServer string
				switch kind {
				case KindProfile:
					p := &v1alpha1.ComplianceProfile{}
					if err := yaml.UnmarshalStrict(raw, p); err != nil {
						t.Fatal(err)
					}
					fromServer = Fingerprint(p, nil)
				case KindBinding:
					b := &v1alpha1.ComplianceBinding{}
					if err := yaml.UnmarshalStrict(raw, b); err != nil {
						t.Fatal(err)
					}
					fromServer = Fingerprint(nil, b)
				}
				if fromServer != objs[0].Fingerprint {
					t.Fatalf("defaulting differs from the API server\nserver:  %s", raw)
				}
			}
		})
	}
}

func TestPreviewConformsOnTargetingExamples(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	for _, dir := range []string{"valid", "invalid"} {
		files, _ := filepath.Glob("../../testdata/targeting/examples/" + dir + "/*.yaml")
		if len(files) == 0 {
			t.Fatalf("no %s examples", dir)
		}
		for _, f := range files {
			t.Run(dir+"/"+filepath.Base(f), func(t *testing.T) {
				raw, err := os.ReadFile(f)
				if err != nil {
					t.Fatal(err)
				}
				_, errs := Parse(f, raw, Limits{})
				var obj map[string]any
				if err := yaml.Unmarshal(raw, &obj); err != nil {
					t.Fatal(err)
				}
				serverRejects := len(crds[obj["kind"].(string)].Validate(obj)) > 0
				if dir == "valid" && (len(errs) > 0 || serverRejects) {
					t.Fatalf("valid example rejected: preview=%v server=%v", errs, serverRejects)
				}
				if dir == "invalid" && len(errs) == 0 {
					t.Fatal("invalid example accepted by the preview")
				}
			})
		}
	}
}
