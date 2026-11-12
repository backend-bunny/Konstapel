package stack_test

// Applied content of assessment runs (add-policy-bundle-distribution 7.2):
// a run's content is the set of bundles its contributions were applied
// from, keyed by manifest digest, never the desired bundle in their place.
// The real binding, assessment and run reconcilers run over the signed
// revisions A, B (same key, tightened rules) and C (rotated key) served by
// the complete stack (verifier, acceptances, resolver, cache, OCIContent,
// Router), and every published package is opened and verified offline.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle/bundletest"
	"github.com/backend-bunny/Konstapel/internal/bundle/stack"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3store"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// rollout is a binding whose engine policy was applied from A and whose
// profile now pins next. With deliverNext the binding is reconciled again,
// so next's policy is delivered but not engine-ready and A's keeps
// enforcing beside it (overlapping revisions); otherwise next is desired
// but not yet delivered, and A's policy is the only one applied.
func rollout(t *testing.T, u *upgradeWorld, next v1alpha1.BundleReference, deliverNext bool) (rc *runCluster, pa, pn string) {
	t.Helper()
	rc = newRunCluster(t, u.router(), ref(u.a))
	rc.deliver()
	names := rc.policyNames()
	if len(names) != 1 {
		t.Fatalf("initial: %v", names)
	}
	pa = names[0]
	ready := func(o *unstructured.Unstructured) bool { return o.GetName() == pa }
	rc.ready.Store(&ready)
	p := &v1alpha1.ComplianceProfile{}
	rc.must(rc.c.Get(context.Background(), client.ObjectKey{Name: "org"}, p))
	p.Spec.Bundle = next
	p.Generation++
	rc.must(rc.c.Update(context.Background(), p))
	rc.ref = ref(u.a)
	if !deliverNext {
		return rc, pa, ""
	}
	rc.deliver()
	names = rc.policyNames()
	if len(names) != 2 || !slices.Contains(names, pa) {
		t.Fatalf("replacement: %v", names)
	}
	pn = names[0]
	if pn == pa {
		pn = names[1]
	}
	return rc, pa, pn
}

// requireContent fails unless the descriptor records exactly the applied
// bundles (all packaged), desired, and the derived differences.
func requireContent(t *testing.T, d publication.Descriptor, desired v1alpha1.BundleReference, applied ...v1alpha1.BundleReference) {
	t.Helper()
	rc := d.Revisions.Content
	if rc == nil || len(rc.Applied) != len(applied) || rc.Desired == nil || rc.Desired.Bundle != desired.Name || rc.Desired.ManifestDigest != desired.Digest || rc.Desired.Frozen {
		t.Fatalf("content %+v", rc)
	}
	var want []publication.ContentDifference
	if !slices.Contains(applied, desired) {
		want = append(want, publication.ContentDifference{Kind: publication.DesiredNotApplied, Bundle: desired.Name, ManifestDigest: desired.Digest})
	}
	applied = slices.Clone(applied)
	slices.SortFunc(applied, func(x, y v1alpha1.BundleReference) int { return strings.Compare(x.Digest, y.Digest) })
	for _, a := range applied {
		appliedRevision(t, d, a)
		if a != desired {
			want = append(want, publication.ContentDifference{Kind: publication.AppliedNotDesired, Bundle: a.Name, ManifestDigest: a.Digest})
		}
	}
	if !slices.Equal(rc.Differences, want) {
		t.Fatalf("differences %+v, want %+v", rc.Differences, want)
	}
}

// packagedPolicy reads the official policy packaged with bundle r.
func packagedPolicy(t *testing.T, dir string, r v1alpha1.BundleReference) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(publication.ContentPath(r.Digest)), bundletest.OfficialPolicy))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func packagedCapture(t *testing.T, dir string) collector.CaptureV2 {
	t.Helper()
	var c collector.CaptureV2
	raw, err := os.ReadFile(filepath.Join(dir, "capture.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// requireOnlyMembers fails unless the package carries content for exactly
// the given bundles.
func requireOnlyMembers(t *testing.T, dir string, refs ...v1alpha1.BundleReference) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, "bundles"))
	if err != nil {
		t.Fatal(err)
	}
	var got, want []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	for _, r := range refs {
		want = append(want, strings.TrimPrefix(r.Digest, "sha256:"))
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("packaged bundles %v, want %v", got, want)
	}
}

// An update A→B while A remains applied: the run packages and exports A's
// frozen content (the contributions it assesses were applied from A),
// records B as desired with the explicit difference, and attributes A's
// report to A's subject. The export is the same when the cache is evicted
// and the registry lost, or trust in A revoked, after the run started (and
// when the export is replayed after that change).
func TestOCIRunExportsAppliedWhileUpdateRollsOut(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(u *upgradeWorld, rc *runCluster){
		"unchanged": func(*upgradeWorld, *runCluster) {},
		"cache evicted and registry lost": func(u *upgradeWorld, rc *runCluster) {
			u.fetch.down.Store(true)
			u.coldRestart(rc.setRouter)
		},
		"trust revoked": func(u *upgradeWorld, _ *runCluster) {
			u.SetSources(u.source(upgradeRepo, "rotated", nil))
			u.Sync()
		},
	} {
		for _, replay := range []bool{false, true} {
			t.Run(name+"/replay="+map[bool]string{false: "false", true: "true"}[replay], func(t *testing.T) {
				t.Parallel()
				u := newUpgradeWorld(t)
				rc, pa, _ := rollout(t, u, ref(u.b), false)
				run := rc.start()
				rc.reportFor(runT0.Add(time.Minute), pa)
				if replay {
					rc.failNext.Store(true)
					rc.now = runT0.Add(6 * time.Minute)
					if err := rc.reconcile(rc.runs, run.Name); err == nil || !strings.Contains(err.Error(), "injected") {
						t.Fatalf("closure was not interrupted: %v", err)
					}
				}
				change(u, rc)
				if name != "unchanged" {
					if _, err := rc.assess.Content.Content(context.Background(), ref(u.a)); err == nil {
						t.Fatal("A is still resolvable; the change did not take effect")
					}
				}
				run = rc.finish(run.Name)
				dir, d := rc.pkg(run)
				f := requireBundleExport(t, dir, d, ref(u.a))
				if f.Identity.Receipt.Signer.KeyFingerprint != u.key.Fingerprint {
					t.Fatalf("frozen receipt %+v", f.Identity.Receipt)
				}
				requireContent(t, d, ref(u.b), ref(u.a))
				requireOnlyMembers(t, dir, ref(u.a))
				if bytes.Contains(packagedPolicy(t, dir, ref(u.a)), []byte(bundletest.TightenedMarker)) {
					t.Fatal("the packaged policy is B's, not the applied A's")
				}
				results, err := os.ReadFile(filepath.Join(dir, "assessment-results.json"))
				rc.must(err)
				if bytes.Contains(results, []byte(u.b.ManifestDigest)) {
					t.Fatal("the results attribute the run to the desired, not the applied, bundle")
				}
				// A's report is attributed to A's own subject; B's
				// undelivered policy is stale scope, not a substitute.
				c := packagedCapture(t, dir)
				if len(c.Subjects) != 1 || c.Subjects[0].EnginePolicy != pa || c.Subjects[0].BundleDigest != u.a.ManifestDigest ||
					!slices.ContainsFunc(c.Stale, func(s targeting.StaleScope) bool { return s.Reason == "EngineNotDelivered" }) {
					t.Fatalf("subjects %+v stale %+v", c.Subjects, c.Stale)
				}
				// The existing attribution rule holds: B's undelivered policy is a
				// stale scope of the binding while collection runs, so A's report is
				// recorded but not attributed across that configuration change.
				// The evidence is A's contribution, never B's.
				if d.Evidence.Expected != 1 || d.Evidence.StaleScopes != 1 || d.Evidence.Attributable != 0 || d.Evidence.Unresolved != 1 ||
					!bytes.Contains(mustReadFile(t, filepath.Join(dir, "capture.json")), []byte(`"detail": "stale: `)) {
					t.Fatalf("evidence %+v outcomes %+v", d.Evidence, d.Outcomes)
				}
			})
		}
	}
}

// Applied content that cannot be recovered and verified under the current
// trust contract makes the package export-unavailable (a ContentUnavailable
// diagnostic naming the applied bundle), even when the desired bundle is
// available: desired and vendored content are never substituted. Content
// restored before the window closes is frozen then.
func TestOCIRunAppliedContentUnavailable(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		next     func(u *upgradeWorld) v1alpha1.BundleReference
		break_   func(u *upgradeWorld, rc *runCluster)
		restore  func(u *upgradeWorld, rc *runCluster)
		detail   string
		resolves bool // the desired bundle resolves while A does not
	}{
		"evicted, registry lost at start and closure": {
			next:   func(u *upgradeWorld) v1alpha1.BundleReference { return ref(u.b) },
			break_: func(u *upgradeWorld, rc *runCluster) { u.fetch.down.Store(true); u.coldRestart(rc.setRouter) },
			detail: string(targeting.ContentErrorContentUnavailable),
		},
		"evicted, only A lost from the registry": {
			next: func(u *upgradeWorld) v1alpha1.BundleReference { return ref(u.b) },
			break_: func(u *upgradeWorld, rc *runCluster) {
				d := u.a.ManifestDigest
				u.fetch.lost.Store(&d)
				u.coldRestart(rc.setRouter)
			},
			detail: "could not be frozen", resolves: true,
		},
		"untrusted": {
			next: func(u *upgradeWorld) v1alpha1.BundleReference { return ref(u.c) },
			break_: func(u *upgradeWorld, _ *runCluster) {
				u.SetSources(u.source(upgradeRepo, "rotated", nil))
				u.Sync()
			},
			detail: string(targeting.ContentErrorUntrusted), resolves: true,
		},
		"restored before closure": {
			next:    func(u *upgradeWorld) v1alpha1.BundleReference { return ref(u.b) },
			break_:  func(u *upgradeWorld, rc *runCluster) { u.fetch.down.Store(true); u.coldRestart(rc.setRouter) },
			restore: func(u *upgradeWorld, _ *runCluster) { u.fetch.down.Store(false) },
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			u := newUpgradeWorld(t)
			next := tc.next(u)
			rc, pa, _ := rollout(t, u, next, false)
			tc.break_(u, rc)
			if _, err := rc.assess.Content.Content(context.Background(), ref(u.a)); err == nil {
				t.Fatal("A is still resolvable")
			}
			if _, err := rc.assess.Content.Content(context.Background(), next); (err == nil) != tc.resolves {
				t.Fatalf("desired resolves: %v", err)
			}
			run := rc.start()
			rc.reportFor(runT0.Add(time.Minute), pa)
			if tc.restore != nil {
				tc.restore(u, rc)
				run = rc.finish(run.Name)
				dir, d := rc.pkg(run)
				requireBundleExport(t, dir, d, ref(u.a))
				requireContent(t, d, next, ref(u.a))
				requireOnlyMembers(t, dir, ref(u.a))
				return
			}
			run = rc.finish(run.Name)
			d := requireDiagnostic(t, rc, run, collector.ReasonContentUnavailable, tc.detail)
			if !strings.Contains(d.Diagnostic.Message, u.a.ManifestDigest) || strings.Contains(d.Diagnostic.Message, next.Digest) {
				t.Fatalf("diagnostic %+v", d.Diagnostic)
			}
			rcont := d.Revisions.Content
			if len(rcont.Applied) != 1 || rcont.Desired == nil || rcont.Desired.ManifestDigest != next.Digest || rcont.Desired.Frozen {
				t.Fatalf("content %+v", rcont)
			}
			// The evidence still counts A's enforcing contribution.
			if d.Evidence.Expected != 1 || d.Evidence.Completeness == publication.NoTargets {
				t.Fatalf("evidence %+v", d.Evidence)
			}
		})
	}
}

// Overlapping old and new revisions in one run (A's policy enforcing while
// B's is delivered but not engine-ready) are never collapsed into one bundle
// identity: both are frozen and packaged, each contribution's observations
// are a result of its own bundle with its own content, and the run replays
// from both copies after the cache and registry are lost.
func TestOCIRunOverlappingRevisions(t *testing.T) {
	t.Parallel()
	u := newUpgradeWorld(t)
	rc, pa, pb := rollout(t, u, ref(u.b), true)
	run := rc.start()
	rc.reportFor(runT0.Add(time.Minute), pa, pb)
	rc.failNext.Store(true)
	rc.now = runT0.Add(6 * time.Minute)
	if err := rc.reconcile(rc.runs, run.Name); err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("closure was not interrupted: %v", err)
	}
	u.fetch.down.Store(true)
	u.coldRestart(rc.setRouter)
	run = rc.finish(run.Name)
	dir, d := rc.pkg(run)
	requireBundleExport(t, dir, d, ref(u.a))
	requireBundleExport(t, dir, d, ref(u.b))
	requireContent(t, d, ref(u.b), ref(u.a), ref(u.b))
	requireOnlyMembers(t, dir, ref(u.a), ref(u.b))
	if bytes.Contains(packagedPolicy(t, dir, ref(u.a)), []byte(bundletest.TightenedMarker)) ||
		!bytes.Contains(packagedPolicy(t, dir, ref(u.b)), []byte(bundletest.TightenedMarker)) {
		t.Fatal("a packaged bundle does not carry its own policy")
	}
	if d.Evidence.Expected != 2 || d.Evidence.Attributable != 2 || d.Outcomes.Fail != 2 {
		t.Fatalf("evidence %+v outcomes %+v", d.Evidence, d.Outcomes)
	}
	// One OSCAL result per bundle, each with the observation of the
	// contribution applied from it.
	var doc struct {
		AR struct {
			Results []struct {
				Props []struct{ Name, Value string } `json:"props"`
				Obs   []struct {
					Subjects []struct {
						Props []struct{ Name, Value string } `json:"props"`
					} `json:"subjects"`
				} `json:"observations"`
			} `json:"results"`
		} `json:"assessment-results"`
	}
	raw, err := os.ReadFile(filepath.Join(dir, "assessment-results.json"))
	rc.must(err)
	rc.must(json.Unmarshal(raw, &doc))
	got := map[string][]string{}
	for _, r := range doc.AR.Results {
		digest := ""
		for _, p := range r.Props {
			if p.Name == "bundle-digest" {
				digest = p.Value
			}
		}
		for _, o := range r.Obs {
			for _, s := range o.Subjects {
				for _, p := range s.Props {
					if p.Name == "engine-policy" {
						got[digest] = append(got[digest], p.Value)
					}
				}
			}
		}
	}
	if len(doc.AR.Results) != 2 || !slices.Equal(got[u.a.ManifestDigest], []string{pa}) || !slices.Equal(got[u.b.ManifestDigest], []string{pb}) {
		t.Fatalf("results by bundle %v (%d results)", got, len(doc.AR.Results))
	}
}

// Every frozen copy of a run's content set is checked before export: a lost
// or altered copy of either overlapping revision makes the package a
// ContentLost diagnostic, never an export of the other one.
func TestOCIRunTamperedAppliedCopy(t *testing.T) {
	t.Parallel()
	for _, which := range []string{"A", "B"} {
		for name, damage := range map[string]func(dir string) error{
			"removed": os.RemoveAll,
			"policy edited": func(dir string) error {
				p := filepath.Join(dir, bundletest.OfficialPolicy)
				b, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				return os.WriteFile(p, append(b, '\n'), 0o600)
			},
		} {
			t.Run(which+"/"+name, func(t *testing.T) {
				t.Parallel()
				u := newUpgradeWorld(t)
				rc, pa, pb := rollout(t, u, ref(u.b), true)
				run := rc.start()
				rc.reportFor(runT0.Add(time.Minute), pa, pb)
				target := ref(u.a)
				if which == "B" {
					target = ref(u.b)
				}
				rc.ref = target
				if err := damage(filepath.Join(rc.staging, string(run.UID), "frozen-bundles", strings.TrimPrefix(target.Digest, "sha256:"))); err != nil {
					t.Fatal(err)
				}
				run = rc.finish(run.Name)
				d := requireDiagnostic(t, rc, run, collector.ReasonContentLost, target.Digest)
				if len(d.Revisions.Content.Applied) != 2 {
					t.Fatalf("content %+v", d.Revisions.Content)
				}
			})
		}
	}
}

// vendoredRef is the image's vendored bundle.
func vendoredRef(t *testing.T) v1alpha1.BundleReference {
	t.Helper()
	sums, err := os.ReadFile(filepath.Join(stack.RepoRoot, "content", "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(sums)
	return v1alpha1.BundleReference{Name: stack.VendoredName, Digest: "sha256:" + hex.EncodeToString(h[:])}
}

// A run of the vendored content stages nothing and its package is the
// vendored package as before (no content record, no bundle directories).
// Moving the profile to an OCI bundle while the vendored policy is still
// the one applied exports from the vendored content and records the OCI
// bundle as desired; the OCI bundle's content is never packaged.
func TestRunVendoredAppliedContent(t *testing.T) {
	t.Parallel()
	t.Run("vendored", func(t *testing.T) {
		t.Parallel()
		w := newCraftedWorld(t)
		rc := newRunCluster(t, w.router(), vendoredRef(t))
		rc.deliver()
		run := rc.start()
		if _, err := os.Stat(filepath.Join(rc.staging, string(run.UID), "content.json")); !os.IsNotExist(err) {
			t.Fatalf("a vendored run staged a content record: %v", err)
		}
		rc.report(runT0.Add(time.Minute))
		run = rc.finish(run.Name)
		dir, d := rc.pkg(run)
		if d.PackageKind != publication.KindAssessment || d.Revisions.Content != nil || slices.Contains(d.Producer.Checks, "frozen-bundle-content") {
			t.Fatalf("vendored package changed: %s %+v %v", d.PackageKind, d.Revisions.Content, d.Producer.Checks)
		}
		if _, err := os.Stat(filepath.Join(dir, "bundles")); !os.IsNotExist(err) {
			t.Fatal("a vendored package carries bundle directories")
		}
	})
	t.Run("vendored applied, OCI desired", func(t *testing.T) {
		t.Parallel()
		w := newCraftedWorld(t)
		v := vendoredRef(t)
		rc := newRunCluster(t, w.router(), v)
		rc.deliver()
		p := &v1alpha1.ComplianceProfile{}
		rc.must(rc.c.Get(context.Background(), client.ObjectKey{Name: "org"}, p))
		p.Spec.Bundle = w.ref()
		p.Generation++
		rc.must(rc.c.Update(context.Background(), p))
		run := rc.start()
		rc.report(runT0.Add(time.Minute))
		run = rc.finish(run.Name)
		dir, d := rc.pkg(run)
		if d.PackageKind != publication.KindAssessment {
			t.Fatalf("%s %+v", d.PackageKind, d.Diagnostic)
		}
		requireContent(t, d, w.ref(), v)
		if a := appliedRevision(t, d, v); !a.Vendored {
			t.Fatalf("applied %+v", a)
		}
		requireOnlyMembers(t, dir, v)
		ssp, err := os.ReadFile(filepath.Join(dir, "system-security-plan.json"))
		rc.must(err)
		if !bytes.Contains(ssp, []byte(`"`+bundletest.VendoredStatement+`"`)) || bytes.Contains(ssp, []byte(`"`+bundletest.Statement+`"`)) {
			t.Fatal("the exported mapping is not the applied vendored content's")
		}
		if err := collector.VerifyPackage(dir); err != nil {
			t.Fatal(err)
		}
		if _, err := s3store.ValidatePackage(dir); err != nil {
			t.Fatal(err)
		}
		// The desired bundle's undelivered policy is stale scope (existing
		// attribution rule), so the vendored observation is unresolved.
		if d.Evidence.Expected != 1 || d.Evidence.StaleScopes != 1 || d.Evidence.Unresolved != 1 {
			t.Fatalf("evidence %+v outcomes %+v", d.Evidence, d.Outcomes)
		}
	})
}

func mustReadFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
