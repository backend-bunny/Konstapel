package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/bundletest"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// Provider captures and the run's content set (task 3.2).

// roles stands in for the registry's content roles: contracts mapped to
// whether all their check kinds are reporting-only.
type roles map[string]bool

func (r roles) ReportingOnly(contract string) (bool, error) {
	v, ok := r[contract]
	if !ok {
		return false, fmt.Errorf("provider %q is not installed", contract)
	}
	return v, nil
}

const delivering = "example-delivery/v1"

var installedRoles = roles{LegacyProvider: false, posture: true, delivering: false}

func requireContentFailure(t *testing.T, err error, reason string) *ContentFailure {
	t.Helper()
	var cf *ContentFailure
	if !errors.As(err, &cf) || cf.Reason != reason {
		t.Fatalf("want %s, got %v", reason, err)
	}
	return cf
}

func ref(name, digest string) v1alpha1.BundleReference {
	return v1alpha1.BundleReference{Name: name, Digest: digest}
}

func digestOf(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

// Through the capture boundary, the Kyverno payload 2 names its applied
// content, legacy or envelope alike; a reporting-only provider's capture
// uses the run's frozen selection; everything else is refused, never read
// as using desired or vendored content.
func TestCaptureContentUseByProvider(t *testing.T) {
	raw := fixture(t, v2Fixture)
	var c CaptureV2
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	want := KyvernoContentUse(c)
	if want.Role != ContentApplied || len(want.References) != len(c.Subjects)+len(c.Contributions) || len(want.Bundles()) != 1 {
		t.Fatalf("Kyverno use %+v", want.Bundles())
	}
	for name, doc := range map[string][]byte{"legacy": raw, "envelope": envelope(t, LegacyProvider, 2, 1, raw)} {
		d, err := ReadCapture(doc, installedReaders)
		if err != nil {
			t.Fatal(err)
		}
		got, err := d.ContentUse(installedRoles)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: %+v %v", name, got, err)
		}
	}
	// A reporting-only provider names no applied content.
	d, err := ReadCapture(envelope(t, posture, 1, 1, []byte(`{"payloadVersion":1}`)), installedReaders)
	if err != nil {
		t.Fatal(err)
	}
	if u, err := d.ContentUse(installedRoles); err != nil || u.Role != ContentSelected || len(u.References) != 0 || len(u.Bundles()) != 0 {
		t.Fatalf("reporting-only use %+v %v", u, err)
	}
	refused := map[string]struct {
		doc   CaptureDocument
		roles ContentRoles
	}{
		"prototype capture":         {CaptureDocument{Header: CaptureHeader{Version: 1, Provider: LegacyProvider, PayloadVersion: 1, EvaluatorVersion: 1}, Payload: fixture(t, prototypeFixture)}, installedRoles},
		"delivering other provider": {CaptureDocument{Header: CaptureHeader{Version: 3, Provider: delivering, PayloadVersion: 1, EvaluatorVersion: 1}, Payload: []byte(`{}`)}, installedRoles},
		"uninstalled provider":      {CaptureDocument{Header: CaptureHeader{Version: 3, Provider: "gone/v1", PayloadVersion: 1, EvaluatorVersion: 1}, Payload: []byte(`{}`)}, installedRoles},
		"no installed providers":    {d, nil},
		"unread envelope":           {CaptureDocument{Header: CaptureHeader{Version: 3, Provider: LegacyProvider, PayloadVersion: 2, EvaluatorVersion: 1}, Payload: raw}, installedRoles},
	}
	for name, tc := range refused {
		if u, err := tc.doc.ContentUse(tc.roles); !errors.Is(err, ErrUnsupportedCapture) {
			t.Errorf("%s: want unsupported, got %+v %v", name, u, err)
		}
	}
}

// An enforcing contribution still applied from A while the profile desires
// B resolves to A alone; B stays desired intent and never stands in.
func TestResolveAppliedAVersusDesiredB(t *testing.T) {
	a, b := ref("org", digestOf('a')), ref("org", digestOf('b'))
	rc := &RunContent{Desired: &b, Members: []ContentMember{{Ref: a, Applied: true, Root: "/frozen/a"}}}
	use := ContentUse{Role: ContentApplied, References: []ContentReference{{Ref: a, By: "subject p"}}}
	got, err := rc.Resolve(use)
	if err != nil || len(got) != 1 || got[0].Ref != a || got[0].Root != "/frozen/a" {
		t.Fatalf("%+v %v", got, err)
	}
	// A capture naming the desired bundle, which the run did not freeze as
	// applied, is a mismatch.
	_, err = rc.Resolve(ContentUse{Role: ContentApplied, References: []ContentReference{{Ref: b, By: "subject p"}}})
	cf := requireContentFailure(t, err, ReasonContentMismatch)
	if !strings.Contains(cf.Message, "subject p references org@"+b.Digest) {
		t.Fatal(cf.Message)
	}
	// So is a frozen applied bundle the capture does not assess.
	_, err = rc.Resolve(ContentUse{Role: ContentApplied, References: []ContentReference{}})
	requireContentFailure(t, err, ReasonContentMismatch)
	// Nothing applied: the desired member the plan names is the content.
	plan := &RunContent{Desired: &b, Members: []ContentMember{{Ref: b, Root: "/frozen/b"}}}
	if got, err := plan.Resolve(ContentUse{Role: ContentApplied}); err != nil || len(got) != 1 || got[0].Ref != b {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := (&RunContent{Desired: &b}).Resolve(ContentUse{Role: ContentApplied}); err == nil {
		t.Fatal("an empty content set resolved")
	}
}

// Overlapping applied revisions keep their own members. Resolution identity
// is the bundle name and digest: another name of a frozen digest is not
// that bundle.
func TestResolveOverlappingAppliedRevisions(t *testing.T) {
	v1, v2 := ref("org", digestOf('1')), ref("org", digestOf('2'))
	rc := &RunContent{Desired: &v2, Members: []ContentMember{{Ref: v1, Applied: true, Root: "/1"}, {Ref: v2, Applied: true, Root: "/2"}}}
	use := ContentUse{Role: ContentApplied, References: []ContentReference{{Ref: v1, By: "subject old"}, {Ref: v2, By: "subject new"}, {Ref: v2, By: "contribution new"}}}
	got, err := rc.Resolve(use)
	if err != nil || len(got) != 2 || got[0].Root != "/1" || got[1].Root != "/2" {
		t.Fatalf("%+v %v", got, err)
	}
	if b := use.Bundles(); !slices.Equal(b, []v1alpha1.BundleReference{v1, v2}) {
		t.Fatalf("bundles %v", b)
	}
	alias := ContentUse{Role: ContentApplied, References: []ContentReference{{Ref: v1, By: "subject old"}, {Ref: ref("other", v2.Digest), By: "subject new"}}}
	requireContentFailure(t, func() error { _, err := rc.Resolve(alias); return err }(), ReasonContentMismatch)
	if b := alias.Bundles(); len(b) != 2 || b[1].Name != "other" {
		t.Fatalf("bundles %v", b)
	}
}

// A reporting-only capture is evaluated from the run's frozen selection
// alone: the bundle recorded when the run started. Applied content is never
// read as a selection and no selection is invented; the package records the
// selection as desired, frozen, with no applied identity.
func TestResolveReportingOnlySelection(t *testing.T) {
	dir, f := craftedFrozen(t, bundletest.Options{})
	s := ref(f.Identity.Name, f.Identity.Digests.OCI)
	sel := ContentUse{Role: ContentSelected, References: []ContentReference{}}
	rc := &RunContent{Desired: &s, Members: []ContentMember{frozenMember(dir, f, false)}}
	got, err := rc.Resolve(sel)
	if err != nil || len(got) != 1 || got[0].Root != dir || got[0].Applied {
		t.Fatalf("%+v %v", got, err)
	}
	set, err := memberContent(*got[0], repo(t))
	if err != nil || len(set.Definitions) == 0 {
		t.Fatalf("%+v %v", set, err)
	}
	rec := contentRevision(ExportRequest{Content: rc}, publication.KindAssessment)
	if len(rec.Applied) != 0 || rec.Desired == nil || !rec.Desired.Frozen || rec.Desired.ManifestDigest != s.Digest ||
		!slices.Equal(rec.Differences, []publication.ContentDifference{{Kind: publication.DesiredNotApplied, Bundle: s.Name, ManifestDigest: s.Digest}}) {
		t.Fatalf("record %+v", rec)
	}

	t.Run("binding changes after the freeze", func(t *testing.T) {
		// The record is the start's: a later selection T is a new run's.
		// The frozen copy is read, not the cache or the new selection.
		changed := *rc
		got, err := changed.Resolve(sel)
		if err != nil || got[0].Ref != s || got[0].Frozen.Identity.Digests.OCI != s.Digest {
			t.Fatalf("%+v %v", got, err)
		}
	})
	mismatches := map[string]*RunContent{
		"applied content":           {Desired: &s, Members: []ContentMember{frozenMember(dir, f, true)}},
		"no selection":              {Desired: &s, Members: []ContentMember{}},
		"selection not recorded":    {Members: []ContentMember{frozenMember(dir, f, false)}},
		"another selection":         {Desired: &v1alpha1.BundleReference{Name: s.Name, Digest: digestOf('t')}, Members: []ContentMember{frozenMember(dir, f, false)}},
		"same digest, another name": {Desired: &v1alpha1.BundleReference{Name: "other", Digest: s.Digest}, Members: []ContentMember{frozenMember(dir, f, false)}},
		"two selections": {Desired: &s, Members: []ContentMember{frozenMember(dir, f, false),
			{Ref: ref(s.Name, digestOf('t')), Root: dir, Frozen: f}}},
	}
	for name, m := range mismatches {
		if _, err := m.Resolve(sel); err == nil {
			t.Errorf("%s: resolved", name)
		} else {
			requireContentFailure(t, err, ReasonContentMismatch)
		}
	}
	if _, err := rc.Resolve(ContentUse{Role: ContentSelected, References: []ContentReference{{Ref: s, By: "subject p"}}}); err == nil {
		t.Fatal("a reporting-only use with applied references resolved")
	}
	if _, err := rc.Resolve(ContentUse{Role: "Other"}); err == nil {
		t.Fatal("an unknown role resolved")
	}
}

// Unavailable or lost content is returned as its failure for either role;
// no other content is substituted.
func TestResolveUnavailableContent(t *testing.T) {
	s := ref("org", digestOf('s'))
	unavailable := &ContentFailure{Reason: ReasonContentUnavailable, Message: "org could not be frozen for this run"}
	for name, use := range map[string]ContentUse{
		"selected": {Role: ContentSelected},
		"applied":  {Role: ContentApplied, References: []ContentReference{{Ref: s, By: "subject p"}}},
	} {
		rc := &RunContent{Desired: &s, DesiredVendored: false, Members: []ContentMember{{Ref: s, Applied: use.Role == ContentApplied, Failure: unavailable}}}
		got, err := rc.Resolve(use)
		if cf := requireContentFailure(t, err, ReasonContentUnavailable); got != nil || cf.Message != unavailable.Message {
			t.Fatalf("%s: %+v %v", name, got, err)
		}
		lost := &RunContent{Failure: &ContentFailure{Reason: ReasonContentLost, Message: "unreadable record"}}
		requireContentFailure(t, func() error { _, err := lost.Resolve(use); return err }(), ReasonContentLost)
	}
}

// A retained package replays from its own content after the cache and the
// run's frozen copy are gone: PackageContent reads exactly the packaged
// members, the retained capture resolves to them through the boundary, and
// re-exporting from them yields the bundle's OSCAL and the same content
// record. A missing or renamed member is ContentLost, never re-resolved or
// replaced with vendored content.
func TestPackageContentReplaysAfterEviction(t *testing.T) {
	dir, f := craftedFrozen(t, bundletest.Options{})
	c := ociCapture(t, f.Identity.Name, f.Identity.Digests.OCI)
	c.Reports = reportsAt(c, c.Window.Started.Add(time.Minute), failProd)
	req, d := ociExport(t, c, dir, f)
	if d.PackageKind != publication.KindAssessment {
		t.Fatalf("%s %+v", d.PackageKind, d.Diagnostic)
	}
	want, err := FrozenContentSet(f)
	if err != nil {
		t.Fatal(err)
	}
	// Evict: the run's frozen copy (and with it any cache) is gone.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	rc, err := PackageContent(req.Out, d)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ReadCapture(mustRead(t, filepath.Join(req.Out, "capture.json")), installedReaders)
	if err != nil {
		t.Fatal(err)
	}
	use, err := doc.ContentUse(installedRoles)
	if err != nil {
		t.Fatal(err)
	}
	members, err := rc.Resolve(use)
	if err != nil || len(members) != 1 {
		t.Fatalf("%+v %v", members, err)
	}
	m := members[0]
	if m.Root != filepath.Join(req.Out, publication.ContentPath(f.Identity.Digests.OCI)) || m.Vendored || !reflect.DeepEqual(m.Frozen.Identity, f.Identity) {
		t.Fatalf("replay member %+v", m)
	}
	if got, err := memberContent(*m, repo(t)); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("replay content %+v %v", got, err)
	}
	retained, err := doc.V2()
	if err != nil {
		t.Fatal(err)
	}
	again := exportReq(t, retained, evaluate(t, retained, nil, maxAge), repo(t))
	again.Content, again.TrustedRoot = rc, repo(t)
	d2, err := Export(context.Background(), again)
	if err != nil || d2.PackageKind != publication.KindAssessment {
		t.Fatalf("%v %+v", err, d2.Diagnostic)
	}
	requireCraftedOSCAL(t, again.Out, f)
	if !sameJSON(t, d2.Revisions.Content, d.Revisions.Content) || d2.Evidence != d.Evidence || d2.Outcomes != d.Outcomes {
		t.Fatalf("replay differs: %+v / %+v", d2.Revisions.Content, d.Revisions.Content)
	}

	// The vendored run has no content record: its content is its own tree.
	if rc, err := PackageContent(req.Out, publication.Descriptor{}); rc != nil || err != nil {
		t.Fatalf("%+v %v", rc, err)
	}
	// Another name for the packaged digest is not the packaged bundle.
	renamed := d
	rec := *d.Revisions.Content
	rec.Applied = slices.Clone(rec.Applied)
	rec.Applied[0].Bundle = "other"
	renamed.Revisions.Content = &rec
	_, err = PackageContent(req.Out, renamed)
	requireContentFailure(t, err, ReasonContentLost)
	// A lost member is never replaced with the vendored content.
	if err := os.RemoveAll(filepath.Join(req.Out, bundlesDir)); err != nil {
		t.Fatal(err)
	}
	_, err = PackageContent(req.Out, d)
	requireContentFailure(t, err, ReasonContentLost)
}

// A package whose applied content is the vendored member replays from the
// copy it packaged, not from this image's content root; a diagnostic
// package's unpackaged content is unavailable.
func TestPackageContentVendoredAndUnpackaged(t *testing.T) {
	c := freshCapture(t)
	c.Reports = reportsAt(c, c.Window.Started.Add(time.Minute), failProd)
	vendored := ref(c.Subjects[0].BundleName, c.Subjects[0].BundleDigest)
	desired := ref("org-bundle", digestOf('d'))
	req, d := contentExport(t, c, &RunContent{Desired: &desired, Members: []ContentMember{{Ref: vendored, Applied: true, Vendored: true, Root: repo(t)}}})
	rc, err := PackageContent(req.Out, d)
	if err != nil {
		t.Fatal(err)
	}
	members, err := rc.Resolve(KyvernoContentUse(c))
	if err != nil || len(members) != 1 {
		t.Fatalf("%+v %v", members, err)
	}
	if m := members[0]; !m.Vendored || m.Root != filepath.Join(req.Out, publication.ContentPath(vendored.Digest)) || *rc.Desired != desired || rc.DesiredVendored {
		t.Fatalf("member %+v desired %+v", m, rc.Desired)
	}
	if _, err := os.Stat(filepath.Join(members[0].Root, "content", "SHA256SUMS")); err != nil {
		t.Fatal(err)
	}

	// A Diagnostic package carries no content: its record says so and
	// replay reports it unavailable.
	diag := &RunContent{Desired: &desired, Members: []ContentMember{{Ref: desired, Failure: &ContentFailure{Reason: ReasonContentUnavailable, Message: "not resolvable"}}}}
	c2 := freshCapture(t)
	c2.Subjects, c2.Contributions, c2.EnginePolicies, c2.Checks = nil, nil, nil, []Check{}
	c2.Workloads, c2.Expected = []Workload{}, []Expected{}
	req2, d2 := contentExport(t, c2, diag)
	if d2.PackageKind != publication.KindDiagnostic {
		t.Fatalf("%s", d2.PackageKind)
	}
	rc2, err := PackageContent(req2.Out, d2)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rc2.Resolve(KyvernoContentUse(c2))
	requireContentFailure(t, err, ReasonContentUnavailable)
	if _, err := os.Stat(filepath.Join(req2.Out, bundle.FrozenDir)); !os.IsNotExist(err) {
		t.Fatal("diagnostic package carries content")
	}
}
