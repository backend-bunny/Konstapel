package s3store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/publication"
)

// boundedRetention is the retention of a signing-recovery commit: the run's
// recorded duration, bounded by the expiry recorded at the signing failure.
func boundedRetention(d string, notAfter time.Time) publication.Retention {
	r := retention(d)
	r.NotAfter = &notAfter
	return r
}

// signedStage stages the test package and stores a signature under signer.
func signedStage(t *testing.T, p *Publisher) (publication.Staged, *publication.Signing) {
	t.Helper()
	ctx := context.Background()
	s, err := p.Stage(ctx, publication.StageRequest{Run: testRun, Dir: fullPackage(t)})
	if err != nil {
		t.Fatal(err)
	}
	signer := testSigner(t)
	if _, _, err := p.StoreSignature(ctx, testRun, signStaged(t, signer, s)); err != nil {
		t.Fatal(err)
	}
	return s, requiredBy(signer)
}

// add-evidence-signing-recovery 2.1: a recovered commit records
// retention.notAfter, its receipt expires at notAfter (not publishedAt +
// retention), retries converge on it, and at the bound it is expired, never
// served, and deleted by retention.
func TestRecoveredCommitKeepsRecordedExpiry(t *testing.T) {
	clock := time.Now()
	f := newFake()
	p := newPublisher(t, f, func() time.Time { return clock })
	ctx := context.Background()
	s, sg := signedStage(t, p)
	notAfter := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	req := publication.PublishRequest{Staged: s, Retention: boundedRetention("2160h", notAfter), Signing: sg}
	r, err := p.Publish(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if !r.ExpiresAt.Equal(notAfter) || r.Retention.NotAfter == nil || !r.Retention.NotAfter.Equal(notAfter) || r.Signature == nil ||
		!r.PublishedAt.Before(notAfter) || r.Validate() != nil {
		t.Fatalf("recovered receipt: published %s expires %s retention %+v", r.PublishedAt, r.ExpiresAt, r.Retention)
	}
	raw, err := p.read(ctx, r.Commit.ManifestKey, "")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Kind      string `json:"kind"`
		Retention struct {
			NotAfter time.Time `json:"notAfter"`
		} `json:"retention"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Kind != kindSignedCommit || !doc.Retention.NotAfter.Equal(notAfter) {
		t.Fatalf("commit document: %s", raw)
	}
	again, err := (&Publisher{Client: p.Client, Dest: p.Dest, Now: p.Now}).Publish(ctx, req)
	if err != nil || !reflect.DeepEqual(again, r) {
		t.Fatalf("retry on another leader: %v", err)
	}
	if st, err := p.Inspect(ctx, testRun); err != nil || st.Phase != publication.PhaseCommitted || !st.ExpiresAt.Equal(notAfter) || st.Validate() != nil {
		t.Fatalf("inspect before the bound: %+v %v", st, err)
	}
	if _, err := p.Delete(ctx, testRun); !errors.Is(err, publication.ErrRetentionActive) {
		t.Fatalf("delete before the bound: %v", err)
	}
	clock = notAfter
	if st, err := p.Inspect(ctx, testRun); err != nil || st.Phase != publication.PhaseExpired || st.Availability != publication.AvailabilityExpired {
		t.Fatalf("inspect at the bound: %+v %v", st, err)
	}
	if _, _, err := p.Open(ctx, testRun); !errors.Is(err, publication.ErrExpired) {
		t.Fatalf("open at the bound: %v", err)
	}
	if cl, err := p.Delete(ctx, testRun); err != nil || cl.State != publication.CleanupDeleted {
		t.Fatalf("retention deletion at the bound: %+v %v", cl, err)
	}
}

// A commit whose server time is at or after notAfter (the storage clock is
// ahead of the controller's) is expired at once: never served and deleted
// by retention, whatever the reader's clock says.
func TestCommitLandingAfterNotAfterIsExpired(t *testing.T) {
	f := newFake()
	f.skew = 2 * time.Minute
	p := newPublisher(t, f, time.Now)
	ctx := context.Background()
	s, sg := signedStage(t, p)
	notAfter := time.Now().Add(time.Minute).UTC().Truncate(time.Second)
	r, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: boundedRetention("2160h", notAfter), Signing: sg})
	if err != nil {
		t.Fatal(err)
	}
	if r.PublishedAt.Before(notAfter) || !r.ExpiresAt.Equal(notAfter) || !r.ExpiredAt(time.Now()) || r.Validate() != nil {
		t.Fatalf("late receipt: published %s expires %s", r.PublishedAt, r.ExpiresAt)
	}
	if st, err := p.Inspect(ctx, testRun); err != nil || st.Phase != publication.PhaseExpired || st.Availability != publication.AvailabilityExpired {
		t.Fatalf("late commit inspect: %+v %v", st, err)
	}
	if _, _, err := p.Open(ctx, testRun); !errors.Is(err, publication.ErrExpired) {
		t.Fatalf("late commit served: %v", err)
	}
	if cl, err := p.Delete(ctx, testRun); err != nil || cl.State != publication.CleanupDeleted {
		t.Fatalf("late commit not deleted by retention: %+v %v", cl, err)
	}
}

// The publisher never commits a bound that cannot hold: on an unsigned
// commit, once the controller clock reached it, or after the full
// retention. Nothing is written.
func TestNotAfterGuardsWriteNothing(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	for name, c := range map[string]struct {
		notAfter time.Time
		unsigned bool
		want     error
	}{
		"unsigned":         {notAfter: now.Add(time.Hour), unsigned: true, want: publication.ErrUnsupportedRecord},
		"reached":          {notAfter: now, want: publication.ErrExpired},
		"passed":           {notAfter: now.Add(-time.Hour), want: publication.ErrExpired},
		"extends":          {notAfter: now.Add(2161 * time.Hour)},
		"zero (malformed)": {notAfter: time.Time{}, want: publication.ErrUnsupportedRecord},
	} {
		f := newFake()
		p := newPublisher(t, f, func() time.Time { return now })
		s, sg := signedStage(t, p)
		if c.unsigned {
			sg = &publication.Signing{Mode: publication.SigningDisabled}
		}
		_, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: boundedRetention("2160h", c.notAfter), Signing: sg})
		if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
		if _, _, _, err := p.readCommit(ctx, testRun); !errors.Is(err, publication.ErrNotFound) {
			t.Errorf("%s: a commit was written: %v", name, err)
		}
	}
}

// Adopting a matching commit whose response was lost before the signing
// failure keeps its original publication time and (later) expiry: the
// record is never rewritten and no bound is added.
func TestAdoptedCommitKeepsItsOwnExpiry(t *testing.T) {
	f := newFake()
	f.versioning = "Enabled"
	p := newPublisher(t, f, time.Now)
	ctx := context.Background()
	s, sg := signedStage(t, p)
	orig, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("2160h"), Signing: sg})
	if err != nil {
		t.Fatal(err)
	}
	before, err := p.read(ctx, orig.Commit.ManifestKey, "")
	if err != nil {
		t.Fatal(err)
	}
	// Recovery's bound is the failure record's expiry, earlier than the
	// commit's own.
	notAfter := orig.ExpiresAt.Add(-time.Hour)
	got, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: boundedRetention("2160h", notAfter), Signing: sg})
	if err != nil || !reflect.DeepEqual(got, orig) || got.Retention.NotAfter != nil || !got.ExpiresAt.Equal(orig.PublishedAt.Add(2160*time.Hour)) {
		t.Fatalf("adoption changed the receipt: %+v %v", got, err)
	}
	after, err := p.read(ctx, orig.Commit.ManifestKey, "")
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("the adopted commit was rewritten: %v", err)
	}
	if vs, err := p.listVersions(ctx, orig.Commit.ManifestKey); err != nil || len(vs) != 1 {
		t.Fatalf("commit versions after adoption: %d %v", len(vs), err)
	}
}

// releasedRetention and releasedSignedManifest are the signed-commit
// decoding of the current release (internal/s3store at 1ef9794, before
// retention.notAfter), kept verbatim.
type releasedRetention struct {
	Duration             string    `json:"duration"`
	BindingConfiguration string    `json:"bindingConfiguration"`
	SelectedAt           time.Time `json:"selectedAt"`
}

type releasedSignedManifest struct {
	APIVersion    string            `json:"apiVersion"`
	Kind          string            `json:"kind"`
	PublicationID string            `json:"publicationID"`
	Subject       commitSubject     `json:"subject"`
	Retention     releasedRetention `json:"retention"`
	Signature     commitSignature   `json:"signature"`
}

func releasedDecode(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var sm releasedSignedManifest
	if err := dec.Decode(&sm); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// Mixed versions fail closed: the current release's strict decoder rejects
// a bounded commit as an unsupported record (never as an unbounded one)
// while it still reads every commit written without a bound. This release
// rejects a bound on an unsigned commit and a bound that extends retention.
func TestNotAfterDecodingFailsClosed(t *testing.T) {
	ctx := context.Background()
	p := newPublisher(t, newFake(), time.Now)
	s, sg := signedStage(t, p)
	r, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: boundedRetention("2160h", time.Now().Add(time.Hour)), Signing: sg})
	if err != nil {
		t.Fatal(err)
	}
	bounded, err := p.read(ctx, r.Commit.ManifestKey, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := releasedDecode(bounded); err == nil {
		t.Fatal("the current release's reader accepted a bounded commit")
	}
	if _, sig, err := decodeCommit(bounded); err != nil || sig == nil {
		t.Fatalf("this release rejected its bounded commit: %v", err)
	}

	edit := func(raw []byte, f func(map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		f(m)
		b, _ := json.Marshal(m)
		return b
	}
	unbounded := edit(bounded, func(m map[string]any) { delete(m["retention"].(map[string]any), "notAfter") })
	if err := releasedDecode(unbounded); err != nil {
		t.Fatalf("the current release's reader rejected an unbounded commit: %v", err)
	}
	rt := retention("1h")
	if b, _ := json.Marshal(releasedRetention{Duration: rt.Duration, BindingConfiguration: rt.BindingConfiguration, SelectedAt: rt.SelectedAt}); !bytes.Equal(b, mustJSON(rt)) {
		t.Fatalf("an unbounded retention changed its encoding: %s", b)
	}
	unsigned := `{"apiVersion":"compliance.erenius.io/v1alpha1","kind":"PublicationCommit","publicationID":"p","run":{"clusterID":"c","bindingUID":"b","runUID":"r"},"descriptorSha256":"` +
		s.DescriptorSHA256 + `","archiveKey":"k","packageSha256":"` + s.PackageSHA256 + `","packageSize":1,"retention":{"duration":"1h","bindingConfiguration":"b","selectedAt":"2026-11-13T12:00:00Z","notAfter":"2026-11-13T12:30:00Z"}}`
	if _, _, err := decodeCommit([]byte(unsigned)); !errors.Is(err, publication.ErrUnsupportedRecord) {
		t.Fatalf("an unsigned commit with a bound: %v", err)
	}
	if _, _, err := decodeCommit(edit(bounded, func(m map[string]any) { m["retention"].(map[string]any)["notAfter"] = "0001-01-01T00:00:00Z" })); !errors.Is(err, publication.ErrUnsupportedRecord) {
		t.Fatalf("an empty bound: %v", err)
	}

	// A stored bound after publishedAt + duration is never read as valid.
	extended := edit(bounded, func(m map[string]any) {
		m["retention"].(map[string]any)["notAfter"] = time.Now().Add(2162 * time.Hour).UTC().Format(time.RFC3339)
	})
	run2 := testRun
	run2.RunUID = "run-uid-extended"
	key := p.commitKey(run2)
	extended = edit(extended, func(m map[string]any) {
		m["subject"].(map[string]any)["run"] = map[string]any{"clusterID": run2.ClusterID, "bindingUID": run2.BindingUID, "runUID": run2.RunUID}
	})
	if _, err := p.putVerified(ctx, key, extended); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Inspect(ctx, run2); !errors.Is(err, publication.ErrUnsupportedRecord) {
		t.Fatalf("a bound extending retention: %v", err)
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
