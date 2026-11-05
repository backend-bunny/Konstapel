package fake_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
)

const fixtures = "../../../testdata/publication"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

func setup(t *testing.T, name string) (*fake.Publisher, *clock, publication.Descriptor, string) {
	t.Helper()
	c := &clock{t: time.Date(2026, 11, 5, 10, 5, 0, 0, time.UTC)}
	dir := filepath.Join(fixtures, name)
	d, err := publication.LoadDescriptor(dir)
	if err != nil {
		t.Fatal(err)
	}
	return fake.New(c.now), c, d, dir
}

func retention(d string) publication.Retention {
	return publication.Retention{Duration: d, BindingConfiguration: "binding-config-3", SelectedAt: time.Date(2026, 11, 5, 10, 4, 59, 0, time.UTC)}
}

func TestPublishesEveryFixtureKind(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"namespace-complete", "namespace-incomplete", "binding-diagnostic", "binding-no-targets"} {
		p, _, d, dir := setup(t, name)
		s, err := p.Stage(ctx, publication.StageRequest{Run: d.Run, Dir: dir})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		r, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("2160h")})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err = r.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		st, err := p.Inspect(ctx, d.Run)
		if err != nil || st.Validate() != nil || st.Phase != publication.PhaseCommitted {
			t.Fatalf("%s: %+v %v", name, st, err)
		}
		sum := publication.Summarize(d, st)
		if sum.Evidence != d.Evidence || sum.Outcomes != d.Outcomes || sum.ArtifactRef != r.PublicationID {
			t.Fatalf("%s: summary mixes states: %+v", name, sum)
		}
	}
}

func TestLostResponseRecoversSameIdentity(t *testing.T) {
	ctx := context.Background()
	p, c, d, dir := setup(t, "namespace-incomplete")
	s, err := p.Stage(ctx, publication.StageRequest{Run: d.Run, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	p.LoseResponse(fake.OpPublish)
	if _, err = p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("2160h")}); !errors.Is(err, publication.ErrUnavailable) {
		t.Fatal(err)
	}
	c.advance(time.Hour)
	// A retry after a binding retention edit recovers the original commit.
	r, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("24h")})
	if err != nil {
		t.Fatal(err)
	}
	if r.Retention.Duration != "2160h" || !r.PublishedAt.Equal(time.Date(2026, 11, 5, 10, 5, 0, 0, time.UTC)) || p.Commits() != 1 {
		t.Fatalf("retry rewrote the commit: %+v", r)
	}
	again, err := p.Stage(ctx, publication.StageRequest{Run: d.Run, Dir: dir})
	if err != nil || again != s {
		t.Fatalf("restaging identical bytes must be idempotent: %v", err)
	}
}

func TestConcurrentPublishCommitsOnce(t *testing.T) {
	ctx := context.Background()
	p, _, d, dir := setup(t, "namespace-complete")
	s, err := p.Stage(ctx, publication.StageRequest{Run: d.Run, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	receipts := make([]publication.Receipt, 8)
	for i := range receipts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			receipts[i], _ = p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("2160h")})
		}()
	}
	wg.Wait()
	for _, r := range receipts[1:] {
		if r != receipts[0] {
			t.Fatal("concurrent publishers produced different receipts")
		}
	}
	if p.Commits() != 1 {
		t.Fatal("duplicate commit")
	}
}

func TestDifferentBytesConflict(t *testing.T) {
	ctx := context.Background()
	p, _, d, dir := setup(t, "namespace-complete")
	if _, err := p.Stage(ctx, publication.StageRequest{Run: d.Run, Dir: dir}); err != nil {
		t.Fatal(err)
	}
	// Another package claiming the same run identity is a conflict.
	other := t.TempDir()
	src := filepath.Join(fixtures, "namespace-incomplete")
	od, _ := publication.LoadDescriptor(src)
	od.Run = d.Run
	od.Scope.ClusterID, od.Scope.BindingUID = d.Run.ClusterID, d.Run.BindingUID
	od.ScopeSHA256 = od.Scope.Digest()
	for _, f := range od.Files {
		b, _ := os.ReadFile(filepath.Join(src, f.Path))
		_ = os.MkdirAll(filepath.Dir(filepath.Join(other, f.Path)), 0o755)
		_ = os.WriteFile(filepath.Join(other, f.Path), b, 0o644)
	}
	writeDescriptor(t, other, od)
	if _, err := p.Stage(ctx, publication.StageRequest{Run: d.Run, Dir: other}); !errors.Is(err, publication.ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	if _, err := p.Stage(ctx, publication.StageRequest{Run: publication.RunRef{ClusterID: "x", BindingUID: "y", RunUID: "z"}, Dir: dir}); !errors.Is(err, publication.ErrConflict) {
		t.Fatalf("descriptor/request run mismatch accepted: %v", err)
	}
}

func TestRestartWithoutDurableStagingIsCaptureLost(t *testing.T) {
	ctx := context.Background()
	p, _, d, dir := setup(t, "binding-diagnostic")
	p.DurableStaging = false
	if _, err := p.Stage(ctx, publication.StageRequest{Run: d.Run, Dir: dir}); err != nil {
		t.Fatal(err)
	}
	p.Restart()
	if _, err := p.Recover(ctx, d.Run); !errors.Is(err, publication.ErrCaptureLost) {
		t.Fatalf("expected CaptureLost, got %v", err)
	}
	sum := publication.CaptureLostSummary(d.Scope.Kind)
	if sum.Export != publication.ExportCaptureLost || sum.ArtifactRef != "" || sum.Evidence.Completeness == publication.Complete {
		t.Fatalf("capture loss must not look published or complete: %+v", sum)
	}

	q, _, d2, dir2 := setup(t, "binding-no-targets")
	s, _ := q.Stage(ctx, publication.StageRequest{Run: d2.Run, Dir: dir2})
	q.Restart()
	if got, err := q.Recover(ctx, d2.Run); err != nil || got != s {
		t.Fatalf("durable staging must survive restart: %v", err)
	}
}

func TestOutageIsPublicationFailureOnly(t *testing.T) {
	ctx := context.Background()
	p, _, d, dir := setup(t, "namespace-complete")
	s, _ := p.Stage(ctx, publication.StageRequest{Run: d.Run, Dir: dir})
	p.Fail(fake.OpPublish, publication.ErrUnavailable)
	if _, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("2160h")}); !errors.Is(err, publication.ErrUnavailable) {
		t.Fatal(err)
	}
	st, err := p.Inspect(ctx, d.Run)
	if err != nil || st.Phase == publication.PhaseCommitted || st.Availability == publication.AvailabilityAvailable {
		t.Fatalf("outage reported as published: %+v", st)
	}
	if sum := publication.Summarize(d, st); sum.Evidence != d.Evidence || sum.ArtifactRef != "" {
		t.Fatal("storage failure changed evaluation state or exposed an artifact")
	}
}

func TestRetentionAndCleanup(t *testing.T) {
	ctx := context.Background()
	p, c, d, dir := setup(t, "namespace-complete")
	s, _ := p.Stage(ctx, publication.StageRequest{Run: d.Run, Dir: dir})
	if _, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("1h")}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Delete(ctx, d.Run); !errors.Is(err, publication.ErrRetentionActive) {
		t.Fatalf("early delete allowed: %v", err)
	}
	c.advance(time.Hour)
	st, _ := p.Inspect(ctx, d.Run)
	if st.Phase != publication.PhaseExpired || st.Availability != publication.AvailabilityExpired || st.Cleanup.State != publication.CleanupPending || st.Validate() != nil {
		t.Fatalf("expiry not reported: %+v", st)
	}
	cl, err := p.Delete(ctx, d.Run)
	if err != nil || cl.State != publication.CleanupDeleted {
		t.Fatal(err)
	}
	if st, _ = p.Inspect(ctx, d.Run); st.Phase != publication.PhaseDeleted || st.Validate() != nil {
		t.Fatalf("%+v", st)
	}
}

func writeDescriptor(t *testing.T, dir string, d publication.Descriptor) {
	t.Helper()
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, publication.DescriptorFile), b, 0o644); err != nil {
		t.Fatal(err)
	}
}
