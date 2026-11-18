package publicationtest

// Fault fixtures around the publication contract
// (add-controller-high-availability 1.2). One suite runs against any
// publication.Publisher store: a lost Stage or Publish response, a second
// package with different bytes under the same run identity, and recovery
// by clients that share nothing with the one that staged. Matching
// operations must converge on one identity, one commit and the retention
// and expiry selected at that commit.
//
// A run states what its store can prove. SharedFakeStore results (the
// in-memory fake, or the S3 publisher against an in-memory S3 server) prove
// the contract's semantics only. Only a DurableBackend run, against a real
// S3-compatible service through independent clients, is durable-backend
// acceptance.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/publication"
)

// StoreKind is what a fault run against a store can establish.
type StoreKind string

const (
	// SharedFakeStore is an in-memory store shared by the clients of one test
	// process. It proves the contract's semantics, never durability, a
	// separate process or real storage behavior.
	SharedFakeStore StoreKind = "shared-fake-store"
	// DurableBackend is a real S3-compatible service. Each client is an
	// independent publisher that shares nothing with the others but that
	// service. Only this kind is durable-backend acceptance.
	DurableBackend StoreKind = "durable-backend"
)

// FaultOp names the operation whose response a fault loses.
type FaultOp string

const (
	// LoseStage loses the response of a Stage whose bytes were stored.
	LoseStage FaultOp = "Stage"
	// LosePublish loses the response of a Publish whose commit was stored.
	LosePublish FaultOp = "Publish"
)

// FaultStore is a publication store under test.
type FaultStore struct {
	Name string
	Kind StoreKind
	// Root is the repository root that packages are built from.
	Root string
	// Client returns a new client of the store: another replica, or a
	// restarted process. DurableBackend clients must be distinct publishers.
	Client func(t *testing.T) publication.Publisher
	// LoseResponse arms client c: its next op, and any retry of it inside
	// that call, takes effect in the store, but the caller gets an error. The
	// suite never uses c again, as a replica that died after sending.
	LoseResponse func(t *testing.T, c publication.Publisher, op FaultOp)
	// CommitWrites, when set, reports how many writes of run's commit the
	// store accepted; commit-once means exactly one.
	CommitWrites func(t *testing.T, run publication.RunRef) int
	// Run returns a run identity that no earlier run against the store used.
	Run func(name string) publication.RunRef
}

// FaultCase is the evidence one case recorded.
type FaultCase struct {
	Name          string    `json:"name"`
	PublicationID string    `json:"publicationID"`
	PackageSHA256 string    `json:"packageSha256"`
	PublishedAt   time.Time `json:"publishedAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
	Retention     string    `json:"retention"`
	Clients       int       `json:"clients"`
	CommitWrites  *int      `json:"commitWrites,omitempty"`
}

// FaultReport is what a fault run established against one store.
type FaultReport struct {
	Store string      `json:"store"`
	Kind  StoreKind   `json:"kind"`
	Cases []FaultCase `json:"cases"`
}

// DurableAcceptance reports whether the run may be cited as durable-backend
// acceptance. A shared fake store never is.
func (r FaultReport) DurableAcceptance() bool { return r.Kind == DurableBackend }

// CheckClients refuses a store whose kind claims more than its clients
// show: a durable backend whose clients are one shared publisher would
// prove nothing beyond a fake.
func CheckClients(kind StoreKind, a, b publication.Publisher) error {
	switch kind {
	case SharedFakeStore:
		return nil
	case DurableBackend:
		if a == b {
			return errors.New("durable-backend clients must be independent publishers, not one shared instance")
		}
		return nil
	default:
		return fmt.Errorf("unknown store kind %q", kind)
	}
}

// RunPublicationFaults runs every fault case against s.
func RunPublicationFaults(t *testing.T, s FaultStore) FaultReport {
	t.Helper()
	if s.Client == nil || s.LoseResponse == nil || s.Run == nil || s.Root == "" {
		t.Fatal("fault store is incomplete")
	}
	if err := CheckClients(s.Kind, s.Client(t), s.Client(t)); err != nil {
		t.Fatal(err)
	}
	f := &faults{s: s, report: FaultReport{Store: s.Name, Kind: s.Kind}}
	for _, c := range []struct {
		name string
		run  func(*testing.T, string) FaultCase
	}{
		{"lost-stage-response", f.lostStage},
		{"lost-publish-response", f.lostPublish},
		{"same-run-conflicting-bytes", f.conflictingBytes},
		{"separate-client-recovery", f.separateRecovery},
	} {
		t.Run(c.name, func(t *testing.T) {
			fc := c.run(t, c.name)
			fc.Name = c.name
			if s.CommitWrites != nil && fc.PublicationID != "" {
				n := s.CommitWrites(t, f.runs[c.name])
				if n != 1 {
					t.Fatalf("the store accepted %d commits for one run", n)
				}
				fc.CommitWrites = &n
			}
			f.report.Cases = append(f.report.Cases, fc)
		})
	}
	return f.report
}

type faults struct {
	s      FaultStore
	report FaultReport
	runs   map[string]publication.RunRef
}

func (f *faults) run(name string) publication.RunRef {
	if f.runs == nil {
		f.runs = map[string]publication.RunRef{}
	}
	r := f.s.Run(name)
	f.runs[name] = r
	return r
}

// pkg builds a complete package for run. Every call yields different bytes
// (OSCAL UUIDs differ); reuse a directory to restage the same bytes.
func (f *faults) pkg(t *testing.T, run publication.RunRef) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "pkg")
	if _, err := FullAssessmentPackage(f.s.Root, dir, run); err != nil {
		t.Fatal(err)
	}
	return dir
}

func retention(d, config string) publication.Retention {
	return publication.Retention{Duration: d, BindingConfiguration: config, SelectedAt: time.Now().UTC().Truncate(time.Second)}
}

var ctx = context.Background()

func sameRetention(a, b publication.Retention) bool {
	return a.Duration == b.Duration && a.BindingConfiguration == b.BindingConfiguration && a.SelectedAt.Equal(b.SelectedAt)
}

// sameReceipt compares the identity, commit, bytes and retention of two
// receipts.
func sameReceipt(a, b publication.Receipt) bool {
	return a.PublicationID == b.PublicationID && a.Commit == b.Commit && a.DescriptorSHA256 == b.DescriptorSHA256 &&
		a.PackageSHA256 == b.PackageSHA256 && a.PackageSize == b.PackageSize && a.PublishedAt.Equal(b.PublishedAt) &&
		a.ExpiresAt.Equal(b.ExpiresAt) && sameRetention(a.Retention, b.Retention)
}

// committed checks, through a fresh client, that run's commit is r: its
// status, and the archive bytes it serves.
func (f *faults) committed(t *testing.T, run publication.RunRef, r publication.Receipt) {
	t.Helper()
	c := f.s.Client(t)
	st, err := c.Inspect(ctx, run)
	if err != nil {
		t.Fatal(err)
	}
	if st.Phase != publication.PhaseCommitted || st.PublicationID != r.PublicationID || st.PackageSHA256 != r.PackageSHA256 ||
		st.PublishedAt == nil || !st.PublishedAt.Equal(r.PublishedAt) || st.ExpiresAt == nil || !st.ExpiresAt.Equal(r.ExpiresAt) {
		t.Fatalf("committed status differs from the receipt:\nstatus  %+v\nreceipt %+v", st, r)
	}
	body, _, err := c.Open(ctx, run)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	b, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != r.PackageSHA256 || int64(len(b)) != r.PackageSize {
		t.Fatal("the served archive is not the committed one")
	}
}

func (f *faults) evidence(r publication.Receipt, clients int) FaultCase {
	return FaultCase{PublicationID: r.PublicationID, PackageSHA256: r.PackageSHA256, PublishedAt: r.PublishedAt, ExpiresAt: r.ExpiresAt,
		Retention: r.Retention.Duration, Clients: clients}
}

func expiresAfter(t *testing.T, r publication.Receipt, d time.Duration) {
	t.Helper()
	if !r.ExpiresAt.Equal(r.PublishedAt.Add(d)) {
		t.Fatalf("expiry %s is not publishedAt %s + %s", r.ExpiresAt, r.PublishedAt, d)
	}
}

// lostStage: the staged bytes landed, the stager never learned it. Another
// client recovers them under the run's identity, restaging the same bytes
// changes nothing, and they commit.
func (f *faults) lostStage(t *testing.T, name string) FaultCase {
	run := f.run(name)
	dir := f.pkg(t, run)
	a := f.s.Client(t)
	f.s.LoseResponse(t, a, LoseStage)
	if _, err := a.Stage(ctx, publication.StageRequest{Run: run, Dir: dir}); !errors.Is(err, publication.ErrUnavailable) {
		t.Fatalf("a lost stage response must be uncertain (ErrUnavailable), got %v", err)
	}
	b := f.s.Client(t)
	rec, err := b.Recover(ctx, run)
	if err != nil {
		t.Fatalf("stored bytes not recovered by another client: %v", err)
	}
	if rec.Run != run || rec.PublicationID != run.PublicationID() {
		t.Fatalf("recovered under another identity: %+v", rec)
	}
	again, err := b.Stage(ctx, publication.StageRequest{Run: run, Dir: dir})
	if err != nil || again != rec {
		t.Fatalf("restaging the same bytes: %+v %v (recovered %+v)", again, err, rec)
	}
	ret := retention("2160h", "fault/lost-stage")
	r, err := b.Publish(ctx, publication.PublishRequest{Staged: rec, Retention: ret})
	if err != nil {
		t.Fatal(err)
	}
	if r.PublicationID != rec.PublicationID || r.PackageSHA256 != rec.PackageSHA256 || !sameRetention(r.Retention, ret) {
		t.Fatalf("receipt %+v for staged %+v", r, rec)
	}
	expiresAfter(t, r, 2160*time.Hour)
	f.committed(t, run, r)
	return f.evidence(r, 3)
}

// lostPublish: the commit landed, the publisher never learned it. Later
// clients, with a changed retention, get the original commit: identity,
// publishedAt, retention and expiry. Different bytes under the identity
// are a conflict.
func (f *faults) lostPublish(t *testing.T, name string) FaultCase {
	run := f.run(name)
	dir := f.pkg(t, run)
	a := f.s.Client(t)
	st, err := a.Stage(ctx, publication.StageRequest{Run: run, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	original := retention("2160h", "fault/lost-publish/original")
	f.s.LoseResponse(t, a, LosePublish)
	if _, err := a.Publish(ctx, publication.PublishRequest{Staged: st, Retention: original}); !errors.Is(err, publication.ErrUnavailable) {
		t.Fatalf("a lost commit response must be uncertain (ErrUnavailable), got %v", err)
	}
	b := f.s.Client(t)
	rec, err := b.Recover(ctx, run)
	if err != nil || rec != st {
		t.Fatalf("recovered %+v %v, staged %+v", rec, err, st)
	}
	r, err := b.Publish(ctx, publication.PublishRequest{Staged: rec, Retention: retention("24h", "fault/lost-publish/edited")})
	if err != nil {
		t.Fatal(err)
	}
	if r.PublicationID != st.PublicationID || r.PackageSHA256 != st.PackageSHA256 || !sameRetention(r.Retention, original) {
		t.Fatalf("the successor did not get the original commit: %+v", r)
	}
	expiresAfter(t, r, 2160*time.Hour)
	c := f.s.Client(t)
	r2, err := c.Publish(ctx, publication.PublishRequest{Staged: st, Retention: retention("1h", "fault/lost-publish/third")})
	if err != nil || !sameReceipt(r2, r) {
		t.Fatalf("a third client's receipt differs: %v\nwant %+v\ngot  %+v", err, r, r2)
	}
	if _, err := c.Stage(ctx, publication.StageRequest{Run: run, Dir: f.pkg(t, run)}); !errors.Is(err, publication.ErrConflict) {
		t.Fatalf("different bytes under a committed identity: %v", err)
	}
	f.committed(t, run, r)
	return f.evidence(r, 3)
}

// conflictingBytes: two clients stage different bytes for one run. At most
// one commit exists; every other attempt is a conflict, and the committed
// bytes never change.
func (f *faults) conflictingBytes(t *testing.T, name string) FaultCase {
	run := f.run(name)
	dirX, dirY := f.pkg(t, run), f.pkg(t, run)
	a, b := f.s.Client(t), f.s.Client(t)
	sx, err := a.Stage(ctx, publication.StageRequest{Run: run, Dir: dirX})
	if err != nil {
		t.Fatal(err)
	}
	type attempt struct {
		c   publication.Publisher
		s   publication.Staged
		dir string
	}
	attempts := []attempt{{a, sx, dirX}}
	// A store may refuse the second bytes at once, or keep both attempts
	// and let the commit decide.
	if sy, err := b.Stage(ctx, publication.StageRequest{Run: run, Dir: dirY}); err == nil {
		if sy.PackageSHA256 == sx.PackageSHA256 || sy.PublicationID != sx.PublicationID {
			t.Fatalf("second package staged as %+v (first %+v)", sy, sx)
		}
		attempts = append(attempts, attempt{b, sy, dirY})
	} else if !errors.Is(err, publication.ErrConflict) {
		t.Fatalf("different bytes for one run: %v", err)
	}
	var won *publication.Receipt
	var winner, loser *attempt
	for i := range attempts {
		r, err := attempts[i].c.Publish(ctx, publication.PublishRequest{Staged: attempts[i].s, Retention: retention("2160h", "fault/conflict")})
		switch {
		case err == nil && won == nil:
			won, winner = &r, &attempts[i]
		case err == nil:
			t.Fatal("two different packages committed under one run identity")
		case errors.Is(err, publication.ErrConflict):
			loser = &attempts[i]
		default:
			t.Fatalf("publish: %v", err)
		}
	}
	if won == nil {
		t.Fatal("no package committed")
	}
	losingDir := dirY
	if winner.dir == dirY {
		losingDir = dirX
	}
	c := f.s.Client(t)
	if _, err := c.Stage(ctx, publication.StageRequest{Run: run, Dir: losingDir}); !errors.Is(err, publication.ErrConflict) {
		t.Fatalf("restaging the losing bytes after the commit: %v", err)
	}
	if loser != nil {
		if _, err := c.Publish(ctx, publication.PublishRequest{Staged: loser.s, Retention: retention("24h", "fault/conflict/retry")}); !errors.Is(err, publication.ErrConflict) {
			t.Fatalf("publishing the losing bytes from another client: %v", err)
		}
	}
	again, err := c.Stage(ctx, publication.StageRequest{Run: run, Dir: winner.dir})
	if err != nil || again != winner.s {
		t.Fatalf("restaging the committed bytes: %+v %v", again, err)
	}
	f.committed(t, run, *won)
	return f.evidence(*won, 3)
}

// separateRecovery: the stager is gone. Successor clients that share
// nothing with it, and race one another with different retentions,
// recover its staging and converge on one commit; a run that was never
// staged is CaptureLost, not an outage.
func (f *faults) separateRecovery(t *testing.T, name string) FaultCase {
	run := f.run(name)
	dir := f.pkg(t, run)
	st, err := f.s.Client(t).Stage(ctx, publication.StageRequest{Run: run, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	const n = 4
	receipts := make([]publication.Receipt, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		c := f.s.Client(t)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rec, err := c.Recover(ctx, run)
			if err != nil {
				errs[i] = err
				return
			}
			if rec != st {
				errs[i] = fmt.Errorf("recovered %+v, staged %+v", rec, st)
				return
			}
			receipts[i], errs[i] = c.Publish(ctx, publication.PublishRequest{Staged: rec, Retention: retention(fmt.Sprintf("%dh", 2160+i), fmt.Sprintf("fault/successor-%d", i))})
		}()
	}
	close(start)
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("successor %d: %v", i, errs[i])
		}
		if !sameReceipt(receipts[i], receipts[0]) {
			t.Fatalf("successors disagree:\n%+v\n%+v", receipts[0], receipts[i])
		}
	}
	r := receipts[0]
	if r.PackageSHA256 != st.PackageSHA256 {
		t.Fatal("committed bytes are not the staged ones")
	}
	d, err := r.Retention.ParseDuration()
	if err != nil {
		t.Fatal(err)
	}
	expiresAfter(t, r, d)
	f.committed(t, run, r)

	lost := f.s.Run(name + "-never-staged")
	c := f.s.Client(t)
	if _, err := c.Recover(ctx, lost); !errors.Is(err, publication.ErrCaptureLost) {
		t.Fatalf("a run never staged must be CaptureLost: %v", err)
	}
	if _, err := c.Inspect(ctx, lost); !errors.Is(err, publication.ErrNotFound) {
		t.Fatalf("a run never staged has no publication: %v", err)
	}
	return f.evidence(r, n+2)
}
