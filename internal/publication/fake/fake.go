// Package fake provides an in-memory publication.Publisher for scheduler,
// collector, and contract tests. It models commit-once semantics, response
// loss, outages, restarts that lose undurable staging, and retention expiry.
// It proves nothing about real storage semantics.
package fake

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/backend-bunny/Konstapel/internal/publication"
)

// Op names a publisher operation for fault injection.
type Op string

const (
	OpStage   Op = "Stage"
	OpPublish Op = "Publish"
	OpInspect Op = "Inspect"
	OpDelete  Op = "Delete"
	OpCleanup Op = "CleanupAttempts"
)

type fault struct {
	err error
	// afterEffect applies the operation before returning err, modeling a
	// lost response after the backend completed the work.
	afterEffect bool
}

type record struct {
	staged  publication.Staged
	durable bool
	receipt *publication.Receipt
	cleanup publication.Cleanup
	deleted bool
}

// Publisher is an in-memory publisher. The zero value is not usable; use New.
type Publisher struct {
	mu          sync.Mutex
	now         func() time.Time
	destination publication.Destination
	// DurableStaging controls whether staged bytes survive Restart.
	DurableStaging bool
	records        map[string]*record
	faults         map[Op][]fault
	calls          map[Op]int
}

var _ publication.Publisher = (*Publisher)(nil)

// New returns a fake publisher using clock as its server time.
func New(clock func() time.Time) *Publisher {
	return &Publisher{
		now:            clock,
		destination:    publication.Destination{ID: "fake", Endpoint: "memory://fake", Bucket: "evidence", Prefix: "konstapel/"},
		DurableStaging: true,
		records:        map[string]*record{},
		faults:         map[Op][]fault{},
		calls:          map[Op]int{},
	}
}

// Fail makes the next call to op return err without effect.
func (p *Publisher) Fail(op Op, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.faults[op] = append(p.faults[op], fault{err: err})
}

// LoseResponse makes the next call to op take effect and then return
// publication.ErrUnavailable, as if the response were lost.
func (p *Publisher) LoseResponse(op Op) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.faults[op] = append(p.faults[op], fault{err: publication.ErrUnavailable, afterEffect: true})
}

// Restart drops staging that was not durable, modeling a controller restart.
func (p *Publisher) Restart() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, r := range p.records {
		if !r.durable && r.receipt == nil {
			delete(p.records, id)
		}
	}
}

// Calls reports how many times op was invoked.
func (p *Publisher) Calls(op Op) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls[op]
}

// Commits reports how many distinct publications are committed.
func (p *Publisher) Commits() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, r := range p.records {
		if r.receipt != nil {
			n++
		}
	}
	return n
}

func (p *Publisher) enter(ctx context.Context, op Op) (*fault, error) {
	p.calls[op]++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if q := p.faults[op]; len(q) > 0 {
		f := q[0]
		p.faults[op] = q[1:]
		if !f.afterEffect {
			return nil, f.err
		}
		return &f, nil
	}
	return nil, nil
}

func lost(f *fault, err error) error {
	if err == nil && f != nil {
		return f.err
	}
	return err
}

// Stage verifies and stages a package directory.
func (p *Publisher) Stage(ctx context.Context, req publication.StageRequest) (publication.Staged, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f, err := p.enter(ctx, OpStage)
	if err != nil {
		return publication.Staged{}, err
	}
	d, err := publication.LoadDescriptor(req.Dir)
	if err != nil {
		return publication.Staged{}, err
	}
	if d.Run != req.Run {
		return publication.Staged{}, fmt.Errorf("descriptor run does not match request: %w", publication.ErrConflict)
	}
	if err = publication.VerifyDir(req.Dir, d); err != nil {
		return publication.Staged{}, err
	}
	sum, size, err := packageDigest(req.Dir, d)
	if err != nil {
		return publication.Staged{}, err
	}
	s := publication.Staged{Run: req.Run, PublicationID: req.Run.PublicationID(), DescriptorSHA256: d.Digest(), PackageSHA256: sum, PackageSize: size}
	if r, ok := p.records[s.PublicationID]; ok {
		if r.staged != s {
			return publication.Staged{}, publication.ErrConflict
		}
		return s, lost(f, nil)
	}
	p.records[s.PublicationID] = &record{staged: s, durable: p.DurableStaging, cleanup: publication.Cleanup{State: publication.CleanupNotDue}}
	return s, lost(f, nil)
}

// Recover returns durable staging or ErrCaptureLost.
func (p *Publisher) Recover(ctx context.Context, run publication.RunRef) (publication.Staged, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return publication.Staged{}, err
	}
	r, ok := p.records[run.PublicationID()]
	if !ok {
		return publication.Staged{}, publication.ErrCaptureLost
	}
	return r.staged, nil
}

// Publish commits staged bytes once.
func (p *Publisher) Publish(ctx context.Context, req publication.PublishRequest) (publication.Receipt, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f, err := p.enter(ctx, OpPublish)
	if err != nil {
		return publication.Receipt{}, err
	}
	r, ok := p.records[req.Staged.PublicationID]
	if !ok || req.Staged.PublicationID != req.Staged.Run.PublicationID() {
		return publication.Receipt{}, publication.ErrCaptureLost
	}
	if r.staged != req.Staged {
		return publication.Receipt{}, publication.ErrConflict
	}
	if r.receipt != nil {
		return *r.receipt, lost(f, nil)
	}
	d, err := req.Retention.ParseDuration()
	if err != nil {
		return publication.Receipt{}, err
	}
	at := p.now().UTC().Truncate(time.Second)
	id := r.staged.PublicationID
	rc := publication.Receipt{
		PublicationID: id, Destination: p.destination,
		Commit:           publication.Commit{ManifestKey: p.destination.Prefix + id + "/commit.json", ManifestVersionID: "v1", ArchiveKey: p.destination.Prefix + id + "/attempts/1/package.tar", ArchiveVersionID: "v1"},
		DescriptorSHA256: r.staged.DescriptorSHA256, PackageSHA256: r.staged.PackageSHA256, PackageSize: r.staged.PackageSize,
		PublishedAt: at, Retention: req.Retention, ExpiresAt: at.Add(d),
	}
	r.receipt = &rc
	return rc, lost(f, nil)
}

// Inspect reports publication state derived from the stored commit.
func (p *Publisher) Inspect(ctx context.Context, run publication.RunRef) (publication.Status, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := p.enter(ctx, OpInspect); err != nil {
		return publication.Status{}, err
	}
	r, ok := p.records[run.PublicationID()]
	if !ok {
		return publication.Status{}, publication.ErrNotFound
	}
	if r.receipt == nil {
		return publication.Status{Phase: publication.PhaseUploading, PublicationID: r.staged.PublicationID, Availability: publication.AvailabilityUnavailable, Cleanup: r.cleanup}, nil
	}
	s := publication.Committed(*r.receipt)
	s.Cleanup = r.cleanup
	switch {
	case r.deleted:
		s.Phase, s.Availability = publication.PhaseDeleted, publication.AvailabilityUnavailable
	case !p.now().Before(r.receipt.ExpiresAt):
		s.Phase, s.Availability = publication.PhaseExpired, publication.AvailabilityExpired
		if s.Cleanup.State == publication.CleanupNotDue {
			s.Cleanup.State = publication.CleanupPending
		}
	}
	return s, nil
}

// Delete removes an expired publication's owned objects.
func (p *Publisher) Delete(ctx context.Context, run publication.RunRef) (publication.Cleanup, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f, err := p.enter(ctx, OpDelete)
	if err != nil {
		return publication.Cleanup{}, err
	}
	r, ok := p.records[run.PublicationID()]
	if !ok {
		return publication.Cleanup{}, publication.ErrNotFound
	}
	now := p.now().UTC()
	if r.receipt != nil && now.Before(r.receipt.ExpiresAt) {
		return r.cleanup, publication.ErrRetentionActive
	}
	r.deleted = true
	r.cleanup = publication.Cleanup{State: publication.CleanupDeleted, Attempts: r.cleanup.Attempts + 1, LastAttempt: &now}
	return r.cleanup, lost(f, nil)
}

// packageDigest stands in for an archive checksum: a SHA-256 over the
// descriptor bytes and every inventoried file in path order.
func packageDigest(dir string, d publication.Descriptor) (string, int64, error) {
	h := sha256.New()
	var size int64
	for _, name := range append([]string{publication.DescriptorFile}, paths(d)...) {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			return "", 0, err
		}
		fmt.Fprintf(h, "%s\x00%d\x00", name, len(b))
		h.Write(b)
		size += int64(len(b))
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

func paths(d publication.Descriptor) []string {
	out := make([]string, len(d.Files))
	for i, f := range d.Files {
		out[i] = f.Path
	}
	return out
}

// CleanupAttempts drops uncommitted staging for the run.
func (p *Publisher) CleanupAttempts(ctx context.Context, run publication.RunRef) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	f, err := p.enter(ctx, OpCleanup)
	if err != nil {
		return err
	}
	if r, ok := p.records[run.PublicationID()]; ok && r.receipt == nil {
		delete(p.records, run.PublicationID())
	}
	return lost(f, nil)
}
