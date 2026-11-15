// Package fake provides an in-memory attachments.Store for transfer-service
// and CLI tests. It models the contract's verify-before-stage, commit-once,
// conflict, expiry and lost-response semantics. It proves nothing about real
// storage; the S3 adapter has its own tests against the RustFS fixture.
package fake

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/backend-bunny/Konstapel/internal/attachments"
)

// Op names a store operation for fault injection.
type Op string

const (
	OpStage     Op = "Stage"
	OpCommit    Op = "Commit"
	OpCommitted Op = "Committed"
	OpOpen      Op = "Open"
)

type attempt struct {
	id       string
	doc      attachments.Document
	uploader attachments.Principal
	body     []byte
}

// Store is an in-memory attachments.Store for one destination.
type Store struct {
	Dest attachments.Destination
	// Now is the storage server's clock (commitment time) and the expiry
	// clock.
	Now func() time.Time

	mu       sync.Mutex
	attempts map[attachments.Ref][]attempt
	commits  map[attachments.Ref]attachments.Receipt
	faults   map[Op]error
	// Tamper replaces the bytes Open returns, as if storage were damaged.
	tamper map[attachments.Ref][]byte
	seq    int
	calls  []string
	// AfterStage runs (unlocked) after a successful Stage, and BeforeCommit
	// after Commit chose its attempt and before it creates the commitment,
	// to inject races.
	AfterStage, BeforeCommit func(ref attachments.Ref)
}

var _ attachments.Store = (*Store)(nil)

// New returns an empty store.
func New(now func() time.Time) *Store {
	return &Store{Dest: attachments.Destination{ID: "dest-uid", Endpoint: "https://s3.example.internal", Bucket: "evidence", Prefix: "konstapel"},
		Now: now, attempts: map[attachments.Ref][]attempt{}, commits: map[attachments.Ref]attachments.Receipt{},
		faults: map[Op]error{}, tamper: map[attachments.Ref][]byte{}}
}

// Fail makes op return err until cleared with a nil err.
func (s *Store) Fail(op Op, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		delete(s.faults, op)
		return
	}
	s.faults[op] = err
}

// Tamper makes Open return body instead of the committed bytes.
func (s *Store) Tamper(ref attachments.Ref, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tamper[ref] = body
}

// Calls lists the operations performed, as "Op ref.UID".
func (s *Store) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

// Attempts returns the number of staged attempts of ref.
func (s *Store) Attempts(ref attachments.Ref) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.attempts[ref])
}

func (s *Store) begin(op Op, ref attachments.Ref) error {
	s.calls = append(s.calls, string(op)+" "+ref.UID)
	return s.faults[op]
}

func (s *Store) Destination() attachments.Destination { return s.Dest }

func (s *Store) Stage(ctx context.Context, req attachments.StageRequest) (attachments.Staged, error) {
	st, err := s.stage(ctx, req)
	if err == nil && s.AfterStage != nil {
		s.AfterStage(req.Ref)
	}
	return st, err
}

func (s *Store) stage(_ context.Context, req attachments.StageRequest) (attachments.Staged, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.begin(OpStage, req.Ref); err != nil {
		return attachments.Staged{}, err
	}
	if err := req.Ref.Validate(); err != nil {
		return attachments.Staged{}, err
	}
	sum, err := req.Document.Sum()
	if err != nil {
		return attachments.Staged{}, err
	}
	if req.Uploader.Username == "" {
		return attachments.Staged{}, fmt.Errorf("an authenticated uploader is required")
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, req.Document.Size+1))
	if err != nil {
		return attachments.Staged{}, err
	}
	if got := sha256.Sum256(body); int64(len(body)) != req.Document.Size || got != sum {
		return attachments.Staged{}, fmt.Errorf("%w: received %d bytes with a different size or SHA-256", attachments.ErrIntegrity, len(body))
	}
	s.seq++
	id := fmt.Sprintf("a%03d", s.seq)
	s.attempts[req.Ref] = append(s.attempts[req.Ref], attempt{id: id, doc: req.Document, uploader: req.Uploader, body: body})
	return attachments.Staged{Ref: req.Ref, AttemptID: id, Document: req.Document, Uploader: req.Uploader}, nil
}

func same(r attachments.Receipt, req attachments.CommitRequest) error {
	if r.Document != req.Document || r.SpecDigest != req.SpecDigest {
		return fmt.Errorf("%w: the attachment committed %s, not %s", attachments.ErrConflict, r.Document.SHA256, req.Document.SHA256)
	}
	return nil
}

func (s *Store) Commit(_ context.Context, req attachments.CommitRequest) (attachments.Receipt, error) {
	s.mu.Lock()
	if err := s.begin(OpCommit, req.Ref); err != nil {
		s.mu.Unlock()
		return attachments.Receipt{}, err
	}
	if r, ok := s.commits[req.Ref]; ok {
		s.mu.Unlock()
		return r, same(r, req)
	}
	if err := attachments.ValidateRetention(req.Retention); err != nil {
		s.mu.Unlock()
		return attachments.Receipt{}, err
	}
	var chosen *attempt
	list := s.attempts[req.Ref]
	for i := len(list) - 1; i >= 0; i-- {
		if list[i].doc == req.Document {
			chosen = &list[i]
			break
		}
	}
	if chosen == nil {
		s.mu.Unlock()
		return attachments.Receipt{}, fmt.Errorf("%w: no verified upload holds %s", attachments.ErrNotFound, req.Document.SHA256)
	}
	at := *chosen
	hook := s.BeforeCommit
	s.mu.Unlock()
	if hook != nil {
		hook(req.Ref)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.commits[req.Ref]; ok {
		return r, same(r, req)
	}
	now := s.Now().UTC().Truncate(time.Second)
	r := attachments.Receipt{Ref: req.Ref, Destination: s.Dest, ManifestKey: "attachments/" + req.Ref.UID + "/commit.json",
		DocumentKey: "attachments/" + req.Ref.UID + "/attempts/" + at.id + "/document", DocumentVersionID: at.id,
		Document: at.doc, SpecDigest: req.SpecDigest, Uploader: at.uploader, CommittedAt: now, ValidUntil: req.ValidUntil.UTC(),
		Retention: req.Retention, ExpiresAt: attachments.ExpiresAt(now, req.ValidUntil, req.Retention)}
	s.commits[req.Ref] = r
	return r, nil
}

func (s *Store) Committed(_ context.Context, ref attachments.Ref) (attachments.Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.begin(OpCommitted, ref); err != nil {
		return attachments.Receipt{}, err
	}
	r, ok := s.commits[ref]
	if !ok {
		return attachments.Receipt{}, attachments.ErrNotFound
	}
	return r, nil
}

func (s *Store) Open(_ context.Context, r attachments.Receipt) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.begin(OpOpen, r.Ref); err != nil {
		return nil, err
	}
	if !s.Now().Before(r.ExpiresAt) {
		return nil, fmt.Errorf("%w: the source document expired", attachments.ErrNotFound)
	}
	if b, ok := s.tamper[r.Ref]; ok {
		return io.NopCloser(bytes.NewReader(b)), nil
	}
	for _, a := range s.attempts[r.Ref] {
		if a.id == r.DocumentVersionID {
			return io.NopCloser(bytes.NewReader(a.body)), nil
		}
	}
	return nil, fmt.Errorf("%w: the committed document is missing before its expiry", attachments.ErrUnavailable)
}

func (s *Store) Health(context.Context, attachments.Receipt) (*attachments.Problem, error) {
	return nil, nil
}

func (s *Store) CleanupAttempts(context.Context, attachments.Ref, time.Time) error { return nil }

// DeleteUncommitted removes every attempt of an uncommitted attachment.
func (s *Store) DeleteUncommitted(_ context.Context, ref attachments.Ref) (attachments.Cleanup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.commits[ref]; ok {
		return attachments.Cleanup{}, attachments.ErrConflict
	}
	delete(s.attempts, ref)
	return attachments.Cleanup{State: attachments.CleanupDeleted}, nil
}

func (s *Store) Delete(_ context.Context, r attachments.Receipt, now time.Time) (attachments.Cleanup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Before(r.ExpiresAt) {
		return attachments.Cleanup{}, attachments.ErrRetentionActive
	}
	delete(s.commits, r.Ref)
	delete(s.attempts, r.Ref)
	return attachments.Cleanup{State: attachments.CleanupDeleted}, nil
}
