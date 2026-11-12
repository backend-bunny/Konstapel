package cache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"

	"github.com/backend-bunny/Konstapel/internal/bundle/verify"
)

// Retained verification material is stored per entry as one file,
// proofs/sha256/<manifest hex>: a fixed header naming the SHA-256 of the
// rest, then the canonical encoding of a verify.RecheckBundle for exactly
// that manifest. It is replaced as a whole by an atomic rename and removed
// with its entry. It is evidence for verify.Verifier.Recheck, never an
// authorization: the cache checks its integrity, not its trust.
const proofMagic = "konstapel-proofs/v1 sha256:"

// proofHeaderLen is the header: magic, 64 hex digits and a newline.
const proofHeaderLen = len(proofMagic) + 64 + 1

type proofState struct {
	sum  string // hex SHA-256 of the encoded material (after the header)
	size int64  // file size, header included
	cost int64
}

func proofFile(data []byte) ([]byte, string) {
	sum := sha256.Sum256(data)
	h := hex.EncodeToString(sum[:])
	out := make([]byte, 0, proofHeaderLen+len(data))
	out = append(out, proofMagic...)
	out = append(out, h...)
	out = append(out, '\n')
	return append(out, data...), h
}

// parseProofHeader returns the recorded hash from a proof file's header.
func parseProofHeader(head []byte) (string, error) {
	if len(head) < proofHeaderLen || !bytes.HasPrefix(head, []byte(proofMagic)) || head[proofHeaderLen-1] != '\n' {
		return "", errors.New("no proof header")
	}
	sum := string(head[len(proofMagic) : proofHeaderLen-1])
	if !hexPattern.MatchString(sum) {
		return "", errors.New("malformed proof header")
	}
	return sum, nil
}

// PutProofs stores the verification material for a stored entry, replacing
// any material stored before. rb must be valid (verify.RecheckBundle.Check)
// and for exactly this manifest digest, and its encoding within
// Limits.MaxProofBytes. Its charge is reserved (evicting unleased entries
// other than this one if needed) before anything is written; the file is
// written in staging, fsynced and renamed into place under the commit lock.
// On any failure the previous material, if any, is unchanged.
func (c *Cache) PutProofs(ctx context.Context, digest string, rb *verify.RecheckBundle) error {
	h, err := hexOf(digest)
	if err != nil {
		return err
	}
	if rb == nil {
		return fmt.Errorf("%w: no material", ErrProofs)
	}
	data, err := rb.Encode()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProofs, err)
	}
	if sum := sha256.Sum256(rb.SubjectManifest); "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return fmt.Errorf("%w: the material is for another subject than %s", ErrProofs, digest)
	}
	if int64(len(data)) > c.lim.MaxProofBytes {
		return fmt.Errorf("%w: verification material of %d bytes exceeds %d", ErrLimit, len(data), c.lim.MaxProofBytes)
	}
	file, sum := proofFile(data)
	cost := blocks(int64(len(file)))
	c.mu.Lock()
	closed, present := c.closed, c.entries[h] != nil
	c.mu.Unlock()
	if closed {
		return ErrClosed
	}
	if !present {
		return fmt.Errorf("%w: %s", ErrNotFound, digest)
	}
	if err := c.reserve(cost, h); err != nil {
		return err
	}
	defer c.release(cost)
	if err := ctx.Err(); err != nil {
		return err
	}
	tmp := path.Join(stagingDir, "proofs-"+randomName())
	defer c.fs.RemoveAll(tmp) // nothing left after the rename
	if err := writeFile(c.fs, tmp, file); err != nil {
		return classifyWrite(err)
	}

	c.commit.Lock()
	defer c.commit.Unlock()
	c.mu.Lock()
	st := c.entries[h]
	closed = c.closed
	c.mu.Unlock()
	if closed {
		return ErrClosed
	}
	if st == nil {
		return fmt.Errorf("%w: %s was removed while its verification material was written", ErrNotFound, digest)
	}
	if err := c.fs.Rename(tmp, path.Join(proofsDir, h)); err != nil {
		return classifyWrite(err)
	}
	c.mu.Lock()
	if st.proofs != nil {
		c.used -= st.proofs.cost
	}
	st.proofs = &proofState{sum: sum, size: int64(len(file)), cost: cost}
	c.used += cost
	c.mu.Unlock()
	return classifyWrite(c.fs.SyncDir(proofsDir))
}

// Proofs returns the retained verification material of a stored entry. The
// file is re-read and checked on every call: its size and the hash recorded
// when it was written (in memory, and in the header after a restart) must
// match, it must decode strictly (verify.DecodeRecheckBundle, which also
// checks every retained digest) and be for exactly this digest. Material
// that fails is removed and ErrCorrupt returned; the entry itself is kept.
// No material is ErrNoProofs. The result is evidence to recheck under
// current trust, not a decision.
func (c *Cache) Proofs(digest string) (*verify.RecheckBundle, error) {
	h, err := hexOf(digest)
	if err != nil {
		return nil, err
	}
	// A replacement between reading the index and the file is retried, so
	// that it is never reported as corruption.
	for attempt := 0; ; attempt++ {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, ErrClosed
		}
		st := c.entries[h]
		var ps *proofState
		if st != nil {
			ps = st.proofs
		}
		c.mu.Unlock()
		switch {
		case st == nil:
			return nil, fmt.Errorf("%w: %s", ErrNotFound, digest)
		case ps == nil:
			return nil, fmt.Errorf("%w: %s", ErrNoProofs, digest)
		}
		rb, cerr := c.readProofs(h, ps)
		if cerr == nil {
			return rb, nil
		}
		replaced, qerr := c.quarantineProofs(h, ps)
		if replaced {
			if attempt < 8 {
				continue
			}
			return nil, fmt.Errorf("verification material for %s was replaced repeatedly while being read", digest)
		}
		cerr = fmt.Errorf("%w: verification material for %s: %v", ErrCorrupt, digest, cerr)
		if qerr != nil {
			return nil, errors.Join(cerr, qerr)
		}
		return nil, cerr
	}
}

func (c *Cache) readProofs(h string, ps *proofState) (*verify.RecheckBundle, error) {
	raw, err := readBounded(c.fs, path.Join(proofsDir, h), ps.size)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != ps.size {
		return nil, fmt.Errorf("%d bytes, recorded %d", len(raw), ps.size)
	}
	recorded, err := parseProofHeader(raw)
	if err != nil {
		return nil, err
	}
	data := raw[proofHeaderLen:]
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != recorded || got != ps.sum {
		return nil, errors.New("does not match its recorded hash")
	}
	rb, err := verify.DecodeRecheckBundle(data)
	if err != nil {
		return nil, err
	}
	if s := sha256.Sum256(rb.SubjectManifest); hex.EncodeToString(s[:]) != h {
		return nil, errors.New("is for another subject")
	}
	return rb, nil
}

// quarantineProofs removes corrupt verification material unless it was
// replaced (or its entry removed) since it was read, which it reports.
func (c *Cache) quarantineProofs(h string, ps *proofState) (replaced bool, err error) {
	c.commit.Lock()
	defer c.commit.Unlock()
	c.mu.Lock()
	st := c.entries[h]
	if st == nil || st.proofs != ps || c.closed {
		c.mu.Unlock()
		return true, nil
	}
	c.mu.Unlock()
	if err := c.fs.RemoveAll(path.Join(proofsDir, h)); err != nil {
		return false, err
	}
	c.mu.Lock()
	st.proofs = nil
	c.used -= ps.cost
	c.mu.Unlock()
	return false, nil
}

// recoverProofs is Open's structural check of retained material: a file
// named by a stored entry's digest, regular, within the size bound, with a
// well-formed header. Anything else is removed. The hash is checked on read.
func (c *Cache) recoverProofs() error {
	files, err := c.fs.ReadDir(proofsDir)
	if err != nil {
		return err
	}
	for _, f := range files {
		name := f.Name()
		ps, err := c.loadProofs(name)
		if err == nil {
			c.entries[name].proofs = ps
			c.used += ps.cost
			continue
		}
		if err := c.fs.RemoveAll(path.Join(proofsDir, name)); err != nil {
			return err
		}
		if hexPattern.MatchString(name) {
			c.recovery.Proofs = append(c.recovery.Proofs, name)
		} else {
			c.recovery.Other = append(c.recovery.Other, path.Join(proofsDir, name))
		}
	}
	return nil
}

func (c *Cache) loadProofs(name string) (*proofState, error) {
	if !hexPattern.MatchString(name) || c.entries[name] == nil {
		return nil, errors.New("no such entry")
	}
	p := path.Join(proofsDir, name)
	info, err := c.fs.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= int64(proofHeaderLen) || info.Size() > int64(proofHeaderLen)+c.lim.MaxProofBytes {
		return nil, errors.New("not a proof file within the limit")
	}
	head, err := readHead(c, p, proofHeaderLen)
	if err != nil {
		return nil, err
	}
	sum, err := parseProofHeader(head)
	if err != nil {
		return nil, err
	}
	return &proofState{sum: sum, size: info.Size(), cost: blocks(info.Size())}, nil
}

func readHead(c *Cache, name string, n int) ([]byte, error) {
	f, err := c.fs.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	k := 0
	for k < n {
		m, err := f.Read(buf[k:])
		k += m
		if err != nil {
			break
		}
	}
	return buf[:k], nil
}
