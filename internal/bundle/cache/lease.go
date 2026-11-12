package cache

import (
	"fmt"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// maxOwnerBytes bounds a lease owner, which names a profile, applied
// contribution or assessment and appears in errors and status.
const maxOwnerBytes = 512

type leaseRequest struct {
	holder, owner string
}

func checkLeaseRequest(holder, owner string) error {
	switch holder {
	case bundle.HolderProfile, bundle.HolderApplied, bundle.HolderAssessment:
	default:
		return fmt.Errorf("%w: holder %q is not %q, %q or %q", ErrLease, holder,
			bundle.HolderProfile, bundle.HolderApplied, bundle.HolderAssessment)
	}
	if owner == "" || len(owner) > maxOwnerBytes {
		return fmt.Errorf("%w: owner must be 1 to %d bytes", ErrLease, maxOwnerBytes)
	}
	return nil
}

// Acquire pins a stored entry for a holder (a desired profile, the last
// applied contribution or an active assessment) on behalf of owner. A leased
// entry is never evicted; it is removed only if it is found corrupt, and then
// Get reports ErrCorrupt to its holders instead of serving it. Several
// owners can lease one entry; each lease is released separately.
//
// Leases live in memory only. After a restart no lease exists: owners
// re-acquire them from their own ownership state (the desired profile, the
// applied contribution recorded by targeting, the active assessment).
func (c *Cache) Acquire(digest, holder, owner string) (bundle.Lease, error) {
	h, err := hexOf(digest)
	if err != nil {
		return bundle.Lease{}, err
	}
	if err := checkLeaseRequest(holder, owner); err != nil {
		return bundle.Lease{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return bundle.Lease{}, ErrClosed
	}
	if c.entries[h] == nil {
		return bundle.Lease{}, fmt.Errorf("%w: %s", ErrNotFound, digest)
	}
	l, err := c.acquireLocked(h, &leaseRequest{holder: holder, owner: owner})
	if err != nil {
		return bundle.Lease{}, err
	}
	return *l, nil
}

// acquireLocked adds a lease on an indexed entry; nil req is no lease. The
// caller holds c.mu.
func (c *Cache) acquireLocked(h string, req *leaseRequest) (*bundle.Lease, error) {
	if req == nil {
		return nil, nil
	}
	st := c.entries[h]
	if st == nil {
		return nil, fmt.Errorf("%w: sha256:%s", ErrNotFound, h)
	}
	now := c.now()
	l := bundle.Lease{ID: randomName(), Holder: req.holder, Owner: req.owner, Digest: "sha256:" + h, AcquiredAt: now.UTC()}
	if c.leases[h] == nil {
		c.leases[h] = map[string]bundle.Lease{}
	}
	c.leases[h][l.ID] = l
	st.lastUsed = now
	return &l, nil
}

// Release ends a lease. The lease must be exactly one that Acquire returned
// and that is still held: an unknown, already released, or altered lease
// (another owner, holder, digest or time under a known ID) is ErrLease and
// releases nothing. Releasing the last lease on an entry makes it evictable
// again; it is not removed by the release itself.
func (c *Cache) Release(l bundle.Lease) error {
	h, err := hexOf(l.Digest)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrLease, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	held, ok := c.leases[h][l.ID]
	if !ok || held.Holder != l.Holder || held.Owner != l.Owner || held.Digest != l.Digest || !held.AcquiredAt.Equal(l.AcquiredAt) {
		return fmt.Errorf("%w: no lease %q by %s %q is held on %s", ErrLease, l.ID, l.Holder, l.Owner, l.Digest)
	}
	delete(c.leases[h], l.ID)
	if len(c.leases[h]) == 0 {
		delete(c.leases, h)
		delete(c.lost, h)
	}
	return nil
}
