package publication

import (
	"testing"
	"time"
)

// An Orphaned publication keeps any receipt it had, owns no cleanup, and is
// never available.
func TestOrphanedStatusInvariants(t *testing.T) {
	interrupted := Status{Phase: PhaseOrphaned, PublicationID: "pub-1", Availability: AvailabilityUnavailable, Cleanup: Cleanup{State: CleanupOrphaned}}
	if err := interrupted.Validate(); err != nil {
		t.Fatalf("interrupted orphaned publication: %v", err)
	}
	bad := interrupted
	bad.Cleanup.State = CleanupNotDue
	if bad.Validate() == nil {
		t.Fatal("orphaned publication with Konstapel-owned cleanup accepted")
	}
	bad = interrupted
	bad.Availability = AvailabilityAvailable
	if bad.Validate() == nil {
		t.Fatal("available orphaned publication accepted")
	}
	now := time.Now()
	bad = interrupted
	bad.Commit, bad.PublishedAt = &Commit{}, &now
	if bad.Validate() == nil {
		t.Fatal("orphaned commit without a full receipt accepted")
	}
}
