package publicationtest_test

import (
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/publication/fake"
	"github.com/backend-bunny/Konstapel/internal/publication/publicationtest"
)

// A durable-backend claim needs independent clients; one shared fake
// cannot be cited as durable acceptance.
func TestDurableClaimNeedsIndependentClients(t *testing.T) {
	a, b := fake.New(time.Now), fake.New(time.Now)
	if publicationtest.CheckClients(publicationtest.DurableBackend, a, a) == nil {
		t.Fatal("one shared publisher accepted as a durable backend")
	}
	if err := publicationtest.CheckClients(publicationtest.DurableBackend, a, b); err != nil {
		t.Fatal(err)
	}
	if err := publicationtest.CheckClients(publicationtest.SharedFakeStore, a, a); err != nil {
		t.Fatal(err)
	}
	if publicationtest.CheckClients("fake-but-durable", a, b) == nil {
		t.Fatal("unknown store kind accepted")
	}
	if (publicationtest.FaultReport{Kind: publicationtest.SharedFakeStore}).DurableAcceptance() ||
		!(publicationtest.FaultReport{Kind: publicationtest.DurableBackend}).DurableAcceptance() {
		t.Fatal("durable acceptance follows the store kind")
	}
}
