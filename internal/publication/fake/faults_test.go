package fake_test

// The publication fault fixtures (add-controller-high-availability 1.2)
// against the in-memory fake. Every client is the one shared fake: this
// checks the fake models the contract, and is never durable acceptance.

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
	"github.com/backend-bunny/Konstapel/internal/publication/publicationtest"
)

func TestPublicationFaults(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	p := fake.New(time.Now)
	n := 0
	r := publicationtest.RunPublicationFaults(t, publicationtest.FaultStore{
		Name: "fake.Publisher", Kind: publicationtest.SharedFakeStore, Root: root,
		Client: func(*testing.T) publication.Publisher { return p },
		LoseResponse: func(t *testing.T, _ publication.Publisher, op publicationtest.FaultOp) {
			switch op {
			case publicationtest.LoseStage:
				p.LoseResponse(fake.OpStage)
			case publicationtest.LosePublish:
				p.LoseResponse(fake.OpPublish)
			default:
				t.Fatalf("no response loss for %s", op)
			}
		},
		Run: func(name string) publication.RunRef {
			n++
			return publication.RunRef{ClusterID: "kube-system:fault-fixture", BindingUID: "binding-faults", RunUID: fmt.Sprintf("%s-%d", name, n)}
		},
	})
	if r.DurableAcceptance() || len(r.Cases) != 4 || p.Commits() != 4 {
		t.Fatalf("report %+v, %d commits", r, p.Commits())
	}
}
