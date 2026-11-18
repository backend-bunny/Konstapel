// Package s3storetest adapts the S3 publisher to the publication fault
// fixtures (add-controller-high-availability 1.2). Each client is a new SDK
// client with its own HTTP transport, as a separate replica would build:
// clients share nothing but the S3 service. Responses are lost on the
// client side (s3fault.LostResponses), after the service processed the
// request, so one client's loss never affects another.
package s3storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"path"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/publicationtest"
	"github.com/backend-bunny/Konstapel/internal/s3fault"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// FaultStore returns the fault-suite store for the S3 publisher at d. Kind
// is the caller's claim: DurableBackend only for a real S3-compatible
// service, SharedFakeStore for an in-memory S3 server.
func FaultStore(name string, kind publicationtest.StoreKind, root string, d s3store.Destination, creds *s3store.StaticCredentials) publicationtest.FaultStore {
	var mu sync.Mutex
	commits := map[string]int{}
	lossy := map[publication.Publisher]*s3fault.LostResponses{}
	suffix := random()
	return publicationtest.FaultStore{
		Name: name, Kind: kind, Root: root,
		Client: func(t *testing.T) publication.Publisher {
			t.Helper()
			base, err := s3store.NewClient(context.Background(), d, creds)
			if err != nil {
				t.Fatal(err)
			}
			lr := &s3fault.LostResponses{Observe: func(r *http.Request, status int) {
				// Any commit write the service accepted, conditional or
				// not (a conditional one answers 412 when one exists).
				if s3fault.IsCommitWrite(r) && status/100 == 2 {
					mu.Lock()
					commits[path.Base(path.Dir(r.URL.Path))]++
					mu.Unlock()
				}
			}}
			c := s3.New(base.Options(), func(o *s3.Options) { lr.Inner, o.HTTPClient = o.HTTPClient, lr })
			p := &s3store.Publisher{Client: c, Dest: d}
			mu.Lock()
			lossy[p] = lr
			mu.Unlock()
			return p
		},
		LoseResponse: func(t *testing.T, c publication.Publisher, op publicationtest.FaultOp) {
			t.Helper()
			mu.Lock()
			lr := lossy[c]
			mu.Unlock()
			switch {
			case lr == nil:
				t.Fatal("not a client of this store")
			case op == publicationtest.LoseStage:
				lr.Arm(s3fault.IsAttemptRecord)
			case op == publicationtest.LosePublish:
				lr.Arm(s3fault.IsCommitWrite)
			default:
				t.Fatalf("no response loss for %s", op)
			}
		},
		CommitWrites: func(_ *testing.T, run publication.RunRef) int {
			mu.Lock()
			defer mu.Unlock()
			return commits[run.RunUID]
		},
		Run: func(name string) publication.RunRef {
			return publication.RunRef{ClusterID: "kube-system:fault-fixture", BindingUID: "binding-faults-" + suffix, RunUID: name + "-" + random()}
		},
	}
}

func random() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
