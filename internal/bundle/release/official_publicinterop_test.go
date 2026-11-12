//go:build publicinterop

package release

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
	"github.com/backend-bunny/Konstapel/internal/bundle/verify"
)

// Public-good interoperability, against the real registry and the real
// release: retrieves the official bundle anonymously from ghcr.io by digest
// through the consumer's registry adapter (VerifyRelease) and verifies it
// through the production verifier under bundles/official-sources.yaml with
// the embedded Sigstore public-good root, then shows that a rule naming
// another identity, issuer, builder or source is refused. It needs network
// access to ghcr.io and is skipped unless built with the publicinterop tag:
//
//	devbox run -- go test -tags publicinterop -count=1 -run '^TestOfficialReleasePublicGood' ./internal/bundle/release/
//
// Verification itself stays offline: no Sigstore service is contacted.
func TestOfficialReleasePublicGood(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	v, err := verify.New(kubeaccess.NewMemoryReader())
	if err != nil {
		t.Fatal(err)
	}
	src := officialRule(t)
	acc, res, err := VerifyRelease(ctx, ReleaseCheck{Source: src, Digest: officialDigest, Verifier: v})
	if err != nil {
		t.Fatal(err)
	}
	checkOfficialAccepted(t, acc)
	if res.Repository != src.Repository || res.Digest != officialDigest {
		t.Fatalf("retrieved %s@%s", res.Repository, res.Digest)
	}
	t.Logf("verified %s@%s anonymously: signer %s, source %s, workflow commit %s, signed %s, referrers via %s",
		src.Repository, officialDigest, acc.Receipt.Signer.Identity, acc.Provenance.SourceRevision,
		acc.Provenance.Workflow.Commit, acc.Proofs.Signature.SigningTime.Format(time.RFC3339), res.ReferrersSource)

	for name, c := range officialNegatives(t) {
		t.Run(name, func(t *testing.T) {
			_, _, err := VerifyRelease(ctx, ReleaseCheck{Source: c.src, Digest: officialDigest, Verifier: v})
			if err == nil {
				t.Fatal("accepted")
			}
			for _, w := range c.want {
				if !errors.Is(err, w) {
					t.Fatalf("error %v does not match %v", err, w)
				}
			}
		})
	}
}
