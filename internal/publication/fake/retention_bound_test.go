package fake_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"

	"github.com/backend-bunny/Konstapel/internal/evidencesign"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
)

// signedStaging stages a fixture and stores a signature with a disposable
// key generated for the test.
func signedStaging(t *testing.T) (*fake.Publisher, *clock, publication.Staged, *publication.Signing) {
	t.Helper()
	p, c, d, dir := setup(t, "namespace-complete")
	ctx := context.Background()
	s, err := p.Stage(ctx, publication.StageRequest{Run: d.Run, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	enc, err := encrypted.Encrypt(der, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	signer, err := evidencesign.NewSecretSigner(map[string][]byte{
		evidencesign.SecretPrivateKey: pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED SIGSTORE PRIVATE KEY", Bytes: enc}),
		evidencesign.SecretPublicKey:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}),
		evidencesign.SecretPassword:   []byte("pw"),
	})
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := evidencesign.ParseArchiveDigest(s.PackageSHA256)
	sig, err := signer.Sign(ctx, digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.StoreSignature(ctx, s.Run, sig.Bundle); err != nil {
		t.Fatal(err)
	}
	pk := signer.PublicKey()
	return p, c, s, &publication.Signing{Mode: publication.SigningRequired, PublicKeyPEM: pk.PEM, KeyFingerprint: pk.Fingerprint}
}

func bounded(d string, notAfter time.Time) publication.Retention {
	r := retention(d)
	r.NotAfter = &notAfter
	return r
}

// add-evidence-signing-recovery 2.1, the fake: expiresAt = notAfter; at
// the bound the publication is expired and deleted; a commit landing at or
// after it is expired at once; guards write nothing; adoption keeps the
// existing commit's own expiry.
func TestRetentionNotAfter(t *testing.T) {
	ctx := context.Background()

	p, c, s, sg := signedStaging(t)
	notAfter := c.now().Add(10 * 24 * time.Hour)
	r, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: bounded("2160h", notAfter), Signing: sg})
	if err != nil || !r.ExpiresAt.Equal(notAfter) || !r.PublishedAt.Equal(c.now()) || r.Validate() != nil {
		t.Fatalf("bounded commit: %+v %v", r, err)
	}
	if again, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: bounded("2160h", notAfter), Signing: sg}); err != nil || !reflect.DeepEqual(again, r) {
		t.Fatalf("retry: %v", err)
	}
	if _, err := p.Delete(ctx, s.Run); !errors.Is(err, publication.ErrRetentionActive) {
		t.Fatalf("delete before the bound: %v", err)
	}
	c.advance(10 * 24 * time.Hour)
	if st, err := p.Inspect(ctx, s.Run); err != nil || st.Phase != publication.PhaseExpired {
		t.Fatalf("at the bound: %+v %v", st, err)
	}
	if _, _, err := p.Open(ctx, s.Run); !errors.Is(err, publication.ErrExpired) {
		t.Fatalf("served at the bound: %v", err)
	}
	if cl, err := p.Delete(ctx, s.Run); err != nil || cl.State != publication.CleanupDeleted {
		t.Fatalf("deleted at the bound: %+v %v", cl, err)
	}

	// The server clock is ahead: the commit lands after the bound.
	p, c, s, sg = signedStaging(t)
	p.ServerSkew = 2 * time.Minute
	notAfter = c.now().Add(time.Minute)
	r, err = p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: bounded("2160h", notAfter), Signing: sg})
	if err != nil || r.PublishedAt.Before(notAfter) || r.Validate() != nil {
		t.Fatalf("late commit: %+v %v", r, err)
	}
	if st, err := p.Inspect(ctx, s.Run); err != nil || st.Phase != publication.PhaseExpired || st.Availability != publication.AvailabilityExpired {
		t.Fatalf("late commit inspect: %+v %v", st, err)
	}
	if _, _, err := p.Open(ctx, s.Run); !errors.Is(err, publication.ErrExpired) {
		t.Fatalf("late commit served: %v", err)
	}
	if cl, err := p.Delete(ctx, s.Run); err != nil || cl.State != publication.CleanupDeleted {
		t.Fatalf("late commit deleted: %+v %v", cl, err)
	}

	// Guards write nothing.
	for name, edit := range map[string]func(c *clock, req *publication.PublishRequest){
		"unsigned": func(c *clock, req *publication.PublishRequest) {
			req.Signing = nil
			req.Retention = bounded("2160h", c.now().Add(time.Hour))
		},
		"reached": func(c *clock, req *publication.PublishRequest) { req.Retention = bounded("2160h", c.now()) },
		"extends": func(c *clock, req *publication.PublishRequest) {
			req.Retention = bounded("2160h", c.now().Add(2160*time.Hour+time.Second))
		},
	} {
		p, c, s, sg := signedStaging(t)
		req := publication.PublishRequest{Staged: s, Signing: sg}
		edit(c, &req)
		if _, err := p.Publish(ctx, req); err == nil || p.Commits() != 0 {
			t.Errorf("%s: %v, %d commits", name, err, p.Commits())
		}
	}

	// Adoption of a lost-response commit keeps its own (later) expiry.
	p, c, s, sg = signedStaging(t)
	p.LoseResponse(fake.OpPublish)
	if _, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("2160h"), Signing: sg}); !errors.Is(err, publication.ErrUnavailable) {
		t.Fatalf("lost response: %v", err)
	}
	c.advance(time.Hour)
	got, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: bounded("2160h", c.now().Add(24*time.Hour)), Signing: sg})
	if err != nil || got.Retention.NotAfter != nil || !got.PublishedAt.Equal(c.now().Add(-time.Hour)) || !got.ExpiresAt.Equal(got.PublishedAt.Add(2160*time.Hour)) {
		t.Fatalf("adoption: %+v %v", got, err)
	}
}
