package s3store

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/secure-systems-lab/go-securesystemslib/encrypted"

	"github.com/backend-bunny/Konstapel/internal/evidencesign"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/publicationtest"
)

// testSigner is a disposable Cosign-format key generated per test.
func testSigner(t *testing.T) *evidencesign.SecretSigner {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	enc, err := encrypted.Encrypt(der, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	s, err := evidencesign.NewSecretSigner(map[string][]byte{
		evidencesign.SecretPrivateKey: pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED SIGSTORE PRIVATE KEY", Bytes: enc}),
		evidencesign.SecretPublicKey:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}),
		evidencesign.SecretPassword:   []byte("pw"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func requiredBy(s *evidencesign.SecretSigner) *publication.Signing {
	p := s.PublicKey()
	return &publication.Signing{Mode: publication.SigningRequired, PublicKeyPEM: p.PEM, KeyFingerprint: p.Fingerprint}
}

func signStaged(t *testing.T, s *evidencesign.SecretSigner, st publication.Staged) []byte {
	t.Helper()
	d, err := evidencesign.ParseArchiveDigest(st.PackageSHA256)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	return sig.Bundle
}

// The commit gate: a Required publication commits only after a stored
// signature verifies for the staged archive under the pinned key; the
// signed commit references it and is a SignedPublicationCommit that a
// pre-signing reader cannot mistake for an unsigned commit.
func TestSignedCommitGate(t *testing.T) {
	for _, mode := range []string{"", "Enabled"} {
		f := newFake()
		f.versioning = mode
		p := newPublisher(t, f, time.Now)
		ctx := context.Background()
		s, err := p.Stage(ctx, publication.StageRequest{Run: testRun, Dir: fullPackage(t)})
		if err != nil {
			t.Fatal(err)
		}
		signer, other := testSigner(t), testSigner(t)
		req := publication.PublishRequest{Staged: s, Retention: retention("2160h"), Signing: requiredBy(signer)}

		// No signature: nothing is committed.
		if _, err := p.Publish(ctx, req); !errors.Is(err, publication.ErrSignatureRequired) {
			t.Fatalf("%s: commit without a signature: %v", mode, err)
		}
		if _, _, _, err := p.readCommit(ctx, testRun); !errors.Is(err, publication.ErrNotFound) {
			t.Fatalf("%s: a commit exists: %v", mode, err)
		}

		// The first stored bundle wins; a second, different valid bundle is
		// discarded.
		first := signStaged(t, signer, s)
		got, ref, err := p.StoreSignature(ctx, testRun, first)
		if err != nil || !bytes.Equal(got, first) || ref.Key != p.signatureKey(testRun) {
			t.Fatalf("%s: store: %v", mode, err)
		}
		second := signStaged(t, signer, s)
		if got, _, err := p.StoreSignature(ctx, testRun, second); err != nil || !bytes.Equal(got, first) || bytes.Equal(first, second) {
			t.Fatalf("%s: the second store replaced the first: %v", mode, err)
		}

		// Another key's intent is refused, and commits nothing.
		if _, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("2160h"), Signing: requiredBy(other)}); !errors.Is(err, publication.ErrSignatureRequired) {
			t.Fatalf("%s: a signature by another key satisfied the gate: %v", mode, err)
		}

		r, err := p.Publish(ctx, req)
		if err != nil {
			t.Fatal(mode, err)
		}
		if r.Signature == nil || r.Signature.KeyFingerprint != signer.PublicKey().Fingerprint || r.Signature.SHA256 != ref.SHA256 ||
			r.Signature.MediaType != evidencesign.BundleMediaType || r.Validate() != nil || (mode == "Enabled") != (r.Signature.VersionID != "") {
			t.Fatalf("%s: signed receipt %+v", mode, r.Signature)
		}
		raw, err := p.read(ctx, r.Commit.ManifestKey, "")
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		_ = json.Unmarshal(raw, &doc)
		if doc["kind"] != kindSignedCommit || doc["run"] != nil || doc["subject"] == nil {
			t.Fatalf("%s: signed commit document: %s", mode, raw)
		}
		// A reader from before signing (top-level run required) rejects it.
		var legacy manifest
		if err := json.Unmarshal(raw, &legacy); err != nil || legacy.Run == testRun {
			t.Fatalf("%s: a pre-signing reader would accept the signed commit as this run's", mode)
		}

		// Retries converge; Inspect reports the signature; mismatched
		// intents never accept the existing commit.
		if again, err := p.Publish(ctx, req); err != nil || !reflect.DeepEqual(again, r) {
			t.Fatalf("%s: retry: %v", mode, err)
		}
		if st, err := p.Inspect(ctx, testRun); err != nil || st.Signature == nil || *st.Signature != *r.Signature || st.Validate() != nil {
			t.Fatalf("%s: inspect: %+v %v", mode, st.Signature, err)
		}
		if _, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("2160h")}); !errors.Is(err, publication.ErrConflict) {
			t.Fatalf("%s: an unsigned intent accepted the signed commit: %v", mode, err)
		}
		if _, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("2160h"), Signing: requiredBy(other)}); !errors.Is(err, publication.ErrConflict) {
			t.Fatalf("%s: another key's intent accepted the commit: %v", mode, err)
		}
		// Cleanup of attempts keeps the signature with the commit.
		if err := p.CleanupAttempts(ctx, testRun); err != nil {
			t.Fatal(err)
		}
		if b, _, err := p.ReadSignature(ctx, testRun); err != nil || !bytes.Equal(b, first) {
			t.Fatalf("%s: attempt cleanup removed the signature: %v", mode, err)
		}
	}
}

// A stored bundle for another archive or tampered bytes never satisfies
// the gate, and an existing unsigned commit never satisfies a Required
// intent.
func TestSignedCommitGateRejects(t *testing.T) {
	ctx := context.Background()
	signer := testSigner(t)
	t.Run("signature for another archive", func(t *testing.T) {
		p := newPublisher(t, newFake(), time.Now)
		s, err := p.Stage(ctx, publication.StageRequest{Run: testRun, Dir: fullPackage(t)})
		if err != nil {
			t.Fatal(err)
		}
		otherArchive := s
		otherArchive.PackageSHA256 = strings.Repeat("0", 64)
		if _, _, err := p.StoreSignature(ctx, testRun, signStaged(t, signer, otherArchive)); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("1h"), Signing: requiredBy(signer)}); !errors.Is(err, publication.ErrSignatureRequired) {
			t.Fatalf("a signature for another archive satisfied the gate: %v", err)
		}
	})
	t.Run("tampered bundle", func(t *testing.T) {
		p := newPublisher(t, newFake(), time.Now)
		s, err := p.Stage(ctx, publication.StageRequest{Run: testRun, Dir: fullPackage(t)})
		if err != nil {
			t.Fatal(err)
		}
		b := signStaged(t, signer, s)
		b = bytes.Replace(b, []byte(`"signature":"M`), []byte(`"signature":"N`), 1)
		if _, _, err := p.StoreSignature(ctx, testRun, b); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("1h"), Signing: requiredBy(signer)}); !errors.Is(err, publication.ErrSignatureRequired) {
			t.Fatalf("a tampered signature satisfied the gate: %v", err)
		}
	})
	t.Run("unsigned commit under Required", func(t *testing.T) {
		p := newPublisher(t, newFake(), time.Now)
		s, err := p.Stage(ctx, publication.StageRequest{Run: testRun, Dir: fullPackage(t)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("1h")}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := p.StoreSignature(ctx, testRun, signStaged(t, signer, s)); err != nil {
			t.Fatal(err)
		}
		_, err = p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("1h"), Signing: requiredBy(signer)})
		if !errors.Is(err, publication.ErrSignatureRequired) || !errors.Is(err, publication.ErrConflict) {
			t.Fatalf("an unsigned commit satisfied a Required intent: %v", err)
		}
	})
}

// Commit documents are decoded strictly: an unsigned commit is exactly the
// pre-signing document; unknown kinds, versions, fields, and signature
// formats are unsupported records, never read as unsigned.
func TestCommitRecordsAreDecodedStrictly(t *testing.T) {
	unsigned := `{"apiVersion":"compliance.erenius.io/v1alpha1","kind":"PublicationCommit","publicationID":"p","run":{"clusterID":"c","bindingUID":"b","runUID":"r"},"descriptorSha256":"` + strings.Repeat("1", 64) + `","archiveKey":"k","packageSha256":"` + strings.Repeat("2", 64) + `","packageSize":1,"retention":{"duration":"1h","bindingConfiguration":"b","selectedAt":"2026-11-13T12:00:00Z"}}`
	if m, sig, err := decodeCommit([]byte(unsigned)); err != nil || sig != nil || m.Run.RunUID != "r" {
		t.Fatalf("unsigned commit: %v", err)
	}
	signer := testSigner(t)
	pub := signer.PublicKey()
	sm := signedManifest{APIVersion: publication.APIVersion, Kind: kindSignedCommit, PublicationID: "p",
		Subject:   commitSubject{Run: publication.RunRef{ClusterID: "c", BindingUID: "b", RunUID: "r"}, DescriptorSHA256: strings.Repeat("1", 64), ArchiveKey: "k", PackageSHA256: strings.Repeat("2", 64), PackageSize: 1},
		Retention: publication.Retention{Duration: "1h", BindingConfiguration: "b", SelectedAt: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)},
		Signature: commitSignature{Format: signatureFormat, MediaType: evidencesign.BundleMediaType, Key: "k.sig", SHA256: strings.Repeat("3", 64), Size: 10,
			Algorithm: pub.Algorithm, KeyFingerprint: pub.Fingerprint, PublicKey: string(pub.PEM)}}
	signed, _ := json.Marshal(sm)
	if m, sig, err := decodeCommit(signed); err != nil || sig == nil || m.Run.RunUID != "r" {
		t.Fatalf("signed commit: %v", err)
	}
	edit := func(raw []byte, f func(map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		f(m)
		b, _ := json.Marshal(m)
		return b
	}
	for name, raw := range map[string][]byte{
		"unknown kind":            edit([]byte(unsigned), func(m map[string]any) { m["kind"] = "PublicationCommitV3" }),
		"unknown apiVersion":      edit([]byte(unsigned), func(m map[string]any) { m["apiVersion"] = "compliance.erenius.io/v2" }),
		"unsigned with signature": edit([]byte(unsigned), func(m map[string]any) { m["signature"] = map[string]any{"format": signatureFormat} }),
		"signed without kind":     edit(signed, func(m map[string]any) { m["kind"] = kindCommit }),
		"unknown format":          edit(signed, func(m map[string]any) { m["signature"].(map[string]any)["format"] = "sigstore-bundle-v0.4" }),
		"other algorithm":         edit(signed, func(m map[string]any) { m["signature"].(map[string]any)["algorithm"] = "ecdsa-sha2-384-nistp384" }),
		"fingerprint mismatch": edit(signed, func(m map[string]any) {
			m["signature"].(map[string]any)["keyFingerprint"] = "sha256:" + strings.Repeat("9", 64)
		}),
		"no signature sha": edit(signed, func(m map[string]any) { delete(m["signature"].(map[string]any), "sha256") }),
		"trailing data":    append([]byte(unsigned), []byte(" {}")...),
		"not JSON":         []byte("commit"),
	} {
		if _, sig, err := decodeCommit(raw); !errors.Is(err, publication.ErrUnsupportedRecord) || sig != nil {
			t.Errorf("%s: want ErrUnsupportedRecord, got %v", name, err)
		}
	}
}

// preSigningRead is the commit decoding of releases before evidence signing
// (internal/s3store readManifest at 046cbb8), kept verbatim: it unmarshals
// leniently and accepts the document if its top-level run matches.
func preSigningRead(b []byte, run publication.RunRef) (manifest, error) {
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil || m.Run != run {
		return manifest{}, fmt.Errorf("commit is not this run's publication: %w", publication.ErrConflict)
	}
	return m, nil
}

// Mixed versions fail closed: a controller from before signing that finds a
// signed commit (after a rollback, or during a rolling upgrade) reports a
// conflict instead of reading it as an unsigned publication, while it still
// reads the unsigned commit this release writes exactly as before.
func TestPreSigningReaderRejectsSignedCommit(t *testing.T) {
	ctx := context.Background()
	p := newPublisher(t, newFake(), time.Now)
	s, err := p.Stage(ctx, publication.StageRequest{Run: testRun, Dir: fullPackage(t)})
	if err != nil {
		t.Fatal(err)
	}
	signer := testSigner(t)
	if _, _, err := p.StoreSignature(ctx, testRun, signStaged(t, signer, s)); err != nil {
		t.Fatal(err)
	}
	r, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("1h"), Signing: requiredBy(signer)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := p.read(ctx, r.Commit.ManifestKey, "")
	if err != nil {
		t.Fatal(err)
	}
	if m, err := preSigningRead(raw, testRun); !errors.Is(err, publication.ErrConflict) {
		t.Fatalf("a pre-signing reader accepted the signed commit as unsigned: %+v", m)
	}

	other := testRun
	other.RunUID = "run-uid-unsigned"
	dir := filepath.Join(t.TempDir(), "pkg")
	if _, err := publicationtest.FullAssessmentPackage(repoRoot(t), dir, other); err != nil {
		t.Fatal(err)
	}
	s2, err := p.Stage(ctx, publication.StageRequest{Run: other, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := p.Publish(ctx, publication.PublishRequest{Staged: s2, Retention: retention("1h"), Signing: &publication.Signing{Mode: publication.SigningDisabled}})
	if err != nil || r2.Signature != nil {
		t.Fatalf("unsigned publish: %v", err)
	}
	raw2, err := p.read(ctx, r2.Commit.ManifestKey, "")
	if err != nil {
		t.Fatal(err)
	}
	m, err := preSigningRead(raw2, other)
	if err != nil || m.PackageSHA256 != s2.PackageSHA256 {
		t.Fatalf("a pre-signing reader rejected an unsigned commit: %v", err)
	}
	if again, _ := json.Marshal(m); string(again) != string(raw2) {
		t.Fatalf("the unsigned commit is not the pre-signing document:\n%s\n%s", raw2, again)
	}
}

// Integrity checks, attempt cleanup, and retention deletion cover the
// signature object and every version of it, without touching unrelated
// objects or changing the recorded expiry.
func TestSignatureObjectLifecycle(t *testing.T) {
	for _, mode := range []string{"", "Enabled"} {
		t.Run("versioning="+mode, func(t *testing.T) {
			ctx := context.Background()
			f := newFake()
			f.versioning = mode
			now := time.Now()
			p := newPublisher(t, f, func() time.Time { return now })
			s, err := p.Stage(ctx, publication.StageRequest{Run: testRun, Dir: fullPackage(t)})
			if err != nil {
				t.Fatal(err)
			}
			signer := testSigner(t)
			good := signStaged(t, signer, s)
			if _, _, err := p.StoreSignature(ctx, testRun, good); err != nil {
				t.Fatal(err)
			}
			r, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("1h"), Signing: requiredBy(signer)})
			if err != nil {
				t.Fatal(err)
			}
			put := func(key string, body []byte) {
				t.Helper()
				if _, err := p.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(p.Dest.Bucket), Key: aws.String(key), Body: bytes.NewReader(body)}); err != nil {
					t.Fatal(err)
				}
			}
			otherRun := testRun
			otherRun.RunUID = "run-uid-other"
			unrelated := []string{p.signatureKey(otherRun), p.Dest.KeyPrefix() + "unrelated-object"}
			for _, k := range unrelated {
				put(k, []byte("keep me"))
			}
			health := func() *publication.Failure {
				t.Helper()
				st, err := p.Inspect(ctx, testRun)
				if err != nil {
					t.Fatal(err)
				}
				if !st.ExpiresAt.Equal(r.ExpiresAt) {
					t.Fatalf("expiry changed: %s, want %s", st.ExpiresAt, r.ExpiresAt)
				}
				return st.Failure
			}
			if f := health(); f != nil {
				t.Fatalf("intact signed package: %+v", f)
			}
			// A replaced signature object is corrupt; a missing one is missing.
			other := signStaged(t, testSigner(t), s)
			put(p.signatureKey(testRun), other)
			if f := health(); mode == "" && (f == nil || f.Reason != publication.FailureIntegrityFailed || !strings.Contains(f.Message, "signature")) {
				t.Fatalf("replaced signature: %+v", f)
			} else if mode == "Enabled" && f != nil {
				// Versioned: the committed version is still intact.
				t.Fatalf("versioned: the committed signature version is intact, got %+v", f)
			}
			if mode == "" {
				put(p.signatureKey(testRun), good)
				if _, err := p.Client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(p.Dest.Bucket), Key: aws.String(p.signatureKey(testRun))}); err != nil {
					t.Fatal(err)
				}
				if f := health(); f == nil || f.Reason != publication.FailureObjectMissing || !strings.Contains(f.Message, "signature") {
					t.Fatalf("missing signature: %+v", f)
				}
				put(p.signatureKey(testRun), good)
			}
			// Retention deletion after expiry removes every owned version,
			// including the signature, and nothing else.
			now = r.ExpiresAt.Add(time.Second)
			if _, err := p.Delete(ctx, testRun); err != nil {
				t.Fatal(err)
			}
			if left, err := p.listVersions(ctx, p.runPrefix(testRun)); err != nil {
				t.Fatal(err)
			} else {
				if len(left) != 0 {
					t.Fatalf("owned objects left after retention: %+v", left)
				}
			}
			for _, k := range unrelated {
				if _, err := p.read(ctx, k, ""); err != nil {
					t.Fatalf("unrelated object %s removed: %v", k, err)
				}
			}
		})
	}
}

// Attempt cleanup of an uncommitted run removes its abandoned signature
// object (every version); a committed run keeps its signature.
func TestCleanupAttemptsRemovesUncommittedSignature(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	f.versioning = "Enabled"
	p := newPublisher(t, f, time.Now)
	s, err := p.Stage(ctx, publication.StageRequest{Run: testRun, Dir: fullPackage(t)})
	if err != nil {
		t.Fatal(err)
	}
	signer := testSigner(t)
	if _, _, err := p.StoreSignature(ctx, testRun, signStaged(t, signer, s)); err != nil {
		t.Fatal(err)
	}
	// A second version of the key (written around the conditional create).
	if _, err := p.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(p.Dest.Bucket), Key: aws.String(p.signatureKey(testRun)), Body: bytes.NewReader([]byte("x"))}); err != nil {
		t.Fatal(err)
	}
	sibling := p.signatureKey(testRun) + ".unrelated"
	if _, err := p.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(p.Dest.Bucket), Key: aws.String(sibling), Body: bytes.NewReader([]byte("keep"))}); err != nil {
		t.Fatal(err)
	}
	if err := p.CleanupAttempts(ctx, testRun); err != nil {
		t.Fatal(err)
	}
	vs, _ := p.listVersions(ctx, p.signatureKey(testRun))
	for _, v := range vs {
		if v.key == p.signatureKey(testRun) {
			t.Fatalf("abandoned signature version left: %+v", v)
		}
	}
	if _, err := p.read(ctx, sibling, ""); err != nil {
		t.Fatalf("unrelated object removed: %v", err)
	}
}
