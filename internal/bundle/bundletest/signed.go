package bundletest

// Signed revisions of the official bundle for upgrade, rollback and
// publisher-rotation tests. A Signer holds a fresh ECDSA P-256 key that
// exists only in memory for the life of the test process (it is never
// written anywhere) and produces the proofs `cosign sign --key` and
// `cosign attest --key --type slsaprovenance1` produce with no transparency
// log, timestamp authority or signing configuration (see
// internal/bundle/verify/testdata/provenance/README.md): a Sigstore bundle
// v0.3 with a DSSE envelope and a public-key hint, in a referrer manifest
// for the subject. Every key and identity here is test material.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing/fstest"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/publish"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

// OfficialName is the repository's official bundle.
const OfficialName = "konstapel-privileged-containers"

// OfficialPolicy is the official bundle's policy source path.
const OfficialPolicy = "content/upstream/kyverno/disallow-privileged-containers/disallow-privileged-containers.yaml"

// OfficialOptions adjust a build of the official bundle definition.
type OfficialOptions struct {
	// Version replaces the definition's version when set.
	Version string
	// Revision is the source commit recorded in the bundle (default
	// "e" * 40).
	Revision string
	// Edit replaces the source bytes of the named repository paths before
	// the build (the archive paths of the definition are unchanged).
	Edit map[string]func([]byte) ([]byte, error)
}

// Official builds bundles/<OfficialName>/definition.json from the repository
// at repo, applying o. The result passes the same validation as a release
// build.
func Official(repo string, o OfficialOptions) (*bundle.Archive, error) {
	raw, err := os.ReadFile(filepath.Join(repo, "bundles", OfficialName, "definition.json"))
	if err != nil {
		return nil, err
	}
	def, err := bundle.LoadDefinition(raw)
	if err != nil {
		return nil, err
	}
	if o.Version != "" {
		def.Version = o.Version
	}
	def.Source.Revision = o.Revision
	if def.Source.Revision == "" {
		def.Source.Revision = strings.Repeat("e", 40)
	}
	src := fstest.MapFS{}
	for _, in := range def.Include {
		if in.From == "" || src[in.From] != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(in.From)))
		if err != nil {
			return nil, err
		}
		src[in.From] = &fstest.MapFile{Data: b}
	}
	for p, edit := range o.Edit {
		f, ok := src[p]
		if !ok {
			return nil, fmt.Errorf("edit of %s: not a source of the definition", p)
		}
		b, err := edit(f.Data)
		if err != nil {
			return nil, fmt.Errorf("edit of %s: %w", p, err)
		}
		src[p] = &fstest.MapFile{Data: b}
	}
	return bundle.Build(def, src, time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC))
}

// TightenedMarker is in the official policy's validation message only after
// TightenPolicy.
const TightenedMarker = "TIGHTENED-REVISION"

// TightenPolicy is a semantic change to the official policy: its validation
// additionally rejects containers that allow privilege escalation, and its
// message carries TightenedMarker. Rules, not only metadata, differ.
func TightenPolicy(b []byte) ([]byte, error) {
	const oldExpr = `container.?securityContext.?privileged.orValue(false) == false)"`
	const newExpr = `(container.?securityContext.?privileged.orValue(false) == false && container.?securityContext.?allowPrivilegeEscalation.orValue(true) == false))"`
	const oldMsg = `message: "Privileged mode is disallowed.`
	if bytes.Count(b, []byte(oldExpr)) != 1 || bytes.Count(b, []byte(oldMsg)) != 1 {
		return nil, fmt.Errorf("the official policy changed; update bundletest.TightenPolicy")
	}
	b = bytes.Replace(b, []byte(oldExpr), []byte(newExpr), 1)
	return bytes.Replace(b, []byte(oldMsg), []byte(`message: "`+TightenedMarker+`: privileged mode and privilege escalation are disallowed.`), 1), nil
}

// Signer is a disposable organization publisher key.
type Signer struct {
	priv *ecdsa.PrivateKey
	// PublicKey is the PEM public key a central rule references.
	PublicKey []byte
	// Fingerprint is sha256:<hex> of the DER public key.
	Fingerprint string
}

// NewSigner generates a fresh in-memory key.
func NewSigner() (*Signer, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return &Signer{priv: k, PublicKey: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
		Fingerprint: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

// Predicate types of the two required proofs.
const (
	predicateSign       = "https://sigstore.dev/cosign/sign/v1"
	predicateProvenance = "https://slsa.dev/provenance/v1"
)

// Result is the retrieval of a from repository with a signature and a
// provenance attestation by s. The provenance follows the Konstapel bundle
// provenance contract for an organization builder (builder record with
// builderRevision), built by publish.BuildProvenance from a publication
// record of a.
func (s *Signer) Result(a *bundle.Archive, repository, builder, builderRevision string) (*registry.Result, error) {
	sig, err := s.proof(a, registry.ProofSignature, predicateSign, []byte("{}"))
	if err != nil {
		return nil, err
	}
	pred, err := Provenance(a, builder, builderRevision)
	if err != nil {
		return nil, err
	}
	prov, err := s.proof(a, registry.ProofProvenance, predicateProvenance, pred)
	if err != nil {
		return nil, err
	}
	return &registry.Result{Repository: repository, Digest: a.ManifestDigest, Manifest: a.Manifest, LayerDigest: a.LayerDigest, Layer: a.Layer,
		Proofs: []registry.Proof{sig, prov}}, nil
}

// Provenance is the conforming provenance predicate for a.
func Provenance(a *bundle.Archive, builder, builderRevision string) ([]byte, error) {
	d := a.Descriptor
	rec := publish.Record{Format: publish.RecordFormat, Name: d.Name, Version: d.Version,
		ManifestDigest: a.ManifestDigest, LayerDigest: a.LayerDigest, ContentDigest: d.ContentDigest(),
		Tools: []publish.Tool{{Name: "go", Version: "1.27.3"}}}
	rec.Source.Repository, rec.Source.Commit = d.Source.Repository, d.Source.Revision
	defSum := sha256.Sum256([]byte(d.Name + "@" + d.Version))
	rec.Definition = publish.FileDigest{Path: "bundles/" + d.Name + "/definition.json", SHA256: hex.EncodeToString(defSum[:])}
	rec.Tests = publish.Tests{Runner: "kyverno-test", Result: publish.TestsPassed}
	for _, f := range d.Files {
		if f.Role == bundle.RoleTest {
			rec.Tests.Files = append(rec.Tests.Files, publish.FileDigest{Path: f.Path, SHA256: f.SHA256})
		}
	}
	return publish.BuildProvenance(rec, publish.ProvenanceInput{Builder: builder, BuilderRevision: builderRevision,
		SigningTools: []publish.Tool{{Name: "cosign", Version: "v3.1.3"}}})
}

// proof signs an in-toto statement about a's manifest in a DSSE envelope.
func (s *Signer) proof(a *bundle.Archive, kind registry.ProofKind, predicateType string, predicate []byte) (registry.Proof, error) {
	statement, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"digest": map[string]string{"sha256": strings.TrimPrefix(a.ManifestDigest, "sha256:")}, "annotations": map[string]string{}}},
		"predicateType": predicateType,
		"predicate":     json.RawMessage(predicate),
	})
	if err != nil {
		return registry.Proof{}, err
	}
	const payloadType = "application/vnd.in-toto+json"
	pae := fmt.Appendf(nil, "DSSEv1 %d %s %d ", len(payloadType), payloadType, len(statement))
	pae = append(pae, statement...)
	h := sha256.Sum256(pae)
	sig, err := ecdsa.SignASN1(rand.Reader, s.priv, h[:])
	if err != nil {
		return registry.Proof{}, err
	}
	fp, _ := hex.DecodeString(strings.TrimPrefix(s.Fingerprint, "sha256:"))
	sb, err := json.Marshal(map[string]any{
		"mediaType":            registry.SigstoreBundleArtifactType,
		"verificationMaterial": map[string]any{"publicKey": map[string]string{"hint": base64.StdEncoding.EncodeToString(fp)}},
		"dsseEnvelope": map[string]any{"payload": base64.StdEncoding.EncodeToString(statement), "payloadType": payloadType,
			"signatures": []any{map[string]string{"sig": base64.StdEncoding.EncodeToString(sig)}}},
	})
	if err != nil {
		return registry.Proof{}, err
	}
	empty := "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	m, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config":        map[string]any{"mediaType": "application/vnd.oci.empty.v1+json", "size": 2, "digest": empty, "artifactType": registry.SigstoreBundleArtifactType},
		"layers":        []any{map[string]any{"mediaType": registry.SigstoreBundleArtifactType, "size": len(sb), "digest": sha(sb)}},
		"annotations": map[string]string{"dev.sigstore.bundle.content": "dsse-envelope", registry.PredicateTypeAnnotation: predicateType,
			"org.opencontainers.image.created": "2026-11-12T08:00:00Z"},
		"subject":      map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "size": len(a.Manifest), "digest": a.ManifestDigest},
		"artifactType": registry.SigstoreBundleArtifactType,
	})
	if err != nil {
		return registry.Proof{}, err
	}
	return registry.Proof{Kind: kind, PredicateType: predicateType, ManifestDigest: sha(m), Manifest: m,
		BundleMediaType: registry.SigstoreBundleArtifactType, BundleDigest: sha(sb), Bundle: sb}, nil
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}
