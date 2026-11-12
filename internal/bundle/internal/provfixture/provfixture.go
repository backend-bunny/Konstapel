// Package provfixture loads the checked-in Cosign provenance fixtures
// (internal/bundle/verify/testdata/provenance, see its README.md) for tests
// of packages layered on the verifier: the real official bundle signed and
// attested with an organization key. Only tests import it.
package provfixture

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
)

// Facts about the fixtures (testdata/provenance/facts.txt).
const (
	SourceRepository = "https://github.com/backend-bunny/Konstapel"
	Builder          = "https://ci.example.test/konstapel/bundle-release@refs/heads/main"
	Repository       = "registry.example.test/fixtures/konstapel-privileged-containers"
	Name             = "konstapel-privileged-containers"
)

// Fixtures are the subject and its proofs.
type Fixtures struct {
	Manifest, Layer []byte
	Subject         string
	LayerDigest     string
	FPOrg, FPOther  string
	PubOrg          []byte
	PubOther        []byte
	// Proofs by fixture name: sign-org, sign-other, prov-valid,
	// prov-valid-other, prov-wrong-builder.
	Proofs map[string]registry.Proof
}

func dir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "verify", "testdata", "provenance")
}

func read(name string) ([]byte, error) { return os.ReadFile(filepath.Join(dir(), name)) }

// Load reads the fixtures.
func Load() (*Fixtures, error) {
	f := &Fixtures{Proofs: map[string]registry.Proof{}}
	var err error
	for _, x := range []struct {
		dst  *[]byte
		name string
	}{{&f.Manifest, "subject-manifest.json"}, {&f.Layer, "subject-layer.tar.gz"}, {&f.PubOrg, "org.pub"}, {&f.PubOther, "other.pub"}} {
		if *x.dst, err = read(x.name); err != nil {
			return nil, err
		}
	}
	f.Subject = SHA(f.Manifest)
	if f.LayerDigest, _, err = bundle.ValidateManifest(f.Manifest); err != nil {
		return nil, err
	}
	facts, err := read("facts.txt")
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(facts), "\n") {
		k, v, _ := strings.Cut(line, " ")
		switch k {
		case "subject":
			if v != f.Subject {
				return nil, fmt.Errorf("facts.txt subject %s, manifest hashes to %s", v, f.Subject)
			}
		case "org":
			f.FPOrg = v
		case "other":
			f.FPOther = v
		}
	}
	for _, n := range []string{"sign-org", "sign-other", "prov-valid", "prov-valid-other", "prov-wrong-builder"} {
		kind := registry.ProofProvenance
		if strings.HasPrefix(n, "sign-") {
			kind = registry.ProofSignature
		}
		m, err := read(n + ".manifest.json")
		if err != nil {
			return nil, err
		}
		b, err := read(n + ".bundle.json")
		if err != nil {
			return nil, err
		}
		var ann struct {
			Annotations map[string]string `json:"annotations"`
		}
		if err := json.Unmarshal(m, &ann); err != nil {
			return nil, err
		}
		f.Proofs[n] = registry.Proof{Kind: kind, PredicateType: ann.Annotations[registry.PredicateTypeAnnotation], ManifestDigest: SHA(m), Manifest: m,
			BundleMediaType: registry.SigstoreBundleArtifactType, BundleDigest: SHA(b), Bundle: b}
	}
	return f, nil
}

// Reader holds the organization key as Secret/org and the other key as
// Secret/other, under the default data key.
func (f *Fixtures) Reader() *kubeaccess.MemoryReader {
	r := kubeaccess.NewMemoryReader()
	PutKey(r, "org", f.PubOrg)
	PutKey(r, "other", f.PubOther)
	return r
}

// PutKey stores a public key Secret.
func PutKey(r *kubeaccess.MemoryReader, name string, pub []byte) {
	r.Put(bundle.KindSecret, name, kubeaccess.NewObject("Opaque", map[string][]byte{bundle.DefaultPublicKey: pub}))
}

// Source is the organization-key rule for the official bundle.
func (f *Fixtures) Source() bundle.BundleSource {
	return bundle.BundleSource{
		Name:       Name,
		Repository: Repository,
		Publisher: bundle.Publisher{
			Type:           bundle.SignerPublicKey,
			PublicKey:      &bundle.ObjectRef{Kind: bundle.KindSecret, Name: "org"},
			KeyFingerprint: f.FPOrg,
			Provenance:     bundle.ProvenanceRule{SourceRepository: SourceRepository, Builder: Builder},
		},
	}
}

// Result is the retrieval of the subject with the named proofs.
func (f *Fixtures) Result(proofs ...string) *registry.Result {
	res := &registry.Result{Repository: Repository, Digest: f.Subject, Manifest: f.Manifest, LayerDigest: f.LayerDigest, Layer: f.Layer}
	for _, p := range proofs {
		res.Proofs = append(res.Proofs, f.Proofs[p])
	}
	return res
}

// StatementDigest is the digest of the DSSE payload in a Sigstore bundle.
func StatementDigest(bundleJSON []byte) (string, error) {
	var m struct {
		DsseEnvelope struct {
			Payload string `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	if err := json.Unmarshal(bundleJSON, &m); err != nil {
		return "", err
	}
	p, err := base64.StdEncoding.DecodeString(m.DsseEnvelope.Payload)
	if err != nil {
		return "", err
	}
	return SHA(p), nil
}

// SHA is sha256:<hex> of b.
func SHA(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}
