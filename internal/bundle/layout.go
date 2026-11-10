package bundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// An OCI image layout is the frozen, pushable form of a bundle: the exact
// manifest and layer bytes that publication will upload and sign. Any OCI
// tool can copy it to a registry without rewriting a byte.

const (
	layoutVersion = `{"imageLayoutVersion":"1.0.0"}`
	// AnnotationName and AnnotationVersion label the layout's index entry.
	AnnotationName    = "io.konstapel.bundle.name"
	AnnotationVersion = "io.konstapel.bundle.version"
)

func blobPath(dir, digest string) string {
	return filepath.Join(dir, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:"))
}

// WriteLayout writes a to dir, which must not exist: frozen inputs are never
// replaced.
func WriteLayout(dir string, a *Archive) error {
	if _, err := os.Lstat(dir); err == nil {
		return fmt.Errorf("%s exists; frozen bundle inputs are never replaced", dir)
	}
	if err := os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o755); err != nil {
		return err
	}
	index, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests": []any{map[string]any{
			"mediaType":    manifestMediaType,
			"digest":       a.ManifestDigest,
			"size":         len(a.Manifest),
			"artifactType": ArtifactType,
			"annotations": map[string]string{
				AnnotationName: a.Descriptor.Name, AnnotationVersion: a.Descriptor.Version,
			},
		}},
	})
	if err != nil {
		return err
	}
	for name, data := range map[string][]byte{"oci-layout": []byte(layoutVersion), "index.json": index} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return err
		}
	}
	for digest, data := range map[string][]byte{
		a.ManifestDigest: a.Manifest, a.LayerDigest: a.Layer, EmptyConfigDigest: []byte("{}"),
	} {
		if err := os.WriteFile(blobPath(dir, digest), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// VerifyLayout re-reads a layout written by WriteLayout and checks it end to
// end: the index names one bundle manifest, every blob matches its digest and
// size, the manifest has the bundle shape, and the unpacked payload matches
// its descriptor. It is the check run before anything is signed or pushed.
func VerifyLayout(dir string) (*Descriptor, string, error) {
	read := func(p string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, p)) }
	if v, err := read("oci-layout"); err != nil || string(v) != layoutVersion {
		return nil, "", errors.New("oci-layout is missing or has an unsupported version")
	}
	raw, err := read("index.json")
	if err != nil {
		return nil, "", err
	}
	var index struct {
		Manifests []ociDescriptor `json:"manifests"`
	}
	if err := json.Unmarshal(raw, &index); err != nil {
		return nil, "", fmt.Errorf("index.json: %w", err)
	}
	if len(index.Manifests) != 1 {
		return nil, "", fmt.Errorf("index.json must name exactly one manifest, found %d", len(index.Manifests))
	}
	blob := func(want ociDescriptor) ([]byte, error) {
		data, err := os.ReadFile(blobPath(dir, want.Digest))
		if err != nil {
			return nil, err
		}
		if digestOf(data) != want.Digest || int64(len(data)) != want.Size {
			return nil, fmt.Errorf("blob %s does not match its digest or size", want.Digest)
		}
		return data, nil
	}
	manifest, err := blob(index.Manifests[0])
	if err != nil {
		return nil, "", err
	}
	layerDigest, layerSize, err := ValidateManifest(manifest)
	if err != nil {
		return nil, "", err
	}
	layer, err := blob(ociDescriptor{Digest: layerDigest, Size: layerSize})
	if err != nil {
		return nil, "", err
	}
	if _, err := blob(ociDescriptor{Digest: EmptyConfigDigest, Size: 2}); err != nil {
		return nil, "", err
	}
	d, payload, err := Unpack(layer)
	if err != nil {
		return nil, "", err
	}
	if err := d.VerifyPayload(payload); err != nil {
		return nil, "", err
	}
	return d, index.Manifests[0].Digest, nil
}
