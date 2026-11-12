package bundle

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing/fstest"
)

// Frozen bundle content is the exact verified bytes of one applied bundle,
// copied out of the runtime cache when an assessment starts. The assessment
// exports, replays and publishes from this copy only, so its evidence never
// depends on the cache, the registry or the trust configuration after the
// run started, and it never falls back to other content.
//
// A frozen directory (an assessment's staging copy, or an evidence package)
// holds:
//
//	bundle/manifest.json  the OCI manifest; its sha256 is the bundle digest
//	bundle/layer.tar.gz   the single layer the manifest names
//	bundle/bundle.json    the descriptor, byte-identical to the layer's
//	bundle/identity.json  identities and the verification context (FrozenIdentity)
//	content/...           the layer's content/ files, byte-identical
//
// The manifest digest anchors everything else: ReadFrozen re-derives the
// layer, descriptor and every content/ file from it and rejects any
// difference, so a frozen copy cannot be edited without changing the digest
// the assessment recorded.
const (
	// FrozenVersion versions FrozenIdentity and the frozen layout.
	FrozenVersion = 1
	// FrozenDir holds the frozen proof files.
	FrozenDir = "bundle"
	// FrozenManifest, FrozenLayer, FrozenDescriptor and FrozenIdentityFile
	// are the frozen proof files, relative to a frozen directory.
	FrozenManifest     = FrozenDir + "/manifest.json"
	FrozenLayer        = FrozenDir + "/layer.tar.gz"
	FrozenDescriptor   = FrozenDir + "/" + DescriptorPath
	FrozenIdentityFile = FrozenDir + "/identity.json"
	// frozenContent is the payload subtree copied next to the proofs.
	frozenContent = "content/"
)

// FrozenIdentity is what an assessment records about the applied bundle it
// froze: every bundle identity, the source, and the verification context
// (receipt) under which the content was resolved when it was frozen. The
// receipt is evidence that a check happened, not a standing authorization;
// a frozen copy is used for the run that froze it and nothing else.
type FrozenIdentity struct {
	FrozenVersion int     `json:"frozenVersion"`
	Name          string  `json:"name"`
	Version       string  `json:"version"`
	Digests       Digests `json:"digests"`
	Source        Source  `json:"source"`
	// Compatibility is the resolver's verdict at freeze time.
	Compatibility CompatibilityResult `json:"compatibility"`
	// Receipt is the verification the content was resolved under.
	Receipt Receipt `json:"receipt"`
}

// Frozen is a verified frozen bundle.
type Frozen struct {
	Identity   FrozenIdentity
	Descriptor *Descriptor
	// Payload is the unpacked layer (bundle.json included).
	Payload fstest.MapFS
}

// verifyFrozen checks the chain manifest -> layer -> descriptor -> payload
// and that id describes exactly that bundle.
func verifyFrozen(manifest, layer []byte, id FrozenIdentity) (*Frozen, error) {
	if id.FrozenVersion != FrozenVersion {
		return nil, fmt.Errorf("frozen bundle: frozenVersion %d: want %d", id.FrozenVersion, FrozenVersion)
	}
	if got := digestOf(manifest); got != id.Digests.OCI {
		return nil, fmt.Errorf("frozen bundle: manifest hashes to %s, recorded %s", got, id.Digests.OCI)
	}
	layerDigest, size, err := ValidateManifest(manifest)
	if err != nil {
		return nil, fmt.Errorf("frozen bundle: %w", err)
	}
	if digestOf(layer) != layerDigest || int64(len(layer)) != size {
		return nil, errors.New("frozen bundle: the layer is not the one the manifest names")
	}
	if id.Digests.Archive != layerDigest {
		return nil, fmt.Errorf("frozen bundle: recorded archive digest %s, manifest names %s", id.Digests.Archive, layerDigest)
	}
	d, payload, err := Unpack(layer)
	if err != nil {
		return nil, fmt.Errorf("frozen bundle: %w", err)
	}
	if err := d.VerifyPayload(payload); err != nil {
		return nil, fmt.Errorf("frozen bundle: %w", err)
	}
	switch {
	case d.Name != id.Name || d.Version != id.Version:
		return nil, fmt.Errorf("frozen bundle: layer is %s@%s, recorded %s@%s", d.Name, d.Version, id.Name, id.Version)
	case d.ContentDigest() != id.Digests.Content:
		return nil, fmt.Errorf("frozen bundle: content digest %s, recorded %s", d.ContentDigest(), id.Digests.Content)
	case d.Source != id.Source || d.Source.Revision != id.Digests.Revision:
		return nil, errors.New("frozen bundle: recorded source does not match the descriptor")
	}
	return &Frozen{Identity: id, Descriptor: d, Payload: payload}, nil
}

// WriteFrozen verifies manifest, layer and id and writes a frozen directory
// at dir, which must not exist. The directory appears complete or not at
// all: it is assembled under a temporary name and renamed into place.
func WriteFrozen(dir string, manifest, layer []byte, id FrozenIdentity) (*Frozen, error) {
	f, err := verifyFrozen(manifest, layer, id)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(dir); err == nil {
		return nil, fmt.Errorf("%s exists; frozen content is never replaced", dir)
	}
	var suffix [8]byte
	_, _ = rand.Read(suffix[:])
	tmp := dir + ".tmp-" + hex.EncodeToString(suffix[:])
	if err := os.MkdirAll(filepath.Join(tmp, FrozenDir), 0o700); err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(tmp)
		}
	}()
	idJSON, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{
		FrozenManifest: manifest, FrozenLayer: layer,
		FrozenDescriptor: f.Payload[DescriptorPath].Data, FrozenIdentityFile: append(idJSON, '\n'),
	}
	for p, file := range f.Payload {
		if p != DescriptorPath {
			files[p] = file.Data
		}
	}
	for p, data := range files {
		target := filepath.Join(tmp, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(target, data, 0o600); err != nil {
			return nil, err
		}
	}
	if err := os.Rename(tmp, dir); err != nil {
		return nil, err
	}
	ok = true
	return f, nil
}

// ReadFrozen reads and verifies a frozen directory (a staging copy or an
// evidence package): the proof chain, the descriptor copy, and that its
// content/ tree is exactly the layer's content/ files. Other files in dir
// (an evidence package's own documents) are not examined.
func ReadFrozen(dir string) (*Frozen, error) {
	read := func(p string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, filepath.FromSlash(p))) }
	manifest, err := read(FrozenManifest)
	if err != nil {
		return nil, fmt.Errorf("frozen bundle: %w", err)
	}
	layer, err := read(FrozenLayer)
	if err != nil {
		return nil, fmt.Errorf("frozen bundle: %w", err)
	}
	raw, err := read(FrozenIdentityFile)
	if err != nil {
		return nil, fmt.Errorf("frozen bundle: %w", err)
	}
	var id FrozenIdentity
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&id); err != nil {
		return nil, fmt.Errorf("frozen bundle: identity: %w", err)
	}
	f, err := verifyFrozen(manifest, layer, id)
	if err != nil {
		return nil, err
	}
	if desc, err := read(FrozenDescriptor); err != nil || !bytes.Equal(desc, f.Payload[DescriptorPath].Data) {
		return nil, errors.New("frozen bundle: bundle/bundle.json is not the layer's descriptor")
	}
	entries, err := os.ReadDir(filepath.Join(dir, FrozenDir))
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if p := FrozenDir + "/" + e.Name(); !slices.Contains([]string{FrozenManifest, FrozenLayer, FrozenDescriptor, FrozenIdentityFile}, p) {
			return nil, fmt.Errorf("frozen bundle: unexpected %s", p)
		}
	}
	if err := sameContent(os.DirFS(dir), f.Payload); err != nil {
		return nil, err
	}
	return f, nil
}

// sameContent requires the content/ tree of dir to be exactly the payload's
// content/ files, byte for byte, with nothing added or missing.
func sameContent(dir fs.FS, payload fstest.MapFS) error {
	want := map[string][]byte{}
	for p, f := range payload {
		if strings.HasPrefix(p, frozenContent) {
			want[p] = f.Data
		}
	}
	seen := map[string]bool{}
	err := fs.WalkDir(dir, strings.TrimSuffix(frozenContent, "/"), func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			return nil
		}
		if !e.Type().IsRegular() {
			return fmt.Errorf("frozen bundle: %s is not a regular file", p)
		}
		data, ok := want[p]
		if !ok {
			return fmt.Errorf("frozen bundle: %s is not in the bundle", p)
		}
		got, err := fs.ReadFile(dir, p)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, data) {
			return fmt.Errorf("frozen bundle: %s differs from the bundle", p)
		}
		seen[p] = true
		return nil
	})
	if err != nil {
		return err
	}
	for p := range want {
		if !seen[p] {
			return fmt.Errorf("frozen bundle: %s is missing", path.Clean(p))
		}
	}
	return nil
}
