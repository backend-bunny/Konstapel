package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// buildInputs returns a definition and source tree matching the fixture payload.
func buildInputs(t *testing.T) (Definition, fstest.MapFS) {
	t.Helper()
	d, payload := fixture(t, false)
	root := fstest.MapFS{}
	def := Definition{
		Name: d.Name, Version: d.Version, Source: d.Source, Policies: d.Policies,
		Scope: d.Scope, Compatibility: d.Compatibility, OSCAL: d.OSCAL,
	}
	for _, f := range d.Files {
		src := "src/" + f.Path // sources need not mirror the archive layout
		root[src] = payload[f.Path]
		def.Include = append(def.Include, Include{From: src, To: f.Path, Role: f.Role})
	}
	return def, root
}

var epoch = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func TestBuildIsReproducible(t *testing.T) {
	def, root := buildInputs(t)
	a, err := Build(def, root, epoch)
	if err != nil {
		t.Fatal(err)
	}
	// Shuffle include order and use a different clock location: same bytes.
	for i, j := 0, len(def.Include)-1; i < j; i, j = i+1, j-1 {
		def.Include[i], def.Include[j] = def.Include[j], def.Include[i]
	}
	b, err := Build(def, root, epoch.In(time.FixedZone("x", 3600)))
	if err != nil {
		t.Fatal(err)
	}
	if a.LayerDigest != b.LayerDigest || a.ManifestDigest != b.ManifestDigest {
		t.Fatalf("not reproducible: %s/%s vs %s/%s", a.LayerDigest, a.ManifestDigest, b.LayerDigest, b.ManifestDigest)
	}
	if !bytes.Equal(a.Layer, b.Layer) || !bytes.Equal(a.Manifest, b.Manifest) {
		t.Fatal("bytes differ for equal digests")
	}
}

func TestBuildChangesWithInputs(t *testing.T) {
	def, root := buildInputs(t)
	a, _ := Build(def, root, epoch)
	root["src/content/policies/privileged.yaml"] = &fstest.MapFile{Data: []byte("kind: Changed\n")}
	b, err := Build(def, root, epoch)
	if err != nil || a.LayerDigest == b.LayerDigest {
		t.Fatalf("content change did not change the digest: %v", err)
	}
	c, _ := Build(def, root, epoch.Add(time.Hour))
	if b.LayerDigest == c.LayerDigest {
		t.Fatal("source time is not part of the archive")
	}
}

func TestBuildDescriptorHasNoOCIDigest(t *testing.T) {
	def, root := buildInputs(t)
	a, err := Build(def, root, epoch)
	if err != nil {
		t.Fatal(err)
	}
	_, files, err := Unpack(a.Layer)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(files[DescriptorPath].Data)
	for _, d := range []string{a.LayerDigest, a.ManifestDigest, strings.TrimPrefix(a.LayerDigest, "sha256:")} {
		if strings.Contains(raw, d) {
			t.Fatalf("descriptor contains its own container digest %s", d)
		}
	}
}

func TestBuildArchiveShape(t *testing.T) {
	def, root := buildInputs(t)
	a, err := Build(def, root, epoch)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(a.Layer))
	if err != nil {
		t.Fatal(err)
	}
	if !zr.ModTime.IsZero() || zr.Name != "" || zr.Comment != "" {
		t.Errorf("gzip header not neutral: %+v", zr.Header)
	}
	tr := tar.NewReader(zr)
	var names []string
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, h.Name)
		if h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" || h.Mode != 0o644 || !h.ModTime.Equal(epoch) {
			t.Errorf("%s: header not normalized: %+v", h.Name, h)
		}
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("entries not sorted: %v", names)
		}
	}
}

func TestBuildRejections(t *testing.T) {
	cases := map[string]struct {
		mut  func(*Definition, fstest.MapFS)
		want string
	}{
		"missing source":   {func(d *Definition, r fstest.MapFS) { delete(r, "src/LICENSE") }, "LICENSE"},
		"duplicate target": {func(d *Definition, r fstest.MapFS) { d.Include = append(d.Include, d.Include[0]) }, "duplicate archive path"},
		"escaping source":  {func(d *Definition, r fstest.MapFS) { d.Include[0].From = "../secret" }, "clean relative"},
		"absolute source":  {func(d *Definition, r fstest.MapFS) { d.Include[0].From = "/etc/passwd" }, "clean relative"},
		"bad target":       {func(d *Definition, r fstest.MapFS) { d.Include[0].To = "../x" }, "outside content/"},
		"bad definition":   {func(d *Definition, r fstest.MapFS) { d.Version = "latest" }, "SemVer"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			def, root := buildInputs(t)
			tc.mut(&def, root)
			if _, err := Build(def, root, epoch); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	def, root := buildInputs(t)
	if _, err := Build(def, root, time.Time{}); err == nil {
		t.Error("accepted a zero source time")
	}
}

func tarGz(t *testing.T, hdrs ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, h := range hdrs {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			tw.Write(make([]byte, h.Size))
		}
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func TestUnpackRejectsUnsafeArchives(t *testing.T) {
	old := maxPayloadBytes
	maxPayloadBytes = 10
	defer func() { maxPayloadBytes = old }()
	cases := map[string]struct {
		layer []byte
		want  string
	}{
		"symlink":   {tarGz(t, &tar.Header{Typeflag: tar.TypeSymlink, Name: "content/x", Linkname: "/etc/passwd"}), "only regular files"},
		"traversal": {tarGz(t, &tar.Header{Typeflag: tar.TypeReg, Name: "../x", Size: 1}), "outside content/"},
		"absolute":  {tarGz(t, &tar.Header{Typeflag: tar.TypeReg, Name: "/etc/x", Size: 1}), "clean relative"},
		"outside":   {tarGz(t, &tar.Header{Typeflag: tar.TypeReg, Name: "bin/x", Size: 1}), "outside content/"},
		"duplicate": {tarGz(t, &tar.Header{Typeflag: tar.TypeReg, Name: "LICENSE", Size: 1}, &tar.Header{Typeflag: tar.TypeReg, Name: "LICENSE", Size: 1}), "duplicate"},
		"oversized": {tarGz(t, &tar.Header{Typeflag: tar.TypeReg, Name: "content/big", Size: 11}), "exceeds"},
		"no desc":   {tarGz(t, &tar.Header{Typeflag: tar.TypeReg, Name: "LICENSE", Size: 1}), "no bundle.json"},
		"not gzip":  {[]byte("plain"), "gzip"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Unpack(tc.layer); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestUnpackDetectsTamperedPayload(t *testing.T) {
	def, root := buildInputs(t)
	a, _ := Build(def, root, epoch)
	d, files, err := Unpack(a.Layer)
	if err != nil {
		t.Fatal(err)
	}
	files["LICENSE"] = &fstest.MapFile{Data: []byte("tampered")}
	if err := d.VerifyPayload(files); err == nil {
		t.Fatal("tampered payload verified")
	}
}
