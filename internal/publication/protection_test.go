package publication_test

// Protected supporting evidence (add-supporting-evidence-attachments 5.3,
// 5.5): explicit roles at fixed paths, a versioned marker derived from the
// roles actually present, binding packages only, and fail-closed readers.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/publication"
)

// protectedBinding is a valid binding-scope assessment descriptor with a
// supporting context and one document copy.
func protectedBinding() publication.Descriptor {
	d := valid()
	d.Scope = publication.Scope{Kind: publication.ScopeBinding, ClusterID: d.Run.ClusterID, BindingUID: d.Run.BindingUID, NamespaceUIDs: []string{"ns-uid-a"}, Revision: "scope-rev-1"}
	d.ScopeSHA256 = d.Scope.Digest()
	d.Files = append(d.Files,
		publication.File{Path: publication.SupportingContextFile, Role: publication.RoleSupportingContext, SHA256: strings.Repeat("1", 64), Size: 10},
		publication.File{Path: publication.SupportingDocumentDir + "0f1e2d3c-aaaa-4bbb-8ccc-000000000001", Role: publication.RoleSupportingDocument, SHA256: strings.Repeat("2", 64), Size: 20})
	sortFiles(d.Files)
	d.Protection = publication.ProtectionFor(d.Files)
	return d
}

func sortFiles(fs []publication.File) {
	for i := range fs {
		for j := i + 1; j < len(fs); j++ {
			if fs[j].Path < fs[i].Path {
				fs[i], fs[j] = fs[j], fs[i]
			}
		}
	}
}

func TestProtectionIsDerivedFromRoles(t *testing.T) {
	if p := publication.ProtectionFor(valid().Files); p != nil {
		t.Fatalf("unprotected files derive %+v", p)
	}
	d := protectedBinding()
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	if !d.Protected() || d.Protection.Version != publication.ProtectionVersion ||
		len(d.Protection.Roles) != 2 || d.Protection.Roles[0] != publication.RoleSupportingContext || d.Protection.Roles[1] != publication.RoleSupportingDocument {
		t.Fatalf("protection %+v", d.Protection)
	}
	// An unprotected descriptor's encoding is unchanged: no protection key.
	raw, _ := json.Marshal(valid())
	if bytes.Contains(raw, []byte("protection")) {
		t.Fatal("an unprotected descriptor encodes a protection marker")
	}
}

func TestProtectedDescriptorValidation(t *testing.T) {
	doc := publication.SupportingDocumentDir + "0f1e2d3c-aaaa-4bbb-8ccc-000000000001"
	cases := map[string]func(*publication.Descriptor){
		"marker removed":        func(d *publication.Descriptor) { d.Protection = nil },
		"unknown version":       func(d *publication.Descriptor) { d.Protection.Version = "konstapel.io/package-protection/v2" },
		"roles understated":     func(d *publication.Descriptor) { d.Protection.Roles = d.Protection.Roles[:1] },
		"marker on unprotected": func(d *publication.Descriptor) { d.Files = valid().Files },
		"namespace package": func(d *publication.Descriptor) {
			v := valid()
			d.Scope, d.ScopeSHA256 = v.Scope, v.ScopeSHA256
		},
		"document without context": func(d *publication.Descriptor) {
			d.Files = removeFile(d.Files, publication.SupportingContextFile)
			d.Protection = publication.ProtectionFor(d.Files)
		},
		"document outside its directory": func(d *publication.Descriptor) {
			setPath(d, doc, "evidence/smuggled")
			d.Protection = publication.ProtectionFor(d.Files)
		},
		"nested document path": func(d *publication.Descriptor) {
			setPath(d, doc, publication.SupportingDocumentDir+"a/b")
		},
		"document disguised as provenance": func(d *publication.Descriptor) {
			setRole(d, doc, publication.RoleProvenance)
			d.Protection = publication.ProtectionFor(d.Files)
		},
		"context disguised as summary": func(d *publication.Descriptor) {
			setRole(d, publication.SupportingContextFile, publication.RoleSummary)
		},
		"context at a document path": func(d *publication.Descriptor) { setRole(d, doc, publication.RoleSupportingContext) },
		"other file under the directory": func(d *publication.Descriptor) {
			d.Files = append(d.Files, publication.File{Path: publication.SupportingDir + "notes.txt", Role: publication.RoleProvenance, SHA256: strings.Repeat("3", 64)})
			sortFiles(d.Files)
		},
	}
	for name, mutate := range cases {
		d := protectedBinding()
		mutate(&d)
		if d.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func removeFile(fs []publication.File, p string) []publication.File {
	var out []publication.File
	for _, f := range fs {
		if f.Path != p {
			out = append(out, f)
		}
	}
	return out
}

func setPath(d *publication.Descriptor, from, to string) {
	for i := range d.Files {
		if d.Files[i].Path == from {
			d.Files[i].Path = to
		}
	}
	sortFiles(d.Files)
}

func setRole(d *publication.Descriptor, p string, r publication.FileRole) {
	for i := range d.Files {
		if d.Files[i].Path == p {
			d.Files[i].Role = r
		}
	}
}

func archive(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, b := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write(b)
	}
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}

func protectionOf(t *testing.T, files map[string][]byte) (bool, error) {
	t.Helper()
	raw, err := publication.ArchiveDescriptor(bytes.NewReader(archive(t, files)))
	if err != nil {
		return false, err
	}
	return publication.PackageProtection(raw)
}

func TestArchiveProtectionFailsClosed(t *testing.T) {
	d := protectedBinding()
	raw, _ := json.MarshalIndent(d, "", "  ")
	if p, err := protectionOf(t, map[string][]byte{"summary.json": []byte("{}"), publication.DescriptorFile: raw}); err != nil || !p {
		t.Fatalf("protected descriptor: %v %v", p, err)
	}
	// Old, unprotected descriptors stay readable, even ones that a newer
	// validation would reject: they are only decoded.
	old, _ := json.Marshal(valid())
	legacy := valid()
	legacy.Producer.Checks = nil
	legacyRaw, _ := json.Marshal(legacy)
	for name, b := range map[string][]byte{"current": old, "older rules": legacyRaw} {
		if p, err := protectionOf(t, map[string][]byte{publication.DescriptorFile: b}); err != nil || p {
			t.Fatalf("%s unprotected descriptor: %v %v", name, p, err)
		}
	}
	future := d
	future.Protection = &publication.Protection{Version: "konstapel.io/package-protection/v2", Roles: d.Protection.Roles}
	unknownVersion, _ := json.Marshal(future)
	unmarked := d
	unmarked.Protection = nil
	unmarkedRaw, _ := json.Marshal(unmarked)
	disguised := d
	setRole(&disguised, publication.SupportingDocumentDir+"0f1e2d3c-aaaa-4bbb-8ccc-000000000001", publication.RoleProvenance)
	disguised.Protection = publication.ProtectionFor(disguised.Files)
	disguisedRaw, _ := json.Marshal(disguised)
	invalidProtected := d
	invalidProtected.Producer.Checks = nil
	invalidRaw, _ := json.Marshal(invalidProtected)
	for name, files := range map[string]map[string][]byte{
		"no descriptor":                  {"summary.json": []byte("{}")},
		"unknown protection version":     {publication.DescriptorFile: unknownVersion},
		"protected files without marker": {publication.DescriptorFile: unmarkedRaw},
		"document disguised by its role": {publication.DescriptorFile: disguisedRaw},
		"protected descriptor invalid":   {publication.DescriptorFile: invalidRaw},
		"unknown key in protected":       {publication.DescriptorFile: bytes.Replace(raw, []byte(`"files":`), []byte(`"accessPolicy":{"v":1},"files":`), 1)},
		"malformed descriptor":           {publication.DescriptorFile: []byte("{")},
	} {
		if p, err := protectionOf(t, files); err == nil {
			t.Errorf("%s: accepted (protected %v)", name, p)
		}
	}
	if _, err := publication.ArchiveDescriptor(strings.NewReader("not gzip")); err == nil {
		t.Error("a non-archive was accepted")
	}
}

// The descriptor excerpt in docs/supporting-evidence.md is the marker a
// package with both protected roles derives.
func TestDocumentedProtectionMarker(t *testing.T) {
	raw, err := os.ReadFile("../../docs/supporting-evidence.md")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(raw), "```json\n\"protection\": ")
	block, _, ok2 := strings.Cut(rest, "\n```")
	if !ok || !ok2 {
		t.Fatal("no documented protection marker")
	}
	var got publication.Protection
	if err := json.Unmarshal([]byte(block), &got); err != nil {
		t.Fatal(err)
	}
	want := protectedBinding().Protection
	if got.Version != want.Version || len(got.Roles) != len(want.Roles) || got.Roles[0] != want.Roles[0] || got.Roles[1] != want.Roles[1] {
		t.Fatalf("documented %+v, derived %+v", got, want)
	}
}
