package preview

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func loadErr(t *testing.T, in Inputs, stdin string, lim Limits) InputErrors {
	t.Helper()
	_, _, err := Load(in, strings.NewReader(stdin), lim)
	var ie InputErrors
	if err == nil || !errors.As(err, &ie) {
		t.Fatalf("want InputErrors, got %v", err)
	}
	return ie
}

func TestLoadMergesRepeatedFilesAndStdin(t *testing.T) {
	dir := t.TempDir()
	a := write(t, dir, "a.yaml", profileYAML("base"))
	b := write(t, dir, "b.yaml", bindingYAML("audit", "base", "Audit"))
	prev := write(t, dir, "prev.yaml", bindingYAML("old", "base", "Audit"))
	prop, before, err := Load(Inputs{Proposed: []string{a, b, StdinPath}, Before: []string{prev}}, strings.NewReader(bindingYAML("from-stdin", "base", "Deny")), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, o := range prop.Objects {
		ids = append(ids, o.Identity.String())
	}
	if strings.Join(ids, ",") != "ComplianceBinding/audit,ComplianceBinding/from-stdin,ComplianceProfile/base" {
		t.Fatalf("ids = %v", ids)
	}
	if prop.Get(Identity{Group: "compliance.erenius.io", Kind: KindBinding, Name: "from-stdin"}).Source != StdinPath {
		t.Fatal("stdin object not attributed to -")
	}
	if len(before.Objects) != 1 {
		t.Fatalf("before = %d objects", len(before.Objects))
	}
}

func TestLoadRequiresProposedButAllowsEmptyStream(t *testing.T) {
	dir := t.TempDir()
	ie := loadErr(t, Inputs{Before: []string{write(t, dir, "p.yaml", profileYAML("x"))}}, "", Limits{})
	if ie[0].Code != CodeNoProposedInput {
		t.Fatalf("%v", ie)
	}
	empty := write(t, dir, "empty.yaml", "")
	prop, _, err := Load(Inputs{Proposed: []string{empty}, Before: []string{write(t, dir, "p.yaml", profileYAML("x"))}}, nil, Limits{})
	if err != nil || prop == nil || len(prop.Objects) != 0 {
		t.Fatalf("explicit empty stream: %v %+v", err, prop)
	}
	// Empty stdin is also an explicitly empty stream.
	if prop, _, err = Load(Inputs{Proposed: []string{StdinPath}}, strings.NewReader(""), Limits{}); err != nil || len(prop.Objects) != 0 {
		t.Fatalf("empty stdin: %v", err)
	}
}

func TestLoadStdinOnlyOnce(t *testing.T) {
	dir := t.TempDir()
	f := write(t, dir, "a.yaml", profileYAML("x"))
	for name, in := range map[string]Inputs{
		"both-proposed":       {Proposed: []string{StdinPath, StdinPath}},
		"proposed-and-before": {Proposed: []string{StdinPath}, Before: []string{StdinPath}},
		"with-files":          {Proposed: []string{f, StdinPath}, Before: []string{StdinPath}},
	} {
		t.Run(name, func(t *testing.T) {
			if ie := loadErr(t, in, profileYAML("x"), Limits{}); ie[0].Code != CodeStdinTwice {
				t.Fatalf("%v", ie)
			}
		})
	}
	if _, _, err := Load(Inputs{Proposed: []string{StdinPath}}, nil, Limits{}); err == nil {
		t.Fatal("nil stdin accepted")
	}
}

func TestLoadSizeLimitIsSharedAndExact(t *testing.T) {
	dir := t.TempDir()
	doc := profileYAML("x")
	f := write(t, dir, "a.yaml", doc)
	g := write(t, dir, "b.yaml", strings.ReplaceAll(doc, "name: x", "name: y"))
	n := int64(len(doc))
	if _, _, err := Load(Inputs{Proposed: []string{f}}, nil, Limits{MaxInputBytes: n}); err != nil {
		t.Fatalf("exactly at the limit: %v", err)
	}
	if ie := loadErr(t, Inputs{Proposed: []string{f}}, "", Limits{MaxInputBytes: n - 1}); ie[0].Code != CodeInputTooLarge || ie[0].Source != f {
		t.Fatalf("%v", ie)
	}
	// Two streams each within the limit but together over it.
	if ie := loadErr(t, Inputs{Proposed: []string{f, g}}, "", Limits{MaxInputBytes: n + 1}); ie[0].Code != CodeInputTooLarge || ie[0].Source != g {
		t.Fatalf("%v", ie)
	}
	// Before shares the budget with proposed.
	if ie := loadErr(t, Inputs{Proposed: []string{f}, Before: []string{g}}, "", Limits{MaxInputBytes: n + 1}); ie[0].Code != CodeInputTooLarge {
		t.Fatalf("%v", ie)
	}
	// Standard input is bounded the same way.
	if ie := loadErr(t, Inputs{Proposed: []string{StdinPath}}, doc, Limits{MaxInputBytes: n - 1}); ie[0].Code != CodeInputTooLarge || ie[0].Source != StdinPath {
		t.Fatalf("%v", ie)
	}
}

func TestLoadReadProblemsAndDuplicates(t *testing.T) {
	dir := t.TempDir()
	a := write(t, dir, "a.yaml", bindingYAML("dup", "p", "Audit"))
	b := write(t, dir, "b.yaml", bindingYAML("dup", "p", "Deny"))
	ie := loadErr(t, Inputs{Proposed: []string{a, b, filepath.Join(dir, "missing.yaml"), dir}}, "", Limits{})
	got := codes(ie)
	want := []Code{CodeDuplicateIdentity, CodeReadFailed, CodeReadFailed}
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("codes = %v\n%v", got, ie)
	}
	if !strings.Contains(ie[0].Message, a) || ie[0].Source != b {
		t.Fatalf("duplicate attribution: %+v", ie[0])
	}
	// The same identity in proposed and before is expected, not a duplicate.
	if _, _, err := Load(Inputs{Proposed: []string{a}, Before: []string{b}}, nil, Limits{}); err != nil {
		t.Fatal(err)
	}
	// An invalid document anywhere makes the whole load fail; nothing is skipped.
	bad := write(t, dir, "bad.yaml", "apiVersion: v1\nkind: Namespace\nmetadata: {name: n}\n")
	if _, _, err := Load(Inputs{Proposed: []string{a, bad}}, nil, Limits{}); err == nil {
		t.Fatal("Namespace silently skipped")
	}
}
