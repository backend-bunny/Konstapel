package preview

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// Diagnostics are ordered by stage, then input position or subject, then
// code, whatever order the pipeline appended them in, and exact duplicates
// are dropped.
func TestReportOrdersDiagnostics(t *testing.T) {
	r := newReport()
	r.Errors = []ReportDiagnostic{
		{Code: ReportExceptionImpactUndetermined, Stage: StageExceptions, Namespace: "prod", Name: "b"},
		{Code: ReportExceptionImpactUndetermined, Stage: StageExceptions, Namespace: "prod", Name: "a"},
		{Code: CompareUnresolvedCandidate, Stage: StageComparison, Name: "x"},
		{Code: ObserveCode(CodeUnknownField), Stage: StageInput, Source: "b.yaml", Document: 1, Line: 3},
		{Code: ObserveCode(CodeDuplicateKey), Stage: StageInput, Source: "a.yaml", Document: 2, Line: 1},
		{Code: ObserveCode(CodeInvalidSpec), Stage: StageInput, Source: "a.yaml", Document: 1, Line: 9},
		{Code: ReportSourcesRequired, Stage: StageContent, Name: "acme"},
		{Code: ReportSourcesRequired, Stage: StageContent, Name: "acme"},
	}
	r.finish()
	var got []string
	for _, d := range r.Errors {
		got = append(got, string(d.Stage)+" "+d.Source+" "+d.Name+" "+string(d.Code))
	}
	want := []string{
		"input a.yaml  invalid-spec", "input a.yaml  duplicate-key", "input b.yaml  unknown-field",
		"content  acme bundle-sources-required", "comparison  x unresolved-candidate",
		"exceptions  a exception-impact-undetermined", "exceptions  b exception-impact-undetermined",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("order\n got %q\nwant %q", got, want)
	}
	if r.Complete {
		t.Fatal("a report without a comparison is complete")
	}
}

// A report without a comparison has null changes and applied state, and is
// never complete, even without errors: undetermined is never empty.
func TestReportWithoutComparison(t *testing.T) {
	r := newReport().finish()
	raw, err := MarshalReport(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"changes", "appliedState", "observation"} {
		if string(m[k]) != "null" {
			t.Errorf("%s = %s", k, m[k])
		}
	}
	if r.Complete || string(m["errors"]) != "[]" || string(m["limitations"]) != "[]" {
		t.Errorf("complete %t errors %s", r.Complete, m["errors"])
	}
}

// Every named stream is reported in argument order with the digest of its
// bytes, including when the input is invalid; an unread stream is marked.
func TestLoadStreamsProvenance(t *testing.T) {
	dir := t.TempDir()
	good := write(t, dir, "good.yaml", bindingYAML("b", "base", "Deny"))
	_, _, streams, err := LoadStreams(Inputs{Proposed: []string{good, dir + "/absent.yaml"}, Before: []string{StdinPath}}, strings.NewReader(""), Limits{})
	if err == nil {
		t.Fatal("an unreadable stream is valid")
	}
	sum := sha256.Sum256([]byte(bindingYAML("b", "base", "Deny")))
	want := []Stream{
		{Role: RoleProposed, Path: good, Read: true, Digest: "sha256:" + hex.EncodeToString(sum[:]), Bytes: int64(len(bindingYAML("b", "base", "Deny")))},
		{Role: RoleProposed, Path: dir + "/absent.yaml"},
		{Role: RoleBefore, Path: StdinPath, Read: true, Digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	}
	if !slices.Equal(streams, want) {
		t.Fatalf("streams\n got %+v\nwant %+v", streams, want)
	}
}
