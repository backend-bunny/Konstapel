package v1alpha1_test

import (
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/crdtest"
)

// add-evidence-signing-recovery 4.1 and 4.2: the signing recovery guide in
// docs/integration/evidence-signing.md cannot drift from the implemented
// contract. Its request examples are valid against the generated CRD and are
// quoted verbatim; its outcome table lists exactly the API's phase and reason
// pairs; its field tables list exactly the request spec and status and the
// run's signingRecovery fields; and its kubectl auth can-i probes give the
// documented answers against the shipped ClusterRoles.

const signingGuide = "../../docs/integration/evidence-signing.md"

func readGuide(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(signingGuide)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// section returns the guide's text from heading to the next heading of the
// same or a higher level, outside fenced blocks.
func section(t *testing.T, doc, heading string) string {
	t.Helper()
	_, rest, ok := strings.Cut(doc, "\n"+heading+"\n")
	if !ok {
		t.Fatalf("guide has no %q", heading)
	}
	level := strings.Index(heading, " ")
	lines := strings.Split(rest, "\n")
	fenced := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimLeft(line, " "), "```") {
			fenced = !fenced
		}
		hashes := len(line) - len(strings.TrimLeft(line, "#"))
		if !fenced && hashes > 0 && hashes <= level && strings.HasPrefix(line[hashes:], " ") {
			return strings.Join(lines[:i], "\n")
		}
	}
	return rest
}

// tableRows returns the cells of every body row of the tables in text.
func tableRows(text string) [][]string {
	var rows [][]string
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, "| ") || strings.HasPrefix(line, "| ---") {
			continue
		}
		var cells []string
		for _, c := range strings.Split(strings.Trim(line, "|"), " | ") {
			cells = append(cells, strings.TrimSpace(c))
		}
		rows = append(rows, cells)
	}
	return rows
}

func TestSigningRecoveryGuideExamplesAreValid(t *testing.T) {
	v := crdtest.Load(t, "../../config/crd/bases")["EvidenceSigningRequest"]
	doc := readGuide(t)
	for _, c := range []struct {
		file   string
		pinned bool
	}{
		{"recovery-request.yaml", true},
		{"recovery-request-confirmed-key.yaml", false},
	} {
		t.Run(c.file, func(t *testing.T) {
			path := "docs/examples/evidence-signing/" + c.file
			raw, err := os.ReadFile("../../" + path)
			if err != nil {
				t.Fatal(err)
			}
			o := obj(t, string(raw))
			if errs := v.Validate(o); len(errs) > 0 {
				t.Fatalf("example rejected: %v", errs.ToAggregate())
			}
			spec := o["spec"].(map[string]any)
			if _, forged := spec["requestedBy"]; forged {
				t.Error("an example sets spec.requestedBy, which admission always writes")
			}
			if _, confirms := spec["expectedKeyFingerprint"]; confirms == c.pinned {
				t.Errorf("expectedKeyFingerprint present = %v, want %v", confirms, !c.pinned)
			}
			if !strings.Contains(doc, "]("+"../examples/evidence-signing/"+c.file+")") {
				t.Errorf("the guide does not link %s", path)
			}
			if !strings.Contains(unindent(doc), unindent(strings.TrimSuffix(string(raw), "\n"))) {
				t.Errorf("the guide does not quote %s verbatim", path)
			}
		})
	}
}

// unindent removes every line's indentation, so an example quoted in a list
// item compares line for line.
func unindent(doc string) string {
	var b strings.Builder
	for _, line := range strings.Split(doc, "\n") {
		b.WriteString(strings.TrimLeft(line, " "))
		b.WriteByte('\n')
	}
	return b.String()
}

func TestSigningRecoveryGuideOutcomesMatchTheAPI(t *testing.T) {
	rows := tableRows(section(t, readGuide(t), "### Recovery outcomes"))
	var got, want []string
	for _, r := range rows[1:] { // the header row
		got = append(got, r[0]+"/"+strings.Trim(r[1], "`"))
	}
	for _, phase := range []v1alpha1.SigningRequestPhase{v1alpha1.SigningRequestPending, v1alpha1.SigningRequestRunning,
		v1alpha1.SigningRequestSucceeded, v1alpha1.SigningRequestFailed} {
		for _, reason := range v1alpha1.SigningRecoveryReasons[phase] {
			want = append(want, string(phase)+"/"+string(reason))
		}
	}
	if len(v1alpha1.SigningRecoveryReasons) != 4 || !slices.Equal(got, want) {
		t.Errorf("outcome table rows\n got %v\nwant %v", got, want)
	}
}

// jsonFields lists a struct's JSON field names, prefixed.
func jsonFields(prefix string, v any) []string {
	var out []string
	rt := reflect.TypeOf(v)
	for i := range rt.NumField() {
		name, _, _ := strings.Cut(rt.Field(i).Tag.Get("json"), ",")
		if name != "" {
			out = append(out, prefix+name)
		}
	}
	return out
}

func TestSigningRecoveryGuideFieldsMatchTheAPI(t *testing.T) {
	rows := tableRows(section(t, readGuide(t), "#### Request fields"))
	var got []string
	for _, r := range rows {
		if f := strings.Trim(r[0], "`"); f != "Field" {
			got = append(got, f)
		}
	}
	want := slices.Concat(jsonFields("spec.", v1alpha1.EvidenceSigningRequestSpec{}),
		jsonFields("status.", v1alpha1.EvidenceSigningRequestStatus{}),
		jsonFields("status.signingRecovery.", v1alpha1.SigningRecoveryStatus{}))
	if !slices.Equal(got, want) {
		t.Errorf("field table rows\n got %v\nwant %v", got, want)
	}
	// Nested names quoted in the descriptions are the API's.
	text := section(t, readGuide(t), "#### Request fields")
	for _, f := range slices.Concat(jsonFields("", v1alpha1.ExactRunReference{}), jsonFields("", v1alpha1.SigningRecoveryPublication{}),
		jsonFields("", v1alpha1.SigningRecoveryClaim{}), jsonFields("", v1alpha1.SigningRecoveryRecord{})) {
		if !strings.Contains(text, "`"+f+"`") {
			t.Errorf("field tables do not name %s", f)
		}
	}
}

var (
	probeSubject = regexp.MustCompile(`^# As .*:$`)
	probeRole    = regexp.MustCompile(`konstapel-[a-z-]+`)
	probeLine    = regexp.MustCompile(`^kubectl auth can-i (\S+) (\S+?)(\.compliance\.erenius\.io)?((?: --subresource=\S+)?)((?: -n \S+)?)\s+# (yes|no)$`)
)

func TestSigningRecoveryGuidePermissionProbes(t *testing.T) {
	text := section(t, readGuide(t), "### Recovery roles")
	roles := map[string][]rbacv1.PolicyRule{}
	for _, r := range loadRoles(t) {
		if r.kind == "ClusterRole" {
			roles[r.name] = r.rules
		}
	}
	var subject []string
	probes := 0
	for _, line := range strings.Split(text, "\n") {
		switch {
		case probeSubject.MatchString(line):
			subject = probeRole.FindAllString(line, -1)
			for _, name := range subject {
				if _, ok := roles[name]; !ok {
					t.Errorf("probe subject names unshipped ClusterRole %s", name)
				}
			}
		case strings.HasPrefix(line, "kubectl auth can-i"):
			m := probeLine.FindStringSubmatch(line)
			if m == nil || len(subject) == 0 {
				t.Errorf("unparsed probe %q", line)
				continue
			}
			probes++
			verb, resource, central := m[1], m[2], m[3] != ""
			if sub := strings.TrimPrefix(m[4], " --subresource="); sub != "" {
				resource += "/" + sub
			}
			allowed := false
			for _, name := range subject {
				if central {
					allowed = allowed || grants(roles[name], verb, resource)
				} else {
					allowed = allowed || grantsCore(roles[name], verb, resource)
				}
			}
			if allowed != (m[6] == "yes") {
				t.Errorf("%v: %q answers %v", subject, line, allowed)
			}
		}
	}
	if probes < 10 {
		t.Fatalf("found %d probes", probes)
	}
}
