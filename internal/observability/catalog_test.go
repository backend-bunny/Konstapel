package observability

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
)

var update = flag.Bool("update", false, "rewrite the exposition and documentation goldens")

const repoRoot = "../.."

// Allowed label names: the binding name plus fixed enums (design §1).
var allowedLabels = []string{"binding", "domain", "condition", "status", "capability", "view", "state", "operation", "result"}

// Dimensions the contract must never carry: workload/namespace/run identity,
// free text, storage references, versions, and framework content.
var forbidden = regexp.MustCompile(`(?i)namespace|workload|pod|uid|run|reason|error|message|policy|profile|control|framework|catalog|nist|moderate|baseline|statement|digest|hash|version|bucket|object|key|reference|url|cluster`)

func TestCatalogNamingConventions(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range Catalog {
		if seen[m.Name] {
			t.Errorf("%s is defined twice", m.Name)
		}
		seen[m.Name] = true
		if !regexp.MustCompile(`^konstapel_[a-z0-9_]+$`).MatchString(m.Name) {
			t.Errorf("%s: not a konstapel_ snake_case name", m.Name)
		}
		switch m.Type {
		case Counter:
			if !strings.HasSuffix(m.Name, "_total") {
				t.Errorf("%s: counters end in _total", m.Name)
			}
		case Gauge, Histogram:
			if strings.HasSuffix(m.Name, "_total") {
				t.Errorf("%s: only counters end in _total", m.Name)
			}
		default:
			t.Errorf("%s: unknown type %q", m.Name, m.Type)
		}
		if m.Unit == "seconds" != strings.HasSuffix(m.Name, "_seconds") {
			t.Errorf("%s: unit %q must match the _seconds suffix", m.Name, m.Unit)
		}
		if m.Unit != "" && m.Unit != "seconds" {
			t.Errorf("%s: unit %q is not a base unit", m.Name, m.Unit)
		}
		if m.Help == "" || m.Availability == "" || m.Reset == "" || m.Domain == "" {
			t.Errorf("%s: help, availability, reset semantics and domain are all documented", m.Name)
		}
	}
}

func TestCatalogLabelsAreBoundedEnums(t *testing.T) {
	for _, m := range Catalog {
		names := map[string]bool{}
		for _, l := range m.Labels {
			if names[l.Name] {
				t.Errorf("%s: label %s twice", m.Name, l.Name)
			}
			names[l.Name] = true
			if !slices.Contains(allowedLabels, l.Name) || forbidden.MatchString(l.Name) {
				t.Errorf("%s: label %q is not an allowed bounded dimension", m.Name, l.Name)
			}
			switch {
			case l.Name == LabelBinding && l.Values != nil:
				t.Errorf("%s: binding takes binding names, not an enum", m.Name)
			case l.Name != LabelBinding && len(l.Values) == 0:
				t.Errorf("%s: label %s has no fixed vocabulary", m.Name, l.Name)
			}
			for _, v := range l.Values {
				if !regexp.MustCompile(`^[A-Za-z_]+$`).MatchString(v) {
					t.Errorf("%s: %s value %q is not a simple enum token", m.Name, l.Name, v)
				}
			}
		}
	}
}

// Framework content belongs in bundle metadata and OSCAL, never in metrics.
func TestCatalogIsFrameworkNeutral(t *testing.T) {
	frameworkTerms := regexp.MustCompile(`(?i)\bnist\b|\bcontrol(s)?\b|\bmoderate\b|\bbaseline\b|\bcatalog\b|\bframework\b|\bac-\d|\bcm-\d|\boscal\b|\bcoverage\b`)
	for _, m := range Catalog {
		for _, text := range []string{m.Name, m.Help} {
			if frameworkTerms.MatchString(text) {
				t.Errorf("%s mentions framework content: %q", m.Name, text)
			}
		}
		for _, l := range m.Labels {
			for _, v := range l.Values {
				if frameworkTerms.MatchString(v) {
					t.Errorf("%s: %s value %q is framework content", m.Name, l.Name, v)
				}
			}
		}
	}
}

// Series per family are bounded by bindings x enum sizes: no label grows
// with workloads or retained history.
func TestCatalogSeriesAreBoundedPerBinding(t *testing.T) {
	for _, m := range Catalog {
		perBinding := 1
		for _, l := range m.Labels {
			if l.Name != LabelBinding {
				perBinding *= len(l.Values)
			}
		}
		if perBinding > 64 {
			t.Errorf("%s: %d series per binding", m.Name, perBinding)
		}
	}
}

// contractRegistry registers one example series for every label combination
// of every family, with binding "example".
func contractRegistry(t *testing.T) *prometheus.Registry {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	for _, m := range Catalog {
		reg.MustRegister(exampleCollector{m})
	}
	return reg
}

type exampleCollector struct{ m Metric }

func (c exampleCollector) desc() *prometheus.Desc {
	var names []string
	for _, l := range c.m.Labels {
		names = append(names, l.Name)
	}
	return prometheus.NewDesc(c.m.Name, c.m.Help, names, nil)
}

func (c exampleCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc() }

func (c exampleCollector) Collect(ch chan<- prometheus.Metric) {
	combos := [][]string{{}}
	for _, l := range c.m.Labels {
		values := l.Values
		if l.Name == LabelBinding {
			values = []string{"example"}
		}
		var next [][]string
		for _, prefix := range combos {
			for _, v := range values {
				next = append(next, append(slices.Clone(prefix), v))
			}
		}
		combos = next
	}
	for _, lv := range combos {
		switch c.m.Type {
		case Counter:
			ch <- prometheus.MustNewConstMetric(c.desc(), prometheus.CounterValue, 0, lv...)
		case Histogram:
			buckets := map[float64]uint64{}
			for _, b := range DurationBuckets {
				buckets[b] = 0
			}
			ch <- prometheus.MustNewConstHistogram(c.desc(), 0, 0, buckets, lv...)
		default:
			ch <- prometheus.MustNewConstMetric(c.desc(), prometheus.GaugeValue, 0, lv...)
		}
	}
}

func golden(t *testing.T, rel string, got []byte) {
	t.Helper()
	path := filepath.Join(repoRoot, rel)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(want, got) {
		t.Errorf("%s is stale; run go test ./internal/observability -update", rel)
	}
}

// The exposition golden pins the full contract: every family, help text,
// type and label combination as Prometheus serves it.
func TestContractExposition(t *testing.T) {
	families, err := contractRegistry(t).Gather()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, f := range families {
		if err := enc.Encode(f); err != nil {
			t.Fatal(err)
		}
	}
	if len(families) != len(Catalog) {
		t.Errorf("%d families exposed for %d catalog entries", len(families), len(Catalog))
	}
	golden(t, "testdata/observability/exposition.txt", buf.Bytes())
}

// The documented catalog table is generated from Catalog.
func TestCatalogDocumentation(t *testing.T) {
	var b strings.Builder
	b.WriteString("| Metric | Type | Labels | Meaning | Availability | Reset |\n| --- | --- | --- | --- | --- | --- |\n")
	for _, m := range Catalog {
		var labels []string
		for _, l := range m.Labels {
			if l.Values == nil {
				labels = append(labels, "`"+l.Name+"`")
			} else {
				labels = append(labels, fmt.Sprintf("`%s` (%s)", l.Name, strings.Join(l.Values, ", ")))
			}
		}
		typ := string(m.Type)
		if m.Unit != "" {
			typ += ", " + m.Unit
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s |\n", m.Name, typ, strings.Join(labels, "<br>"), m.Help, m.Availability, m.Reset)
	}
	doc, err := os.ReadFile(filepath.Join(repoRoot, "docs/integration/metrics.md"))
	if err != nil {
		t.Fatal(err)
	}
	const begin, end = "<!-- catalog:begin -->\n", "<!-- catalog:end -->"
	before, rest, ok := strings.Cut(string(doc), begin)
	_, after, ok2 := strings.Cut(rest, end)
	if !ok || !ok2 {
		t.Fatal("docs/integration/metrics.md lacks the catalog markers")
	}
	want := before + begin + b.String() + end + after
	if *update {
		if err := os.WriteFile(filepath.Join(repoRoot, "docs/integration/metrics.md"), []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if string(doc) != want {
		t.Error("docs/integration/metrics.md catalog table is stale; run go test ./internal/observability -update")
	}
}
