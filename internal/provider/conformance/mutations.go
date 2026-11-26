package conformance

import (
	"context"
	"encoding/json"
	"slices"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/internal/provider/projection"
)

// Deliberate regressions (add-assessment-provider-contract 4.3). Each
// mutation wraps a working provider with one semantic regression of a
// kind a real adapter could ship. RunMutations applies every mutation to
// every case that can expose it and requires the suite to report the
// mutation's own Kind, so each one fails for the right reason.

// mutant is a provider with some of its methods replaced.
type mutant struct {
	Provider
	inventory       func(json.RawMessage) ([]Expectation, error)
	evaluate        func(json.RawMessage, time.Time) (Evaluation, error)
	withoutEvidence func(json.RawMessage) (json.RawMessage, error)
	collect         func(context.Context, client.Reader, json.RawMessage) (json.RawMessage, []string, error)
	retain          func(json.RawMessage) ([]byte, error)
	replay          func([]byte, Content) (json.RawMessage, error)
	extract         func(json.RawMessage, projection.Scope) (json.RawMessage, error)
}

func (m *mutant) Inventory(in json.RawMessage) ([]Expectation, error) {
	if m.inventory != nil {
		return m.inventory(in)
	}
	return m.Provider.Inventory(in)
}

func (m *mutant) Evaluate(in json.RawMessage, at time.Time) (Evaluation, error) {
	if m.evaluate != nil {
		return m.evaluate(in, at)
	}
	return m.Provider.Evaluate(in, at)
}

func (m *mutant) WithoutEvidence(in json.RawMessage) (json.RawMessage, error) {
	if m.withoutEvidence != nil {
		return m.withoutEvidence(in)
	}
	return m.Provider.WithoutEvidence(in)
}

func (m *mutant) Collect(ctx context.Context, c client.Reader, in json.RawMessage) (json.RawMessage, []string, error) {
	if m.collect != nil {
		return m.collect(ctx, c, in)
	}
	return m.Provider.Collect(ctx, c, in)
}

func (m *mutant) Retain(in json.RawMessage) ([]byte, error) {
	if m.retain != nil {
		return m.retain(in)
	}
	return m.Provider.Retain(in)
}

func (m *mutant) Replay(r []byte, content Content) (json.RawMessage, error) {
	if m.replay != nil {
		return m.replay(r, content)
	}
	return m.Provider.Replay(r, content)
}

func (m *mutant) Extract(in json.RawMessage, ns projection.Scope) (json.RawMessage, error) {
	if m.extract != nil {
		return m.extract(in, ns)
	}
	return m.Provider.Extract(in, ns)
}

// baseline is what the unmutated provider gives for a case.
type baseline struct {
	c          Case
	inv        []Expectation
	ev         Evaluation
	namespaces []projection.Scope
	// requests is the number of read requests its collection makes.
	requests int
	// extracted reports whether some namespace extract has evidence that
	// changes its evaluation.
	extracted bool
}

func (b baseline) has(f func(Observation) bool) bool {
	return slices.ContainsFunc(b.ev.Observations, f)
}

func (b baseline) attributable() bool {
	return b.has(func(o Observation) bool { return o.State == Attributable })
}

// evidenced reports whether the case's evidence changes its evaluation.
func (b baseline) evidenced() bool {
	return b.has(func(o Observation) bool { return o.State == Attributable || o.State == Rejected })
}

// mutation is one deliberate regression.
type mutation struct {
	name string
	want Kind
	// exposes reports whether the case can show the regression.
	exposes func(baseline) bool
	mutate  func(*mutant, baseline)
}

func always(baseline) bool { return true }

// mapped replaces Evaluate with the provider's evaluation, changed by f.
func mapped(f func(Evaluation, time.Time) Evaluation) func(*mutant, baseline) {
	return func(m *mutant, _ baseline) {
		m.evaluate = func(in json.RawMessage, at time.Time) (Evaluation, error) {
			ev, err := m.Provider.Evaluate(in, at)
			if err != nil {
				return ev, err
			}
			ev.Observations = slices.Clone(ev.Observations)
			return f(ev, at), nil
		}
	}
}

// each changes every observation with f.
func each(f func(*Observation, time.Time)) func(*mutant, baseline) {
	return mapped(func(ev Evaluation, at time.Time) Evaluation {
		for i := range ev.Observations {
			f(&ev.Observations[i], at)
		}
		return ev
	})
}

// credit makes an observation attributable with a passing outcome.
func credit(o *Observation, evaluated time.Time) {
	o.State, o.Raw, o.Outcome, o.NotApplicable, o.Evaluated = Attributable, "mutant-pass", Pass, false, &evaluated
}

func mutations() []mutation {
	return []mutation{
		// Evaluation.
		{"drops missing observations", KindDropped,
			func(b baseline) bool { return b.has(func(o Observation) bool { return o.State == Missing }) },
			mapped(func(ev Evaluation, _ time.Time) Evaluation {
				ev.Observations = slices.DeleteFunc(ev.Observations, func(o Observation) bool { return o.State == Missing })
				return ev
			})},
		{"missing evidence passes", KindMissingEvidence, func(b baseline) bool { return len(b.inv) > 0 },
			each(func(o *Observation, at time.Time) {
				if o.State == Missing {
					credit(o, at.Add(-time.Minute))
				}
			})},
		{"inventory from evidence", KindIndependence, func(b baseline) bool { return len(b.inv) > 0 },
			func(m *mutant, _ baseline) {
				var mu sync.Mutex
				bare := map[string]bool{}
				m.withoutEvidence = func(in json.RawMessage) (json.RawMessage, error) {
					out, err := m.Provider.WithoutEvidence(in)
					mu.Lock()
					bare[string(out)] = true
					mu.Unlock()
					return out, err
				}
				m.inventory = func(in json.RawMessage) ([]Expectation, error) {
					mu.Lock()
					defer mu.Unlock()
					if bare[string(in)] {
						return nil, nil
					}
					return m.Provider.Inventory(in)
				}
			}},
		{"inventory repeats an entry", KindInventory, func(b baseline) bool { return len(b.inv) > 0 },
			func(m *mutant, _ baseline) {
				m.inventory = func(in json.RawMessage) ([]Expectation, error) {
					inv, err := m.Provider.Inventory(in)
					if len(inv) > 0 {
						inv = append(slices.Clone(inv), inv[0])
					}
					return inv, err
				}
			}},
		{"outcome outside the vocabulary", KindNormalizedOutcome, baseline.attributable,
			each(func(o *Observation, _ time.Time) {
				if o.State == Attributable {
					o.Outcome = "accepted-risk"
				}
			})},
		{"unknown outcome counted as pass", KindGolden,
			func(b baseline) bool {
				return b.has(func(o Observation) bool { return o.State == Attributable && o.Outcome == Unknown && !o.NotApplicable })
			},
			each(func(o *Observation, _ time.Time) {
				if o.State == Attributable && o.Outcome == Unknown && !o.NotApplicable {
					o.Outcome = Pass
				}
			})},
		{"not applicable counted as an outcome", KindGolden,
			func(b baseline) bool { return b.has(func(o Observation) bool { return o.NotApplicable }) },
			each(func(o *Observation, _ time.Time) { o.NotApplicable = false })},
		{"rejected evidence carries an outcome", KindOutcomeWithoutEvidence,
			func(b baseline) bool { return b.has(func(o Observation) bool { return o.State == Rejected }) },
			each(func(o *Observation, _ time.Time) {
				if o.State == Rejected {
					o.Outcome = Fail
				}
			})},
		{"unresolved treated as attributable", KindGolden,
			func(b baseline) bool { return b.has(func(o Observation) bool { return o.State == Unresolved }) },
			each(func(o *Observation, at time.Time) {
				if o.State == Unresolved {
					credit(o, at)
				}
			})},
		{"raw outcome dropped", KindRawOutcome, baseline.attributable,
			each(func(o *Observation, _ time.Time) { o.Raw = "" })},
		{"report update time as freshness", KindSourceTime, baseline.attributable,
			each(func(o *Observation, at time.Time) {
				if o.Evaluated != nil {
					t := at.Add(time.Second)
					o.Evaluated = &t
				}
			})},
		{"evaluation time ignored", KindStaleEvidence, baseline.attributable,
			func(m *mutant, b baseline) {
				m.evaluate = func(in json.RawMessage, _ time.Time) (Evaluation, error) {
					return m.Provider.Evaluate(in, b.c.EvaluationTime)
				}
			}},
		{"duplicate credit", KindDuplicate, func(b baseline) bool { return len(b.ev.Observations) > 0 },
			mapped(func(ev Evaluation, _ time.Time) Evaluation {
				if len(ev.Observations) > 0 {
					ev.Observations = append(ev.Observations, ev.Observations[0])
				}
				return ev
			})},
		{"invented observation", KindUnexpected, always,
			mapped(func(ev Evaluation, _ time.Time) Evaluation {
				ev.Observations = append(ev.Observations, Observation{Subject: "mutant/invented", Check: "mutant", State: Missing})
				return ev
			})},
		{"inconsistent normalization", KindNormalization,
			func(b baseline) bool {
				seen := map[string]bool{}
				return b.has(func(o Observation) bool {
					dup := o.State == Attributable && seen[o.Raw]
					seen[o.Raw] = seen[o.Raw] || o.State == Attributable
					return dup
				})
			},
			mapped(func(ev Evaluation, _ time.Time) Evaluation {
				seen := map[string]bool{}
				for i, o := range ev.Observations {
					if o.State != Attributable {
						continue
					}
					if seen[o.Raw] {
						ev.Observations[i].Outcome = map[Outcome]Outcome{Pass: Fail}[o.Outcome]
						if ev.Observations[i].Outcome == "" {
							ev.Observations[i].Outcome = Pass
						}
						break
					}
					seen[o.Raw] = true
				}
				return ev
			})},
		{"unknown state", KindState, func(b baseline) bool { return len(b.inv) > 0 },
			each(func(o *Observation, _ time.Time) {
				if o.State == Missing {
					o.State = "Pending"
				}
			})},
		{"nondeterministic", KindNondeterministic, always,
			func(m *mutant, _ baseline) {
				var mu sync.Mutex
				calls := 0
				mapped(func(ev Evaluation, _ time.Time) Evaluation {
					mu.Lock()
					defer mu.Unlock()
					calls++
					ev.StaleScopes += calls % 2
					return ev
				})(m, baseline{})
			}},
		{"stale scope invented", KindGolden, always,
			mapped(func(ev Evaluation, _ time.Time) Evaluation { ev.StaleScopes++; return ev })},

		// Lifecycle.
		{"collection ignores cancellation", KindCancellation, always,
			func(m *mutant, _ baseline) {
				m.collect = func(ctx context.Context, c client.Reader, in json.RawMessage) (json.RawMessage, []string, error) {
					return m.Provider.Collect(context.WithoutCancel(ctx), c, in)
				}
			}},
		{"collection writes", KindWrite, always,
			func(m *mutant, _ baseline) {
				m.collect = func(ctx context.Context, c client.Reader, in json.RawMessage) (json.RawMessage, []string, error) {
					if w, ok := c.(client.Writer); ok {
						job := &unstructured.Unstructured{}
						job.SetAPIVersion("scanner.example.io/v1")
						job.SetKind("ScanJob")
						job.SetNamespace("default")
						job.SetName("mutant-scan")
						_ = w.Create(ctx, job)
					}
					return m.Provider.Collect(ctx, c, in)
				}
			}},
		{"collection drops evidence", KindCollection, func(b baseline) bool { return b.evidenced() },
			func(m *mutant, _ baseline) {
				m.collect = func(ctx context.Context, c client.Reader, in json.RawMessage) (json.RawMessage, []string, error) {
					out, limits, err := m.Provider.Collect(ctx, c, in)
					if err != nil || out == nil {
						return out, limits, err
					}
					bare, err := m.Provider.WithoutEvidence(out)
					return bare, limits, err
				}
			}},
		{"collection reuses the input's evidence", KindMissingEvidence, func(b baseline) bool { return b.evidenced() },
			func(m *mutant, _ baseline) {
				m.collect = func(ctx context.Context, c client.Reader, in json.RawMessage) (json.RawMessage, []string, error) {
					if _, _, err := m.Provider.Collect(ctx, c, in); err != nil {
						return nil, nil, err
					}
					return in, nil, nil
				}
			}},
		{"source failure hidden", KindUnavailableSource, func(b baseline) bool { return b.requests > 0 },
			func(m *mutant, _ baseline) {
				m.collect = func(ctx context.Context, c client.Reader, in json.RawMessage) (json.RawMessage, []string, error) {
					out, _, err := m.Provider.Collect(ctx, c, in)
					return out, nil, err
				}
			}},
		{"retention drops evidence", KindReplay, func(b baseline) bool { return b.evidenced() },
			func(m *mutant, _ baseline) {
				m.retain = func(in json.RawMessage) ([]byte, error) {
					bare, err := m.Provider.WithoutEvidence(in)
					if err != nil {
						return nil, err
					}
					return m.Provider.Retain(bare)
				}
			}},
		{"replay substitutes unavailable content", KindContent, always,
			func(m *mutant, _ baseline) {
				m.replay = func(r []byte, _ Content) (json.RawMessage, error) { return m.Provider.Replay(r, ContentRetained) }
			}},

		// Projection.
		{"extract discloses the whole payload", KindProjection, func(b baseline) bool { return len(b.namespaces) > 0 },
			func(m *mutant, _ baseline) {
				m.extract = func(in json.RawMessage, _ projection.Scope) (json.RawMessage, error) { return in, nil }
			}},
		{"extract drops evidence", KindProjection, func(b baseline) bool { return b.extracted },
			func(m *mutant, _ baseline) {
				m.extract = func(in json.RawMessage, ns projection.Scope) (json.RawMessage, error) {
					ext, err := m.Provider.Extract(in, ns)
					if err != nil {
						return nil, err
					}
					return m.Provider.WithoutEvidence(ext)
				}
			}},
		{"unknown scope projected", KindProjection, func(b baseline) bool { return len(b.namespaces) > 0 },
			func(m *mutant, b baseline) {
				m.extract = func(in json.RawMessage, ns projection.Scope) (json.RawMessage, error) {
					if ns.UID == "" {
						ns = b.namespaces[0]
					}
					return m.Provider.Extract(in, ns)
				}
			}},
	}
}

// Mutations are the names of the deliberate regressions RunMutations
// applies.
func Mutations() []string {
	var out []string
	for _, m := range mutations() {
		out = append(out, m.name)
	}
	return out
}

// suite is every check Run makes of a case.
func suite(p Provider, c Case, want Expected) []error {
	return slices.Concat(Verify(p, c, want), CheckLifecycle(p, c), CheckProjection(p, c))
}

// RunMutations proves the suite catches deliberate regressions of the
// provider over its cases under root. The unmodified provider must pass
// every case. Then each mutation is applied to every case that can expose
// it, and the suite must report the mutation's own Kind for each; every
// mutation must be exposed by at least one case.
func RunMutations(t *testing.T, p Provider, root string) {
	t.Helper()
	dirs, err := Dirs(root)
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no conformance cases under %s: %v", root, err)
	}
	type loaded struct {
		dir  string
		c    Case
		want Expected
		b    baseline
	}
	var cases []loaded
	for _, dir := range dirs {
		c, want, err := Load(dir)
		if err != nil || want == nil {
			t.Fatalf("%s: %v (golden present: %t)", dir, err, want != nil)
		}
		if errs := suite(p, c, *want); len(errs) > 0 {
			t.Fatalf("%s: the unmodified provider fails: %v", dir, errs)
		}
		cases = append(cases, loaded{dir: dir, c: c, want: *want, b: baselineOf(t, p, c)})
	}
	for _, m := range mutations() {
		t.Run(m.name, func(t *testing.T) {
			exposed := 0
			for _, x := range cases {
				if !m.exposes(x.b) {
					continue
				}
				exposed++
				mp := &mutant{Provider: p}
				m.mutate(mp, x.b)
				kinds := Kinds(suite(mp, x.c, x.want))
				if !slices.Contains(kinds, m.want) {
					t.Errorf("%s: the suite reported %q, want %q", x.dir, kinds, m.want)
				}
			}
			if exposed == 0 {
				t.Errorf("no case under %s exposes this regression; add one", root)
			}
		})
	}
}

func baselineOf(t *testing.T, p Provider, c Case) baseline {
	t.Helper()
	b := baseline{c: c}
	var err error
	if b.inv, err = p.Inventory(c.Input); err != nil {
		t.Fatal(err)
	}
	ev, err := p.Evaluate(c.Input, c.EvaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	b.ev = normalize(ev)
	if b.namespaces, err = p.Namespaces(c.Input); err != nil {
		t.Fatal(err)
	}
	cluster, _, err := p.Cluster(c.Input)
	if err != nil {
		t.Fatal(err)
	}
	rec := NewRecordingClient(cluster)
	if _, _, err := p.Collect(context.Background(), rec, c.Input); err != nil {
		t.Fatal(err)
	}
	b.requests = reads(rec)
	for _, ns := range b.namespaces {
		ext, err := p.Extract(c.Input, ns)
		if err != nil {
			t.Fatal(err)
		}
		bare, err := p.WithoutEvidence(ext)
		if err != nil {
			t.Fatal(err)
		}
		e1, err1 := p.Evaluate(ext, c.EvaluationTime)
		e2, err2 := p.Evaluate(bare, c.EvaluationTime)
		if err1 != nil || err2 != nil {
			t.Fatal(err1, err2)
		}
		if !sameJSON(normalize(e1), normalize(e2)) {
			b.extracted = true
		}
	}
	return b
}
