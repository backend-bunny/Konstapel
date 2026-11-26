package conformance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/internal/provider/projection"
)

// The lifecycle and projection suites (add-assessment-provider-contract
// 4.3). Check covers a provider's evaluation of frozen inputs. These cover
// the rest of a provider's path through the host, for the same cases:
// collecting the case's evidence from a cluster that serves it, a canceled
// or failing collection, removal of the source, retention and replay
// without the source, unavailable run content, and namespace projection.

// Content is the state of the run's retained content when a capture is
// replayed.
type Content int

const (
	// ContentRetained: the content the run froze is available.
	ContentRetained Content = iota
	// ContentUnavailable: the run's content cannot be resolved (it was
	// never packaged, or is lost). Replay must fail; nothing is
	// substituted.
	ContentUnavailable
)

// ErrContentUnavailable is the error a replay with unavailable content
// must wrap.
var ErrContentUnavailable = errors.New("the run's retained content is unavailable")

// Lifecycle drives a provider's collection, retention and replay through
// the host's own code paths. Inputs are the provider's case inputs.
type Lifecycle interface {
	// Cluster is a cluster serving exactly the input's source evidence:
	// a client over it and the source objects it holds.
	Cluster(input json.RawMessage) (client.Client, []client.Object, error)
	// Collect collects the input's frozen scope from c as the host does
	// (provider.Collect with the host's default limits) and returns the
	// input with the collected evidence in place of its own, and the
	// collection's limitations. A canceled collection returns the
	// cancellation and nothing else.
	Collect(ctx context.Context, c client.Reader, input json.RawMessage) (json.RawMessage, []string, error)
	// Retain freezes a collected input as the run retains it: the
	// provider's capture, written as the provider writes it, and the
	// content the run froze for it.
	Retain(input json.RawMessage) ([]byte, error)
	// Replay reads a retained capture back through the capture boundary
	// and resolves the run's content (in the given state) as replay does,
	// with no cluster, and returns the replayed input. With content
	// unavailable it fails with an error wrapping ErrContentUnavailable.
	Replay(retained []byte, content Content) (json.RawMessage, error)
}

// Projector is a provider's namespace projection through the host's
// dispatch (collector.CaptureDocument.ProjectNamespace and
// ValidateNamespace).
type Projector interface {
	// Namespaces are the namespace instances the input's frozen scope
	// covers.
	Namespaces(input json.RawMessage) ([]projection.Scope, error)
	// Extract is the input projected to ns: the provider's extraction,
	// checked by the shared projection check.
	Extract(input json.RawMessage, ns projection.Scope) (json.RawMessage, error)
	// Validate is the host's check that an extract may be disclosed in
	// ns. It wraps projection.ErrDisclosure when it refuses.
	Validate(extract json.RawMessage, ns projection.Scope) error
}

// Provider is everything the shared conformance suite drives: evaluation,
// lifecycle and projection. Run requires all of it, so no provider passes
// conformance on evaluation alone.
type Provider interface {
	Adapter
	Lifecycle
	Projector
}

// injected is the source failure the unavailable-source scenario injects.
var injected = errors.New("injected source failure")

// reads counts the read requests a collection made.
func reads(rec *RecordingClient) int {
	n := 0
	for _, c := range rec.Calls() {
		if !c.Write() {
			n++
		}
	}
	return n
}

// writes reports the write requests a collection made.
func writes(rec *RecordingClient, what string) []error {
	if w := rec.Writes(); len(w) > 0 {
		return []error{violation(KindWrite, "%s collection made %d write requests, first %+v; collection is read-only", what, len(w), w[0])}
	}
	return nil
}

// CheckLifecycle runs the case through the provider's collection,
// retention and replay:
//
//   - collected from a cluster serving the case's evidence, the evidence
//     evaluates exactly as the case's own does, with no write;
//   - a collection canceled before or during its reads returns the
//     cancellation, with no result and no limitation;
//   - a source whose every request fails is a limitation, and nothing is
//     attributable or has an outcome;
//   - after the source objects are removed, collection finds no evidence:
//     every observation is Missing (or Unresolved), as without evidence;
//   - the retained capture, replayed after that removal, evaluates exactly
//     as the collection it retained did;
//   - replayed with the run's content unavailable, it fails as unavailable
//     content and returns nothing.
func CheckLifecycle(p Provider, c Case) []error {
	var errs []error
	fail := func(k Kind, format string, args ...any) { errs = append(errs, violation(k, format, args...)) }
	at := c.EvaluationTime
	evaluate := func(input json.RawMessage) (Evaluation, error) {
		ev, err := p.Evaluate(input, at)
		return normalize(ev), err
	}
	want, err := evaluate(c.Input)
	if err != nil {
		fail(KindEvaluate, "evaluate: %v", err)
		return errs
	}
	inv, err := p.Inventory(c.Input)
	if err != nil {
		fail(KindInventory, "inventory: %v", err)
		return errs
	}
	cluster, sources, err := p.Cluster(c.Input)
	if err != nil {
		fail(KindCollection, "cluster: %v", err)
		return errs
	}

	// Collected from a cluster that serves the case's evidence.
	rec := NewRecordingClient(cluster)
	collected, _, err := p.Collect(context.Background(), rec, c.Input)
	if err != nil {
		fail(KindCollection, "collect: %v", err)
		return errs
	}
	requests := reads(rec)
	errs = append(errs, writes(rec, "the")...)
	got, err := evaluate(collected)
	switch {
	case err != nil:
		fail(KindCollection, "evaluate the collected evidence: %v", err)
	case !sameJSON(got, want):
		fail(KindCollection, "the evidence collected from a cluster serving the case's evidence evaluates differently from the case")
	}

	// Canceled before any read, and while reading.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec = NewRecordingClient(cluster)
	errs = append(errs, canceled(ctx, p, rec, c.Input, "a collection canceled before it started")...)
	if requests > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		rec = NewRecordingClient(cluster)
		rec.Fail = func(Call) error { cancel(); return ctx.Err() }
		errs = append(errs, canceled(ctx, p, rec, c.Input, "a collection canceled at its first request")...)
		cancel()
	}

	// A source whose every request fails.
	if requests > 0 {
		rec = NewRecordingClient(cluster)
		rec.Fail = func(Call) error { return injected }
		failed, limits, err := p.Collect(context.Background(), rec, c.Input)
		errs = append(errs, writes(rec, "a failing source's")...)
		switch {
		case err != nil:
			fail(KindUnavailableSource, "a failing source failed the collection (%v); it is a limitation of the evidence, not of the provider", err)
		case len(limits) == 0:
			fail(KindUnavailableSource, "a failing source was not recorded as a limitation")
		default:
			ev, err := evaluate(failed)
			if err != nil {
				fail(KindUnavailableSource, "evaluate a failing source's collection: %v", err)
				break
			}
			for _, o := range ev.Observations {
				if o.State == Attributable {
					fail(KindUnavailableSource, "%s / %s is attributable although its source failed", o.Subject, o.Check)
				}
			}
		}
	}

	// Retained, then the source removed.
	retained, err := p.Retain(collected)
	if err != nil {
		fail(KindReplay, "retain: %v", err)
		return errs
	}
	for _, o := range sources {
		if err := cluster.Delete(context.Background(), o); err != nil {
			fail(KindCollection, "remove source %s/%s: %v", o.GetNamespace(), o.GetName(), err)
			return errs
		}
	}
	bare, err := p.WithoutEvidence(c.Input)
	if err != nil {
		fail(KindEvaluate, "without evidence: %v", err)
		return errs
	}
	bareEv, err := evaluate(bare)
	if err != nil {
		fail(KindEvaluate, "evaluate without evidence: %v", err)
		return errs
	}
	rec = NewRecordingClient(cluster)
	recollected, _, err := p.Collect(context.Background(), rec, c.Input)
	errs = append(errs, writes(rec, "the source-removed")...)
	if err != nil {
		fail(KindMissingEvidence, "collect after the source was removed: %v", err)
	} else if ev, err := evaluate(recollected); err != nil {
		fail(KindMissingEvidence, "evaluate the collection after the source was removed: %v", err)
	} else {
		errs = append(errs, missingErrors("after the source was removed", inv, ev)...)
		if !sameJSON(ev, bareEv) {
			fail(KindMissingEvidence, "collection after the source was removed evaluates differently from the case without evidence")
		}
	}

	// Replayed without the source, with and without the run's content.
	replayed, err := p.Replay(retained, ContentRetained)
	if err != nil {
		fail(KindReplay, "replay after the source was removed: %v", err)
	} else if ev, err := evaluate(replayed); err != nil {
		fail(KindReplay, "evaluate the replay: %v", err)
	} else if !sameJSON(ev, got) {
		fail(KindReplay, "the replay after the source was removed evaluates differently from the collection it retained")
	}
	lost, err := p.Replay(retained, ContentUnavailable)
	switch {
	case err == nil:
		fail(KindContent, "replay with the run's content unavailable succeeded; content is never substituted")
	case !errors.Is(err, ErrContentUnavailable):
		fail(KindContent, "replay with the run's content unavailable failed for another reason: %v", err)
	case lost != nil:
		fail(KindContent, "replay with the run's content unavailable returned an input")
	}
	return errs
}

func canceled(ctx context.Context, p Provider, rec *RecordingClient, input json.RawMessage, what string) []error {
	got, limits, err := p.Collect(ctx, rec, input)
	errs := writes(rec, what+"'s")
	if !errors.Is(err, context.Canceled) || got != nil || limits != nil {
		errs = append(errs, violation(KindCancellation, "%s returned %d bytes, limitations %q and error %v; want only the cancellation", what, len(got), limits, err))
	}
	return errs
}

// CheckProjection projects the case to every namespace instance of its
// frozen scope:
//
//   - each extract passes the host's shared check for its namespace, and
//     is refused (projection.ErrDisclosure) for every other one when it
//     discloses anything;
//   - the extracts' expected observations are the case's, and no two
//     namespaces disclose the same one;
//   - every observation an extract evaluates is the case's own: projection
//     never changes a result;
//   - a scope that names no namespace instance is refused.
func CheckProjection(p Provider, c Case) []error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, violation(KindProjection, format, args...)) }
	namespaces, err := p.Namespaces(c.Input)
	if err != nil {
		fail("namespaces: %v", err)
		return errs
	}
	inv, err := p.Inventory(c.Input)
	if err != nil {
		return append(errs, violation(KindInventory, "inventory: %v", err))
	}
	full, err := p.Evaluate(c.Input, c.EvaluationTime)
	if err != nil {
		return append(errs, violation(KindEvaluate, "evaluate: %v", err))
	}
	byKey := map[Expectation]Observation{}
	for _, o := range normalize(full).Observations {
		byKey[Expectation{Subject: o.Subject, Check: o.Check}] = o
	}
	disclosedIn := map[Expectation]string{}
	for i, ns := range namespaces {
		name := fmt.Sprintf("namespace %d", i)
		if ns.UID == "" {
			fail("%s of the frozen scope names no namespace instance", name)
			continue
		}
		ext, err := p.Extract(c.Input, ns)
		if err != nil {
			fail("%s: extract: %v", name, err)
			continue
		}
		if err := p.Validate(ext, ns); err != nil {
			fail("%s: the shared check refuses its own extract: %v", name, err)
			continue
		}
		extInv, err := p.Inventory(ext)
		if err != nil {
			fail("%s: the extract's inventory: %v", name, err)
			continue
		}
		for _, e := range extInv {
			if !slices.Contains(inv, e) {
				fail("%s discloses %s / %s, which the case does not expect", name, e.Subject, e.Check)
			}
			if other, ok := disclosedIn[e]; ok {
				fail("%s / %s is disclosed in both %s and %s", e.Subject, e.Check, other, name)
			}
			disclosedIn[e] = name
		}
		for j, other := range namespaces {
			if j == i || len(extInv) == 0 {
				continue
			}
			if err := p.Validate(ext, other); !errors.Is(err, projection.ErrDisclosure) {
				fail("the extract for %s is not refused in namespace %d: %v", name, j, err)
			}
		}
		ev, err := p.Evaluate(ext, c.EvaluationTime)
		if err != nil {
			fail("%s: evaluate the extract: %v", name, err)
			continue
		}
		for _, o := range normalize(ev).Observations {
			if want, ok := byKey[Expectation{Subject: o.Subject, Check: o.Check}]; ok && !sameJSON(o, want) {
				fail("%s: projection changes %s / %s from %s %q to %s %q", name, o.Subject, o.Check, want.State, want.Raw, o.State, o.Raw)
			}
		}
	}
	if len(namespaces) > 0 {
		if ext, err := p.Extract(c.Input, projection.Scope{}); err == nil || ext != nil {
			fail("a scope that names no namespace instance was projected (%v)", err)
		}
	}
	return errs
}
