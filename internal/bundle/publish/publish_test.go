package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

const repoRoot = "../../.."

var testTime = time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)

// passRunner stands in for kyverno in unit tests; freeze_test.go runs the
// real CLI.
type passRunner struct{ ran [][]string }

func (*passRunner) Name() string                            { return "kyverno test --require-tests" }
func (*passRunner) Version(context.Context) (string, error) { return "v0.0.0-test", nil }
func (p *passRunner) Run(_ context.Context, root string, dirs []string) error {
	for _, d := range dirs {
		if _, err := os.Stat(filepath.Join(root, d, FixtureFile)); err != nil {
			return err
		}
	}
	p.ran = append(p.ran, dirs)
	return nil
}

func officialDefinition(t *testing.T) bundle.Definition {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, "bundles/konstapel-privileged-containers/definition.json"))
	if err != nil {
		t.Fatal(err)
	}
	def, err := bundle.LoadDefinition(raw)
	if err != nil {
		t.Fatal(err)
	}
	return def
}

// archiveCache holds built archives (read-only) per revision and time.
var archiveCache sync.Map

// frozenLayout builds the official bundle from this repository's content at
// a fictitious revision and source time and writes its OCI layout.
func frozenLayout(t *testing.T, revision string, when time.Time) string {
	t.Helper()
	key := revision + when.String()
	var a *bundle.Archive
	if v, ok := archiveCache.Load(key); ok {
		a = v.(*bundle.Archive)
	} else {
		def := officialDefinition(t)
		def.Source.Revision = revision
		var err error
		if a, err = bundle.Build(def, os.DirFS(repoRoot), when); err != nil {
			t.Fatal(err)
		}
		archiveCache.Store(key, a)
	}
	dir := filepath.Join(t.TempDir(), "bundle")
	if err := bundle.WriteLayout(dir, a); err != nil {
		t.Fatal(err)
	}
	return dir
}

func freezeInput() FreezeInput {
	return FreezeInput{DefinitionSHA256: strings.Repeat("ab", 32), Tools: []Tool{{Name: "go", Version: "go1.27.3"}}, Runner: &passRunner{}}
}

var frozenCache sync.Map

// frozenAt returns a frozen bundle for revision and source time, built once
// per test binary (building is slow under -race). Callers must not modify it.
func frozenAt(t *testing.T, revision string, when time.Time) *Frozen {
	t.Helper()
	key := revision + when.String()
	if f, ok := frozenCache.Load(key); ok {
		return f.(*Frozen)
	}
	f := freshFrozen(t, revision, when)
	frozenCache.Store(key, f)
	return f
}

func freshFrozen(t *testing.T, revision string, when time.Time) *Frozen {
	t.Helper()
	dir := frozenLayout(t, revision, when)
	if _, err := Freeze(context.Background(), dir, freezeInput()); err != nil {
		t.Fatal(err)
	}
	f, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

var (
	revA = strings.Repeat("a", 40)
	revB = strings.Repeat("b", 40)
)

type staticCreds map[string]registry.Credential

func (s staticCreds) Credential(_ context.Context, _ bundle.BundleSource, host string) (registry.Credential, error) {
	return s[host], nil
}

func newTarget(t *testing.T, f *faultRegistry) Target {
	t.Helper()
	limits := registry.Limits{RequestTimeout: 2 * time.Second}
	w, err := registry.NewClient(registry.Options{
		TestOnlyPlainHTTP: true, Limits: limits,
		Credentials: staticCreds{f.host(): {Username: f.user, Password: f.pass}},
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := registry.NewClient(registry.Options{TestOnlyPlainHTTP: true, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	return Target{Repository: f.repo(), Writer: w, Reader: r, ReadBackAttempts: 4, ReadBackDelay: 10 * time.Millisecond}
}

func states(res *Result) map[string]string {
	out := map[string]string{}
	for _, a := range res.Actions {
		out[a.Piece] = a.State
	}
	return out
}

func forBothListings(t *testing.T, fn func(t *testing.T, tagSchema bool)) {
	for _, tagSchema := range []bool{false, true} {
		t.Run(map[bool]string{false: "referrers API", true: "tag schema"}[tagSchema], func(t *testing.T) {
			fn(t, tagSchema)
		})
	}
}

// A first publication pushes every piece, the version tag last, then reads
// the subject back anonymously through the consumer's adapter.
func TestPublishCreatesTagLast(t *testing.T) {
	forBothListings(t, func(t *testing.T, tagSchema bool) {
		f := newFaultRegistry(t, tagSchema)
		fr := frozenAt(t, revA, testTime)
		res, err := Publish(context.Background(), fr, newTarget(t, f))
		if err != nil {
			t.Fatal(err)
		}
		if res.Outcome != Created || res.Digest != fr.ManifestDigest || res.Recovered {
			t.Fatalf("result %+v", res)
		}
		want := []string{"config", "layer", "manifest", "record-layer", "record", "tag"}
		var got []string
		for _, a := range res.Actions {
			got = append(got, a.Piece)
			if a.State != StatePushed {
				t.Errorf("%s: %s", a.Piece, a.State)
			}
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("actions %v, want %v", got, want)
		}
		// Request order: the version tag is the last write.
		writes := f.writes(0)
		last := writes[len(writes)-1]
		if last.Method != http.MethodPut || !strings.HasSuffix(last.Path, "/manifests/0.1.0") {
			t.Fatalf("last write %v; writes %v", last, writes)
		}
		tagPuts := 0
		for _, w := range writes {
			if strings.HasSuffix(w.Path, "/manifests/0.1.0") {
				tagPuts++
			}
		}
		if tagPuts != 1 {
			t.Fatalf("%d tag pushes", tagPuts)
		}
		if f.tag("0.1.0") != fr.ManifestDigest {
			t.Fatal("tag does not name the frozen subject")
		}
		if !res.ReadBack.Verified || !res.ReadBack.Anonymous || res.Complete {
			t.Fatalf("read back %+v complete %v", res.ReadBack, res.Complete)
		}
		if fmt.Sprint(res.Missing) != "[signature provenance]" {
			t.Fatalf("missing %v", res.Missing)
		}
		wantSource := registry.ReferrersFromAPI
		if tagSchema {
			wantSource = registry.ReferrersFromTagSchema
		}
		if res.ReadBack.ReferrersSource != wantSource {
			t.Fatalf("referrers source %q", res.ReadBack.ReferrersSource)
		}
		// The read-back after the tag was anonymous.
		sawTag := false
		for _, r := range f.log() {
			if r.Method == http.MethodPut && strings.HasSuffix(r.Path, "/manifests/0.1.0") {
				sawTag = true
			}
			if sawTag && r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/manifests/"+fr.ManifestDigest) && r.Auth {
				t.Fatalf("read-back of the subject carried credentials: %v", r)
			}
		}
	})
}

// A rerun of a complete publication writes nothing.
func TestPublishIsIdempotent(t *testing.T) {
	forBothListings(t, func(t *testing.T, tagSchema bool) {
		f := newFaultRegistry(t, tagSchema)
		fr := frozenAt(t, revA, testTime)
		tgt := newTarget(t, f)
		if _, err := Publish(context.Background(), fr, tgt); err != nil {
			t.Fatal(err)
		}
		from := len(f.log())
		res, err := Publish(context.Background(), fr, tgt)
		if err != nil {
			t.Fatal(err)
		}
		if res.Outcome != AlreadyPublished {
			t.Fatalf("outcome %s", res.Outcome)
		}
		for p, s := range states(res) {
			if s != StateExisting {
				t.Errorf("%s: %s", p, s)
			}
		}
		if w := f.writes(from); len(w) != 0 {
			t.Fatalf("rerun wrote %v", w)
		}
	})
}

// Each injected failure leaves the remote partial; the rerun completes
// exactly the missing pieces and never uploads or replaces existing ones
// (the registry fails the test on any re-upload, re-push or tag move).
func TestRecoveryAfterInjectedFailures(t *testing.T) {
	type fault struct {
		name string
		// hook fails the first matching request.
		match func(r *http.Request, fr *Frozen) bool
		do    func(w http.ResponseWriter, r *http.Request)
		// done are pieces the first run completed.
		done []string
	}
	status := func(code int) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			if code == http.StatusTooManyRequests {
				w.Header().Set("Retry-After", "1")
			}
			writeErr(w, code, "UNAVAILABLE", "injected")
		}
	}
	drop := func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 512)
		_, _ = r.Body.Read(buf) // part of the upload arrives
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	}
	// Consume the body so the server notices the client giving up.
	hang := func(w http.ResponseWriter, r *http.Request) { io.Copy(io.Discard, r.Body); <-r.Context().Done() }
	blobPut := func(d string) func(r *http.Request, fr *Frozen) bool {
		return func(r *http.Request, fr *Frozen) bool {
			return r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/blobs/uploads/") && r.URL.Query().Get("digest") == d
		}
	}
	manifestPut := func(r *http.Request, fr *Frozen) bool {
		return r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/manifests/"+fr.ManifestDigest)
	}
	recordPut := func(r *http.Request, fr *Frozen) bool {
		return r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/manifests/"+digestOf(recordManifest(fr)))
	}
	tagPut := func(r *http.Request, fr *Frozen) bool { return isTagPut(r, "0.1.0") }
	fr0 := frozenAt(t, revA, testTime)
	faults := []fault{
		{"connection dropped mid-upload of the layer", blobPut(fr0.LayerDigest), drop, []string{"config"}},
		{"503 on the layer upload", blobPut(fr0.LayerDigest), status(http.StatusServiceUnavailable), []string{"config"}},
		{"blobs accepted, manifest fails (500)", manifestPut, status(http.StatusInternalServerError), []string{"config", "layer"}},
		{"429 on the record", recordPut, status(http.StatusTooManyRequests), []string{"config", "layer", "manifest", "record-layer"}},
		{"manifest and record accepted, tag fails (500)", tagPut, status(http.StatusInternalServerError), []string{"config", "layer", "manifest", "record-layer", "record"}},
		{"tag request hangs until the request timeout", tagPut, hang, []string{"config", "layer", "manifest", "record-layer", "record"}},
		{"Nth request (the first write) fails", func(r *http.Request, _ *Frozen) bool { return r.Method == http.MethodPost }, status(http.StatusBadGateway), nil},
	}
	for _, fa := range faults {
		forBothListings(t, func(t *testing.T, tagSchema bool) {
			t.Run(fa.name, func(t *testing.T) {
				f := newFaultRegistry(t, tagSchema)
				fr := frozenAt(t, revA, testTime)
				tgt := newTarget(t, f)
				tgt.Writer, _ = registry.NewClient(registry.Options{
					TestOnlyPlainHTTP: true, Limits: registry.Limits{RequestTimeout: 300 * time.Millisecond},
					Credentials: staticCreds{f.host(): {Username: f.user, Password: f.pass}},
				})
				var once sync.Once
				f.setHook(func(w http.ResponseWriter, r *http.Request, _ int) bool {
					hit := false
					if fa.match(r, fr) {
						once.Do(func() { hit = true })
					}
					if hit {
						fa.do(w, r)
					}
					return hit
				})
				res, err := Publish(context.Background(), fr, tgt)
				if !errors.Is(err, ErrIncompleteRemote) {
					t.Fatalf("first run: %v", err)
				}
				if res.Outcome != "" || res.Complete {
					t.Fatalf("a failed run reported %s complete=%v", res.Outcome, res.Complete)
				}
				if f.tag("0.1.0") != "" {
					t.Fatal("the version tag exists although publication failed before it")
				}
				var done []string
				for _, a := range res.Actions {
					done = append(done, a.Piece)
				}
				if strings.Join(done, ",") != strings.Join(fa.done, ",") {
					t.Fatalf("first run completed %v, want %v", done, fa.done)
				}

				f.setHook(nil)
				res, err = Publish(context.Background(), fr, tgt)
				if err != nil {
					t.Fatal(err)
				}
				if res.Outcome != Created {
					t.Fatalf("outcome %s", res.Outcome)
				}
				st := states(res)
				for _, p := range []string{"config", "layer", "manifest", "record-layer", "record", "tag"} {
					want := StatePushed
					for _, d := range fa.done {
						if d == p {
							want = StateExisting
						}
					}
					if p == "record-layer" && want == StateExisting && st["record"] == StateExisting {
						want = "" // a listed record is not looked into again
					}
					if st[p] != want {
						t.Errorf("rerun %s: %s, want %s", p, st[p], want)
					}
				}
				if f.tag("0.1.0") != fr.ManifestDigest || !res.ReadBack.Verified {
					t.Fatal("rerun did not publish the frozen subject")
				}
			})
		})
	}
}

// Different bytes under the version tag: refused, nothing written.
func TestConflictingVersionIsRefused(t *testing.T) {
	forBothListings(t, func(t *testing.T, tagSchema bool) {
		f := newFaultRegistry(t, tagSchema)
		tgt := newTarget(t, f)
		if _, err := Publish(context.Background(), frozenAt(t, revA, testTime), tgt); err != nil {
			t.Fatal(err)
		}
		before, from := f.snapshot(), len(f.log())
		other := frozenAt(t, revB, testTime)
		_, err := Publish(context.Background(), other, tgt)
		if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), revA) {
			t.Fatalf("got %v", err)
		}
		if w := f.writes(from); len(w) != 0 || f.snapshot() != before {
			t.Fatalf("a refused publication wrote %v", w)
		}
	})
	t.Run("tag names a non-bundle manifest", func(t *testing.T) {
		f := newFaultRegistry(t, false)
		f.seedManifest([]byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{},"layers":[]}`), "0.1.0")
		from := len(f.log())
		_, err := Publish(context.Background(), frozenAt(t, revA, testTime), newTarget(t, f))
		if !errors.Is(err, ErrConflict) || len(f.writes(from)) != 0 {
			t.Fatalf("got %v, writes %v", err, f.writes(from))
		}
	})
}

// A tag created by another publisher between the first check and the tag
// push is detected by the re-check; the tag is never pushed over it.
func TestTagCreatedConcurrentlyIsNotOverwritten(t *testing.T) {
	f := newFaultRegistry(t, false)
	other := frozenAt(t, revB, testTime)
	f.seedBlob(other.Layer)
	f.seedBlob([]byte("{}"))
	otherDigest := f.seedManifest(other.Manifest, "")
	gets := 0
	var mu sync.Mutex
	f.setHook(func(w http.ResponseWriter, r *http.Request, _ int) bool {
		if isTagGet(r, "0.1.0") {
			mu.Lock()
			gets++
			if gets == 2 { // the re-check right before the push
				f.setTag("0.1.0", otherDigest)
			}
			mu.Unlock()
		}
		return false
	})
	_, err := Publish(context.Background(), frozenAt(t, revA, testTime), newTarget(t, f))
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("got %v", err)
	}
	for _, r := range f.log() {
		if r.Method == http.MethodPut && strings.HasSuffix(r.Path, "/manifests/0.1.0") {
			t.Fatal("the tag was pushed over a concurrently created tag")
		}
	}
	if f.tag("0.1.0") != otherDigest {
		t.Fatal("the other publisher's tag was changed")
	}
}

// A tag moved by someone else right after this run pushed it is reported,
// never moved back.
func TestTagMovedAfterPushIsAConflict(t *testing.T) {
	f := newFaultRegistry(t, false)
	other := frozenAt(t, revB, testTime)
	otherDigest := f.seedManifest(other.Manifest, "")
	pushed := false
	f.setHook(func(w http.ResponseWriter, r *http.Request, _ int) bool {
		if isTagGet(r, "0.1.0") && pushed {
			f.setTag("0.1.0", otherDigest)
		}
		if isTagPut(r, "0.1.0") {
			pushed = true
		}
		return false
	})
	_, err := Publish(context.Background(), frozenAt(t, revA, testTime), newTarget(t, f))
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "concurrently") {
		t.Fatalf("got %v", err)
	}
	puts := 0
	for _, r := range f.log() {
		if isTagPutReq(r) {
			puts++
		}
	}
	if puts != 1 {
		t.Fatalf("%d tag pushes", puts)
	}
}

func isTagPutReq(r request) bool {
	return r.Method == http.MethodPut && strings.HasSuffix(r.Path, "/manifests/0.1.0")
}

// Racing publishers of one version are serialized: with the same bytes one
// creates and the other finds it published; with different bytes exactly
// one wins and the other gets ErrConflict. The registry holds tag reads so
// that unserialized publishers would both see the tag absent.
func TestRacingPublishersAreSerialized(t *testing.T) {
	for _, same := range []bool{true, false} {
		t.Run(map[bool]string{true: "same bytes", false: "different bytes"}[same], func(t *testing.T) {
			f := newFaultRegistry(t, false)
			// Pair up tag reads: each waits (briefly) for another, so two
			// unserialized publishers would both read the tag as absent.
			var mu sync.Mutex
			var pending chan struct{}
			f.setHook(func(w http.ResponseWriter, r *http.Request, _ int) bool {
				if !isTagGet(r, "0.1.0") {
					return false
				}
				mu.Lock()
				if pending != nil {
					close(pending)
					pending = nil
					mu.Unlock()
					return false
				}
				ch := make(chan struct{})
				pending = ch
				mu.Unlock()
				select {
				case <-ch:
				case <-time.After(200 * time.Millisecond):
					mu.Lock()
					if pending == ch {
						pending = nil
					}
					mu.Unlock()
				}
				return false
			})
			a := frozenAt(t, revA, testTime)
			b := a
			if !same {
				b = frozenAt(t, revB, testTime)
			}
			tgt := newTarget(t, f)
			var wg sync.WaitGroup
			results := make([]*Result, 2)
			errs := make([]error, 2)
			for i, fr := range []*Frozen{a, b} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					results[i], errs[i] = Publish(context.Background(), fr, tgt)
				}()
			}
			wg.Wait()
			created, conflicts := 0, 0
			for i := range errs {
				switch {
				case errs[i] == nil && results[i].Outcome == Created:
					created++
				case errors.Is(errs[i], ErrConflict):
					conflicts++
				case errs[i] != nil:
					t.Fatalf("publisher %d: %v", i, errs[i])
				}
			}
			wantConflicts := 1
			if same {
				wantConflicts = 0
			}
			if created != 1 || conflicts != wantConflicts {
				t.Fatalf("created %d, conflicts %d; results %+v %+v; errs %v", created, conflicts, results[0], results[1], errs)
			}
			puts := 0
			for _, r := range f.log() {
				if isTagPutReq(r) {
					puts++
				}
			}
			if puts != 1 {
				t.Fatalf("%d tag pushes, want exactly 1", puts)
			}
		})
	}
}

// Read-back waits for a registry that has not yet made the push visible,
// but refuses one that serves other bytes, and reports a private package.
func TestReadBack(t *testing.T) {
	t.Run("eventually consistent", func(t *testing.T) {
		f := newFaultRegistry(t, false)
		fr := frozenAt(t, revA, testTime)
		misses := 0
		f.setHook(func(w http.ResponseWriter, r *http.Request, _ int) bool {
			if r.Header.Get("Authorization") == "" && r.Method == http.MethodGet &&
				strings.HasSuffix(r.URL.Path, "/manifests/"+fr.ManifestDigest) && misses < 2 {
				misses++
				writeErr(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "not yet")
				return true
			}
			return false
		})
		res, err := Publish(context.Background(), fr, newTarget(t, f))
		if err != nil {
			t.Fatal(err)
		}
		if res.ReadBack.Attempts != 3 || !res.ReadBack.Verified {
			t.Fatalf("read back %+v", res.ReadBack)
		}
	})
	for _, tc := range []struct {
		name string
		hook func(fr, other *Frozen) func(w http.ResponseWriter, r *http.Request, _ int) bool
	}{
		{"tag reads back as other bytes", func(fr, other *Frozen) func(w http.ResponseWriter, r *http.Request, _ int) bool {
			var pushed atomic.Bool
			return func(w http.ResponseWriter, r *http.Request, _ int) bool {
				if isTagPut(r, "0.1.0") {
					pushed.Store(true)
				}
				if pushed.Load() && r.Header.Get("Authorization") == "" && isTagGet(r, "0.1.0") {
					w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
					w.Header().Set("Docker-Content-Digest", other.ManifestDigest)
					w.Write(other.Manifest)
					return true
				}
				return false
			}
		}},
		{"layer reads back as other bytes", func(fr, other *Frozen) func(w http.ResponseWriter, r *http.Request, _ int) bool {
			return func(w http.ResponseWriter, r *http.Request, _ int) bool {
				if r.Header.Get("Authorization") == "" && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/blobs/"+fr.LayerDigest) {
					w.Header().Set("Content-Length", fmt.Sprint(len(fr.Layer)))
					w.Write(bytes.Repeat([]byte{'x'}, len(fr.Layer)))
					return true
				}
				return false
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFaultRegistry(t, false)
			fr := frozenAt(t, revA, testTime)
			f.setHook(tc.hook(fr, frozenAt(t, revB, testTime)))
			res, err := Publish(context.Background(), fr, newTarget(t, f))
			if !errors.Is(err, ErrReadBack) || res.Complete || res.ReadBack.Verified || res.ReadBack.Attempts != 1 {
				t.Fatalf("got %v, read back %+v", err, res.ReadBack)
			}
		})
	}
	t.Run("private package", func(t *testing.T) {
		f := newFaultRegistry(t, false)
		f.private = true
		fr := frozenAt(t, revA, testTime)
		tgt := newTarget(t, f)
		res, err := Publish(context.Background(), fr, tgt)
		if !errors.Is(err, ErrReadBack) || !errors.Is(err, registry.ErrUnauthorized) || !strings.Contains(err.Error(), "private") || res.Complete {
			t.Fatalf("got %v", err)
		}
		// After an owner makes it public, a rerun completes without writing.
		f.private = false
		from := len(f.log())
		res, err = Publish(context.Background(), fr, tgt)
		if err != nil || res.Outcome != AlreadyPublished || len(f.writes(from)) != 0 {
			t.Fatalf("rerun: %v %+v", err, res)
		}
	})
}

// signer is a ProofCompleter that attaches cosign-shaped referrers, as the
// release signer will, and can fail one kind.
type signer struct {
	w      *registry.Client
	fail   registry.ProofKind
	called [][]registry.ProofKind
}

func (s *signer) Complete(ctx context.Context, sub Subject, missing []registry.ProofKind) error {
	s.called = append(s.called, missing)
	sess, err := s.w.Open(ctx, bundle.BundleSource{Name: sub.Record.Name, Repository: sub.Repository, CredentialSecret: &PublisherCredential})
	if err != nil {
		return err
	}
	for _, k := range missing {
		if k == s.fail {
			return fmt.Errorf("injected %s failure", k)
		}
		pt := map[registry.ProofKind]string{registry.ProofSignature: registry.CosignSignPredicateType, registry.ProofProvenance: registry.SLSAProvenanceV1PredicateType}[k]
		layer := []byte(fmt.Sprintf(`{"mediaType":%q,"proof":%q}`, registry.SigstoreBundleArtifactType, k))
		ld := ocispec.Descriptor{MediaType: registry.SigstoreBundleArtifactType, Digest: digest.FromBytes(layer), Size: int64(len(layer))}
		if err := sess.Repository.Blobs().Push(ctx, ld, bytes.NewReader(layer)); err != nil {
			return err
		}
		m, _ := json.Marshal(map[string]any{
			"schemaVersion": 2, "mediaType": ocispec.MediaTypeImageManifest, "artifactType": registry.SigstoreBundleArtifactType,
			"config":      map[string]any{"mediaType": bundle.EmptyConfigMediaType, "digest": bundle.EmptyConfigDigest, "size": 2},
			"layers":      []any{ld},
			"subject":     map[string]any{"mediaType": ocispec.MediaTypeImageManifest, "digest": sub.Digest, "size": sub.Size},
			"annotations": map[string]string{registry.PredicateTypeAnnotation: pt},
		})
		md := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromBytes(m), Size: int64(len(m))}
		if err := sess.Repository.Manifests().Push(ctx, md, bytes.NewReader(m)); err != nil {
			return err
		}
	}
	return nil
}

// Missing proofs are completed on an already published subject without
// touching its bytes; a rerun after a failed proof adds only that proof.
func TestCompletionOfMissingProofs(t *testing.T) {
	forBothListings(t, func(t *testing.T, tagSchema bool) {
		f := newFaultRegistry(t, tagSchema)
		fr := frozenAt(t, revA, testTime)
		tgt := newTarget(t, f)
		s := &signer{w: tgt.Writer, fail: registry.ProofProvenance}
		tgt.Proofs = s
		res, err := Publish(context.Background(), fr, tgt)
		if !errors.Is(err, ErrIncompleteRemote) || res.Complete {
			t.Fatalf("got %v", err)
		}
		if f.tag("0.1.0") != fr.ManifestDigest {
			t.Fatal("subject not published before proofs")
		}
		manifestBefore := f.manifest(fr.ManifestDigest)

		s.fail = ""
		from := len(f.log())
		res, err = Publish(context.Background(), fr, tgt)
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(s.called[len(s.called)-1]) != "[provenance]" {
			t.Fatalf("completer asked for %v, want only the missing provenance", s.called)
		}
		if res.Outcome != Completed || !res.Complete || fmt.Sprint(res.ProofsAdded) != "[provenance]" || len(res.Missing) != 0 {
			t.Fatalf("result %+v", res)
		}
		for _, w := range f.writes(from) {
			if strings.HasSuffix(w.Path, "/manifests/"+fr.ManifestDigest) || strings.HasSuffix(w.Path, "/manifests/0.1.0") ||
				(strings.Contains(w.Path, "/blobs/uploads/") && strings.Contains(w.Query, strings.TrimPrefix(fr.LayerDigest, "sha256:"))) {
				t.Fatalf("completing proofs wrote the subject: %v", w)
			}
		}
		if !bytes.Equal(f.manifest(fr.ManifestDigest), manifestBefore) || f.tag("0.1.0") != fr.ManifestDigest {
			t.Fatal("subject changed")
		}
		// Everything present: nothing is asked or written.
		n := len(s.called)
		from = len(f.log())
		res, err = Publish(context.Background(), fr, tgt)
		if err != nil || res.Outcome != AlreadyPublished || !res.Complete || len(s.called) != n || len(f.writes(from)) != 0 {
			t.Fatalf("final rerun: %v %+v", err, res)
		}
	})
}

// A record added to a subject whose tag schema index already lists a
// signature keeps that entry; the old index is not deleted.
func TestRecordAddedBesideExistingReferrers(t *testing.T) {
	f := newFaultRegistry(t, true)
	fr := frozenAt(t, revA, testTime)
	tgt := newTarget(t, f)
	// Published by an earlier tool without a record, then signed.
	f.seedBlob([]byte("{}"))
	f.seedBlob(fr.Layer)
	f.seedManifest(fr.Manifest, "0.1.0")
	if err := (&signer{w: tgt.Writer}).Complete(context.Background(),
		Subject{Repository: tgt.Repository, Digest: fr.ManifestDigest, Size: int64(len(fr.Manifest)), Record: fr.Record},
		[]registry.ProofKind{registry.ProofSignature}); err != nil {
		t.Fatal(err)
	}
	res, err := Publish(context.Background(), fr, tgt)
	if err != nil {
		t.Fatal(err)
	}
	st := states(res)
	if res.Outcome != Completed || st["record"] != StatePushed || st["manifest"] != StateExisting || st["layer"] != StateExisting {
		t.Fatalf("result %+v", res)
	}
	if fmt.Sprint(res.Missing) != "[provenance]" || f.indexMoves != 1 {
		t.Fatalf("missing %v, index updates %d", res.Missing, f.indexMoves)
	}
}

// A version already published from the same source and content but other
// bytes (another toolchain) is adopted from its record, never replaced; without
// a record the original inputs cannot be established.
func TestRecoverRepackagedRelease(t *testing.T) {
	f := newFaultRegistry(t, false)
	tgt := newTarget(t, f)
	orig := frozenAt(t, revA, testTime)
	if _, err := Publish(context.Background(), orig, tgt); err != nil {
		t.Fatal(err)
	}
	repack := frozenAt(t, revA, testTime.Add(time.Hour))
	if repack.ManifestDigest == orig.ManifestDigest || repack.Record.ContentDigest != orig.Record.ContentDigest {
		t.Fatal("fixture: want different bytes with the same content")
	}
	from := len(f.log())
	res, err := Publish(context.Background(), repack, tgt)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Recovered || res.Outcome != AlreadyPublished || res.Digest != orig.ManifestDigest || res.Frozen.ManifestDigest != orig.ManifestDigest {
		t.Fatalf("result %+v", res)
	}
	if w := f.writes(from); len(w) != 0 {
		t.Fatalf("recovery wrote %v", w)
	}

	t.Run("without a record", func(t *testing.T) {
		f := newFaultRegistry(t, false)
		f.seedBlob([]byte("{}"))
		f.seedBlob(orig.Layer)
		f.seedManifest(orig.Manifest, "0.1.0")
		from := len(f.log())
		_, err := Publish(context.Background(), repack, newTarget(t, f))
		if !errors.Is(err, ErrFrozenInputs) || len(f.writes(from)) != 0 {
			t.Fatalf("got %v, writes %v", err, f.writes(from))
		}
	})
	t.Run("record for another definition", func(t *testing.T) {
		in := freezeInput()
		in.DefinitionSHA256 = strings.Repeat("cd", 32)
		dir := frozenLayout(t, revA, testTime.Add(time.Hour))
		other, err := Freeze(context.Background(), dir, in)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Publish(context.Background(), other, tgt)
		if !errors.Is(err, ErrFrozenInputs) {
			t.Fatalf("got %v", err)
		}
	})
}

// Credentials never appear in errors or results, even when the registry
// echoes them back.
func TestCredentialsAreRedacted(t *testing.T) {
	f := newFaultRegistry(t, false)
	fr := frozenAt(t, revA, testTime)
	f.setHook(func(w http.ResponseWriter, r *http.Request, _ int) bool {
		if r.Method == http.MethodPut && r.Header.Get("Authorization") != "" && strings.Contains(r.URL.Path, "/manifests/") {
			writeErr(w, http.StatusInternalServerError, "UNKNOWN", "echo: "+r.Header.Get("Authorization")+" pass="+f.pass)
			return true
		}
		return false
	})
	res, err := Publish(context.Background(), fr, newTarget(t, f))
	if !errors.Is(err, ErrIncompleteRemote) {
		t.Fatalf("got %v", err)
	}
	out, _ := json.Marshal(res)
	for _, leak := range []string{f.pass, "cHVibGlzaGVy"} {
		if strings.Contains(err.Error(), leak) || strings.Contains(string(out), leak) {
			t.Fatalf("credential leaked: %v / %s", err, out)
		}
	}
	if !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("expected redaction marker in %v", err)
	}
}

// No credential, no write: the writer never falls back to anonymous.
func TestWriterRequiresACredential(t *testing.T) {
	f := newFaultRegistry(t, false)
	tgt := newTarget(t, f)
	tgt.Writer, _ = registry.NewClient(registry.Options{TestOnlyPlainHTTP: true, Credentials: staticCreds{}})
	_, err := Publish(context.Background(), frozenAt(t, revA, testTime), tgt)
	if !errors.Is(err, registry.ErrCredentials) || len(f.log()) != 0 {
		t.Fatalf("got %v after %d requests", err, len(f.log()))
	}
}

// Cancellation stops publication and is reported as incomplete.
func TestCancellation(t *testing.T) {
	f := newFaultRegistry(t, false)
	fr := frozenAt(t, revA, testTime)
	ctx, cancel := context.WithCancel(context.Background())
	f.setHook(func(w http.ResponseWriter, r *http.Request, _ int) bool {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/manifests/"+fr.ManifestDigest) {
			io.Copy(io.Discard, r.Body)
			cancel()
			<-r.Context().Done()
			return true
		}
		return false
	})
	_, err := Publish(ctx, fr, newTarget(t, f))
	if !errors.Is(err, ErrIncompleteRemote) || !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if f.tag("0.1.0") != "" {
		t.Fatal("tag pushed after cancellation")
	}
}

// Publish refuses a Frozen whose bytes no longer match its record.
func TestPublishRechecksFrozenInputs(t *testing.T) {
	f := newFaultRegistry(t, false)
	fr := frozenAt(t, revA, testTime)
	bad := *fr
	bad.Layer = append([]byte(nil), fr.Layer...)
	bad.Layer[len(bad.Layer)/2] ^= 0xff
	if _, err := Publish(context.Background(), &bad, newTarget(t, f)); !errors.Is(err, ErrFrozenInputs) || len(f.log()) != 0 {
		t.Fatalf("got %v", err)
	}
	bad = *fr
	bad.Record.Tests.Result = "failed"
	if _, err := Publish(context.Background(), &bad, newTarget(t, f)); !errors.Is(err, ErrFrozenInputs) {
		t.Fatalf("got %v", err)
	}
	if _, err := Publish(context.Background(), nil, newTarget(t, f)); !errors.Is(err, ErrFrozenInputs) {
		t.Fatalf("got %v", err)
	}
}
