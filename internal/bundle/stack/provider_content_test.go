package stack_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle/stack"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// A published OCI run replays from its package alone (task 3.2): after
// the cache and the registry are lost, the retained capture, read through
// the boundary with the production registry, resolves to exactly the
// packaged frozen copy of its applied bundle, never the live, desired or
// vendored content.
func TestOCIRunReplaysFromPackageAfterEviction(t *testing.T) {
	t.Parallel()
	w := stack.NewWorld(t)
	rc := newRunCluster(t, w.Stack.Router(stack.LocalContent(), stack.VendoredName), w.Ref())
	rc.deliver()
	run := rc.start()
	rc.report(runT0.Add(time.Minute))
	run = rc.finish(run.Name)
	dir, d := rc.pkg(run)
	f := requireBundleExport(t, dir, d, w.Ref())

	w.Fetch.Down.Store(true)
	if err := w.Stack.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(w.Opts.CacheDir); err != nil {
		t.Fatal(err)
	}
	w.Open()
	if _, err := w.Stack.Router(stack.LocalContent(), stack.VendoredName).Content(context.Background(), w.Ref()); err == nil {
		t.Fatal("the live content is still usable; the eviction did not take effect")
	}

	content, err := collector.PackageContent(dir, d)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "capture.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := collector.ReadCapture(raw, installed.Registry())
	if err != nil {
		t.Fatal(err)
	}
	use, err := doc.ContentUse(installed.Registry())
	if err != nil || use.Role != collector.ContentApplied {
		t.Fatalf("%+v %v", use, err)
	}
	members, err := content.Resolve(use)
	if err != nil || len(members) != 1 {
		t.Fatalf("%+v %v", members, err)
	}
	m := members[0]
	if m.Ref != w.Ref() || !m.Applied || m.Vendored || m.Root != filepath.Join(dir, filepath.FromSlash(publication.ContentPath(w.Ref().Digest))) ||
		!reflect.DeepEqual(m.Frozen.Identity, f.Identity) {
		t.Fatalf("replay member %+v", m)
	}
	want, err := collector.FrozenContentSet(f)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := collector.FrozenContentSet(m.Frozen); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v %v", got, err)
	}
}
