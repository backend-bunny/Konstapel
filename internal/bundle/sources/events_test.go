package sources

import (
	"context"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
)

func profile(name, bundleName string) *v1alpha1.ComplianceProfile {
	return &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: bundleName, Digest: digestA}}}
}

func profileClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
}

func names(reqs []string) []string { slices.Sort(reqs); return reqs }

// Affected bundle names become events for exactly the profiles that use
// them, on every output channel; unrelated changes produce nothing.
func TestTriggerEnqueuesAffectedProfiles(t *testing.T) {
	f := newFixture(t)
	f.putCreds("creds", planted)
	a := pkSource("a", "key-a", f.keyA.fp)
	a.CredentialSecret = &bundle.ObjectRef{Name: "creds"}
	f.set(a, pkSource("b", "key-b", f.keyB.fp))
	f.sync()
	_ = f.w.takePending()
	select {
	case <-f.w.notify:
	default:
	}

	profiles := profileClient(t, profile("p-a1", "a"), profile("p-a2", "a"), profile("p-b", "b"), profile("p-other", "other"))
	if reqs, err := ProfilesFor(context.Background(), profiles, []string{"a"}); err != nil || len(reqs) != 2 || reqs[0].Name != "p-a1" || reqs[1].Name != "p-a2" {
		t.Fatalf("ProfilesFor: %v %v", reqs, err)
	}

	// Unrelated objects, an unchanged configuration: nothing pending.
	f.putCreds("unrelated", "x")
	f.objs.Put(bundle.KindConfigMap, "unrelated", kubeaccess.NewObject("", map[string][]byte{"k": []byte("v")}))
	f.sync()
	if len(f.w.notify) != 0 || len(f.w.takePending()) != 0 {
		t.Fatal("an unrelated change produced events")
	}

	// A credential rotation affects "a" only.
	f.putCreds("creds", "rotated")
	f.sync()
	one, two := make(chan event.GenericEvent, 8), make(chan event.GenericEvent, 8)
	trig := f.w.NewTrigger(profiles, one, two)
	if !trig.NeedLeaderElection() || f.w.NeedLeaderElection() {
		t.Fatal("the trigger runs on the leader; the watcher on every replica")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = trig.Start(ctx); close(done) }()
	var got1, got2 []string
	for len(got1) < 2 || len(got2) < 2 {
		select {
		case e := <-one:
			got1 = append(got1, e.Object.GetName())
		case e := <-two:
			got2 = append(got2, e.Object.GetName())
		case <-time.After(10 * time.Second): // failure guard only
			t.Fatalf("events %v %v", got1, got2)
		}
	}
	cancel()
	<-done
	if want := []string{"p-a1", "p-a2"}; !slices.Equal(names(got1), want) || !slices.Equal(names(got2), want) {
		t.Fatalf("events %v %v", got1, got2)
	}
	if len(one) != 0 || len(two) != 0 {
		t.Fatal("events for unaffected profiles")
	}
}

// The predicate admits the sources ConfigMap and the objects the current
// configuration references, in the controller namespace only, and follows
// configuration changes.
func TestPredicateFollowsConfiguration(t *testing.T) {
	f := newFixture(t)
	a := pkSource("a", "key-a", f.keyA.fp)
	a.CredentialSecret = &bundle.ObjectRef{Name: "creds"}
	a.CA = &bundle.ObjectRef{Kind: bundle.KindConfigMap, Name: "ca"}
	f.set(a)
	f.sync()
	pred := f.w.Predicate()
	secret := func(nsName, name string) client.Object {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: nsName, Name: name}}
	}
	cm := func(nsName, name string) client.Object {
		return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: nsName, Name: name}}
	}
	admit := func(o client.Object) bool { return pred.Update(event.UpdateEvent{ObjectOld: o, ObjectNew: o}) }
	cases := []struct {
		o    client.Object
		want bool
	}{
		{cm(ns, DefaultConfigMapName), true},
		{secret(ns, "creds"), true},
		{secret(ns, "key-a"), true},
		{cm(ns, "ca"), true},
		{secret(ns, "ca"), false}, // referenced as a ConfigMap
		{cm(ns, "creds"), false},  // referenced as a Secret
		{secret(ns, "other"), false},
		{secret("default", "creds"), false},
		{cm("default", DefaultConfigMapName), false},
		{&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "creds"}}, false},
	}
	for _, c := range cases {
		if got := admit(c.o); got != c.want {
			t.Errorf("%T %s/%s: %v", c.o, c.o.GetNamespace(), c.o.GetName(), got)
		}
	}
	// The configuration no longer references creds: the predicate follows.
	a.CredentialSecret = &bundle.ObjectRef{Name: "creds2"}
	f.set(a)
	f.sync()
	if admit(secret(ns, "creds")) || !admit(secret(ns, "creds2")) {
		t.Fatal("predicate did not follow the configuration")
	}
	// Unavailable configuration: only the ConfigMap itself.
	f.setData(nil)
	f.sync()
	if admit(secret(ns, "creds2")) || !admit(cm(ns, DefaultConfigMapName)) {
		t.Fatal("predicate with no configuration")
	}
}

// The informer handler only asks for a Sync, and only for the sources
// ConfigMap.
func TestConfigMapHandlerKicksOnlyForSources(t *testing.T) {
	f := newFixture(t)
	h := f.w.ConfigMapHandler()
	kicked := func() bool {
		select {
		case <-f.w.kick:
			return true
		default:
			return false
		}
	}
	other := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "other"}}
	elsewhere := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: DefaultConfigMapName}}
	mine := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: DefaultConfigMapName}}
	h.OnAdd(other, false)
	h.OnUpdate(elsewhere, elsewhere)
	if kicked() {
		t.Fatal("kicked for another ConfigMap")
	}
	for name, fire := range map[string]func(){
		"add":    func() { h.OnAdd(mine, true) },
		"update": func() { h.OnUpdate(mine, mine) },
		"delete": func() { h.OnDelete(mine) },
		"tombstone": func() {
			h.OnDelete(toolscache.DeletedFinalStateUnknown{Key: ns + "/" + DefaultConfigMapName, Obj: mine})
		},
	} {
		fire()
		fire() // coalesces, never blocks
		if !kicked() || kicked() {
			t.Fatalf("%s: want exactly one pending kick", name)
		}
	}
}

// Start syncs at once and again on a kick.
func TestStartSyncsOnKick(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = f.w.Start(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	f.set(pkSource("a", "key-a", f.keyA.fp))
	// The configuration may be read by the initial Sync or the kicked one;
	// either way "a" becomes pending, which is what we wait for.
	f.w.Kick()
	select {
	case <-f.w.notify:
	case <-time.After(10 * time.Second): // failure guard only
		t.Fatal("no Sync after a kick")
	}
	if got := f.w.takePending(); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("pending %v", got)
	}
}

func TestConfigMapCacheOptions(t *testing.T) {
	o := ConfigMapCacheOptions(ns, DefaultConfigMapName)
	if len(o.ByObject) != 1 {
		t.Fatalf("the cache must hold only the ConfigMap: %+v", o.ByObject)
	}
	for obj, by := range o.ByObject {
		if _, ok := obj.(*corev1.ConfigMap); !ok {
			t.Fatalf("type %T", obj)
		}
		if by.Field == nil || by.Field.String() != "metadata.name="+DefaultConfigMapName {
			t.Fatalf("field selector %v", by.Field)
		}
		if _, ok := by.Namespaces[ns]; !ok || len(by.Namespaces) != 1 {
			t.Fatalf("namespaces %v", by.Namespaces)
		}
	}
	if _, ok := o.DefaultNamespaces[ns]; !ok || len(o.DefaultNamespaces) != 1 {
		t.Fatalf("default namespaces %v", o.DefaultNamespaces)
	}
}
