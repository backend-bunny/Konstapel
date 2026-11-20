package preview

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
)

// fakeAPI is a recording Kubernetes API test server. It serves discovery, get
// and paginated, label-selected lists from an in-memory store, records every
// request it receives, and lets tests inject concurrent changes, denials,
// missing APIs, expired continuations and slow responses. It answers every
// non-GET request with 405 so that a write could never pass silently, and
// tests additionally assert that none arrived.
type fakeAPI struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	rv       int
	colls    map[string]map[string]map[string]any // list path -> name -> object
	served   map[string][]metav1.APIResource      // discovery path -> resources
	requests []recorded
	captures int // GETs of kube-system: one per capture
	// hook runs before the store answers, without the lock held. It returns
	// true when it has written the response.
	hook func(w http.ResponseWriter, r *http.Request) bool
	// onCapture runs at the start of each capture (its 1-based number).
	onCapture func(n int)
	// expire decides whether a continuation token has expired.
	expire func(token string) bool
}

type recorded struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Query  string `json:"query,omitempty"`
}

const (
	pathNamespaces = "/api/v1/namespaces"
	pathProfiles   = "/apis/compliance.erenius.io/v1alpha1/complianceprofiles"
	pathBindings   = "/apis/compliance.erenius.io/v1alpha1/compliancebindings"
	pathExceptions = "/apis/compliance.erenius.io/v1alpha1/complianceexceptions"
	pathPolicies   = "/apis/policies.kyverno.io/v1/validatingpolicies"
)

func pathConfigMaps(ns string) string { return "/api/v1/namespaces/" + ns + "/configmaps" }

func pathSecrets(ns string) string { return "/api/v1/namespaces/" + ns + "/secrets" }

func typeFor(listPath string) (string, string) {
	switch {
	case listPath == pathNamespaces:
		return "v1", "Namespace"
	case strings.HasSuffix(listPath, "/configmaps"):
		return "v1", "ConfigMap"
	case strings.HasSuffix(listPath, "/secrets"):
		return "v1", "Secret"
	case listPath == pathProfiles:
		return "compliance.erenius.io/v1alpha1", "ComplianceProfile"
	case listPath == pathBindings:
		return "compliance.erenius.io/v1alpha1", "ComplianceBinding"
	case listPath == pathExceptions:
		return "compliance.erenius.io/v1alpha1", "ComplianceException"
	case listPath == pathPolicies:
		return "policies.kyverno.io/v1", "ValidatingPolicy"
	}
	return "v1", "Unknown"
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{t: t, colls: map[string]map[string]map[string]any{}, served: map[string][]metav1.APIResource{}}
	gl := []string{"get", "list", "watch", "create", "update", "patch", "delete"}
	f.served["/api/v1"] = []metav1.APIResource{{Name: "namespaces", Verbs: gl}, {Name: "configmaps", Namespaced: true, Verbs: gl}, {Name: "secrets", Namespaced: true, Verbs: gl}}
	f.served["/apis/compliance.erenius.io/v1alpha1"] = []metav1.APIResource{
		{Name: "complianceprofiles", Verbs: gl}, {Name: "complianceprofiles/status", Verbs: []string{"get", "patch", "update"}},
		{Name: "compliancebindings", Verbs: gl}, {Name: "complianceexceptions", Namespaced: true, Verbs: gl}}
	f.served["/apis/policies.kyverno.io/v1"] = []metav1.APIResource{{Name: "validatingpolicies", Verbs: gl}}
	for _, p := range []string{pathNamespaces, pathProfiles, pathBindings, pathExceptions, pathPolicies} {
		f.colls[p] = map[string]map[string]any{}
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) config() *rest.Config { return &rest.Config{Host: f.srv.URL} }

// put stores obj (a typed API object or a map) in the list path, advancing
// the store revision as a write would.
func (f *fakeAPI) put(listPath string, obj any) map[string]any {
	f.t.Helper()
	m, ok := obj.(map[string]any)
	if !ok {
		var err error
		if m, err = runtime.DefaultUnstructuredConverter.ToUnstructured(obj); err != nil {
			f.t.Fatal(err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rv++
	if m["kind"] == nil {
		gv, kind := typeFor(listPath)
		m["apiVersion"], m["kind"] = gv, kind
	}
	meta, _ := m["metadata"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
		m["metadata"] = meta
	}
	name, _ := meta["name"].(string)
	if meta["uid"] == nil || meta["uid"] == "" {
		meta["uid"] = "uid-" + name
	}
	meta["resourceVersion"] = strconv.Itoa(f.rv)
	if f.colls[listPath] == nil {
		f.colls[listPath] = map[string]map[string]any{}
	}
	f.colls[listPath][name] = m
	return m
}

// mutate changes a stored object in place and advances its resourceVersion.
func (f *fakeAPI) mutate(listPath, name string, change func(m map[string]any)) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.colls[listPath][name]
	if m == nil {
		f.t.Fatalf("no %s/%s", listPath, name)
	}
	change(m)
	f.rv++
	m["metadata"].(map[string]any)["resourceVersion"] = strconv.Itoa(f.rv)
}

func (f *fakeAPI) remove(listPath, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.colls[listPath], name)
	f.rv++
}

func (f *fakeAPI) recorded() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

func writeStatus(w http.ResponseWriter, code int, reason metav1.StatusReason, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(metav1.Status{TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: metav1.StatusFailure,
		Code: int32(code), Reason: reason, Message: msg})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, recorded{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery})
	newCapture := r.Method == http.MethodGet && r.URL.Path == pathNamespaces+"/kube-system"
	if newCapture {
		f.captures++
	}
	n, onCapture, hook := f.captures, f.onCapture, f.hook
	f.mu.Unlock()
	if newCapture && onCapture != nil {
		onCapture(n)
	}
	if hook != nil && hook(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writeStatus(w, http.StatusMethodNotAllowed, metav1.StatusReasonMethodNotAllowed, "the recording API server accepts no writes")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p := r.URL.Path
	if res, ok := f.served[p]; ok {
		gv := strings.TrimPrefix(strings.TrimPrefix(p, "/apis/"), "/api/")
		writeJSON(w, metav1.APIResourceList{TypeMeta: metav1.TypeMeta{Kind: "APIResourceList", APIVersion: "v1"}, GroupVersion: gv, APIResources: res})
		return
	}
	if coll, ok := f.colls[p]; ok {
		f.list(w, r, p, coll)
		return
	}
	if coll, ok := f.colls[path.Dir(p)]; ok {
		if obj, ok := coll[path.Base(p)]; ok {
			writeJSON(w, obj)
			return
		}
		writeStatus(w, http.StatusNotFound, metav1.StatusReasonNotFound, fmt.Sprintf("%q not found", path.Base(p)))
		return
	}
	// An unserved namespaced collection in an existing namespace is empty.
	if strings.HasPrefix(p, pathNamespaces+"/") && strings.HasSuffix(p, "/configmaps") {
		f.list(w, r, p, nil)
		return
	}
	writeStatus(w, http.StatusNotFound, metav1.StatusReasonNotFound, "the server could not find the requested resource")
}

func (f *fakeAPI) list(w http.ResponseWriter, r *http.Request, p string, coll map[string]map[string]any) {
	q := r.URL.Query()
	sel := labels.Everything()
	if s := q.Get("labelSelector"); s != "" {
		var err error
		if sel, err = labels.Parse(s); err != nil {
			writeStatus(w, http.StatusBadRequest, metav1.StatusReasonBadRequest, err.Error())
			return
		}
	}
	var names []string
	for name, obj := range coll {
		meta := obj["metadata"].(map[string]any)
		l := labels.Set{}
		if raw, ok := meta["labels"].(map[string]any); ok {
			for k, v := range raw {
				l[k], _ = v.(string)
			}
		}
		if sel.Matches(l) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	listRV, offset := strconv.Itoa(f.rv), 0
	if tok := q.Get("continue"); tok != "" {
		if f.expire != nil && f.expire(tok) {
			writeStatus(w, http.StatusGone, metav1.StatusReasonExpired, "The provided continue parameter is too old to display a consistent list result.")
			return
		}
		rv, off, _ := strings.Cut(tok, ":")
		listRV = rv
		offset, _ = strconv.Atoi(off)
	}
	limit := len(names)
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 {
		limit = l
	}
	end := min(offset+limit, len(names))
	items := []any{}
	for _, n := range names[min(offset, len(names)):end] {
		items = append(items, coll[n])
	}
	meta := map[string]any{"resourceVersion": listRV}
	if end < len(names) {
		meta["continue"] = listRV + ":" + strconv.Itoa(end)
	}
	writeJSON(w, map[string]any{"apiVersion": "v1", "kind": "List", "metadata": meta, "items": items})
}
