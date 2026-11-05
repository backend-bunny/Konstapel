package assessment

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func respond(w http.ResponseWriter, obj any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(obj)
}

func statusError(w http.ResponseWriter, code int, reason metav1.StatusReason, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Failure", Code: int32(code), Reason: reason, Message: message})
}

// Exercise the real HTTP client/discovery path. An empty PATH proves these
// operations do not need kubectl or any other external executable.
func targetForTest(t *testing.T, handle func(http.ResponseWriter, *http.Request) bool) *Target {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
	resources := map[string][]metav1.APIResource{}
	groups := map[string][]metav1.GroupVersionForDiscovery{}
	for _, r := range []struct {
		gvk        schema.GroupVersionKind
		name       string
		namespaced bool
	}{
		{namespaceGVK, "namespaces", false}, {podGVK, "pods", true},
		{serviceAccountGVK, "serviceaccounts", true}, {eventGVK, "events", true},
		{deploymentGVK, "deployments", true}, {policyGVK, "validatingpolicies", false},
		{reportGVK, "policyreports", true}, {clusterReportGVK, "clusterpolicyreports", false},
	} {
		gv := r.gvk.GroupVersion().String()
		if _, exists := resources[gv]; !exists && r.gvk.Group != "" {
			groups[r.gvk.Group] = append(groups[r.gvk.Group], metav1.GroupVersionForDiscovery{GroupVersion: gv, Version: r.gvk.Version})
		}
		resources[gv] = append(resources[gv], metav1.APIResource{Name: r.name, Kind: r.gvk.Kind, Namespaced: r.namespaced, Verbs: metav1.Verbs{"get", "list", "create", "patch", "delete"}})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handle(w, r) {
			return
		}
		switch r.URL.Path {
		case "/api":
			respond(w, metav1.APIVersions{Versions: []string{"v1"}})
			return
		case "/apis":
			list := metav1.APIGroupList{}
			for group, versions := range groups {
				list.Groups = append(list.Groups, metav1.APIGroup{Name: group, Versions: versions, PreferredVersion: versions[0]})
			}
			respond(w, list)
			return
		case "/api/v1/namespaces/kube-system":
			respond(w, Object{"apiVersion": "v1", "kind": "Namespace", "metadata": Object{"name": "kube-system", "uid": "fixture"}})
			return
		}
		gv := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/apis/"), "/api/")
		if list, ok := resources[gv]; ok {
			respond(w, metav1.APIResourceList{GroupVersion: gv, APIResources: list})
			return
		}
		if versions, ok := groups[gv]; ok {
			respond(w, metav1.APIGroup{Name: gv, Versions: versions, PreferredVersion: versions[0]})
			return
		}
		t.Errorf("unexpected request: %s %s", r.Method, r.URL)
		statusError(w, 404, metav1.StatusReasonNotFound, "not found")
	}))
	t.Cleanup(server.Close)
	config := clientcmdapi.Config{
		CurrentContext: "ambient",
		Clusters: map[string]*clientcmdapi.Cluster{
			"explicit": {Server: server.URL}, "ambient": {Server: "http://127.0.0.1:1"},
		},
		Contexts: map[string]*clientcmdapi.Context{
			"explicit": {Cluster: "explicit"}, "ambient": {Cluster: "ambient"},
		},
	}
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := clientcmd.WriteToFile(config, path); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing-ambient-config"))
	target, err := NewTarget(path, "explicit", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if target.Cluster != "kube-system:fixture" {
		t.Fatal("cluster identity not read from explicit target", target.Cluster)
	}
	if _, err := NewTarget(path, "missing-context", time.Second); err == nil {
		t.Fatal("unknown context fell back to ambient config")
	}
	return target
}

func TestTargetRequests(t *testing.T) {
	calls := make(chan string, 3)
	target := targetForTest(t, func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/namespaces/test/pods") {
			return false
		}
		calls <- r.Method + " " + r.URL.Path
		var obj Object
		if err := json.NewDecoder(r.Body).Decode(&obj); err != nil {
			t.Error(err)
		}
		if r.Method == "POST" {
			if r.URL.Query().Get("dryRun") != "All" {
				t.Error("dry-run create could persist a resource")
			}
			statusError(w, 403, metav1.StatusReasonForbidden, "Policy "+PolicyName+" failed: Privileged mode is disallowed")
			return true
		}
		if strings.HasSuffix(r.URL.Path, "/ephemeralcontainers") {
			if r.Header.Get("Content-Type") != "application/merge-patch+json" || At(obj, "spec", "ephemeralContainers") == nil {
				t.Error("incorrect subresource patch", obj)
			}
		} else if r.Header.Get("Content-Type") != "application/apply-patch+yaml" || r.URL.Query().Get("fieldManager") != "konstapel-assessment" || r.URL.Query().Get("force") == "true" {
			t.Error("incorrect apply semantics", r.Header, r.URL)
		}
		Map(obj["metadata"])["uid"] = "server-uid"
		respond(w, obj)
		return true
	})
	obj := pod("request", "test", "owner", true)
	result, err := target.Create(context.Background(), obj, true)
	if !apierrors.IsForbidden(err) || CheckAdmission(admissionResponse(result, err), err, true) != nil {
		t.Fatal("API denial lost its type or policy message", err)
	}
	if _, err := target.Apply(context.Background(), obj); err != nil {
		t.Fatal(err)
	}
	if At(obj, "metadata", "uid") != nil {
		t.Fatal("request mutated caller's desired object")
	}
	eph := Object{"apiVersion": "v1", "kind": "Pod", "metadata": Object{"namespace": "test", "name": "request"}, "spec": Object{"ephemeralContainers": []any{Object{"name": "debug"}}}}
	if _, err := target.PatchEphemeralContainers(context.Background(), eph); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 {
		t.Fatal("unexpected request count", len(calls))
	}
	for _, want := range []string{"POST /api/v1/namespaces/test/pods", "PATCH /api/v1/namespaces/test/pods/request", "PATCH /api/v1/namespaces/test/pods/request/ephemeralcontainers"} {
		if got := <-calls; got != want {
			t.Fatalf("got %s, want %s", got, want)
		}
	}
}

func TestTargetWaitAndCleanup(t *testing.T) {
	for _, mode := range []string{"unowned", "owned", "conflict", "forbidden", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			var deleted atomic.Bool
			target := targetForTest(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/api/v1/namespaces/test" {
					return false
				}
				if r.Method == "DELETE" {
					var options metav1.DeleteOptions
					_ = json.NewDecoder(r.Body).Decode(&options)
					if options.Preconditions == nil || options.Preconditions.UID == nil || string(*options.Preconditions.UID) != "original" || options.Preconditions.ResourceVersion == nil || *options.Preconditions.ResourceVersion != "42" {
						t.Error("cleanup lacks identity/ownership preconditions", options)
					}
					if mode == "conflict" {
						statusError(w, 409, metav1.StatusReasonConflict, "resource replaced")
						return true
					}
					deleted.Store(true)
					respond(w, metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Success"})
					return true
				}
				if mode == "forbidden" {
					statusError(w, 403, metav1.StatusReasonForbidden, "forbidden")
					return true
				}
				if deleted.Load() {
					statusError(w, 404, metav1.StatusReasonNotFound, "gone")
					return true
				}
				owner := "test"
				if mode == "unowned" {
					owner = "someone-else"
				}
				respond(w, Object{"apiVersion": "v1", "kind": "Namespace", "metadata": Object{"name": "test", "uid": "original", "resourceVersion": "42", "labels": Object{OwnerLabel: owner}}})
				return true
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			err := target.DeleteOwned(ctx, namespaceGVK, "", "test", "test")
			if (err == nil) != (mode == "unowned" || mode == "owned") || deleted.Load() != (mode == "owned") {
				t.Fatal("cleanup result", deleted.Load(), err)
			}
			if mode == "conflict" && !apierrors.IsConflict(err) {
				t.Fatal("lost conflict error", err)
			}
			if mode == "owned" || mode == "cancelled" || mode == "forbidden" {
				start := time.Now()
				err = target.Wait(ctx, namespaceGVK, "", "test", 30*time.Millisecond, func(Object) bool { return true })
				if err == nil || time.Since(start) > time.Second {
					t.Fatal("wait ignored missing resource, cancellation, or API error", err)
				}
			}
		})
	}
}
