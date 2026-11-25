package collector_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// The storage backend's pre-archive validation runs the shared projection
// check on a namespace package's capture, then checks the evaluation its
// descriptor summarizes. A namespace package changed after export to carry
// sibling data is refused, and the refusal does not repeat that data.
func TestStorageRefusesTamperedNamespacePackages(t *testing.T) {
	const secret = "SIBLING-SECRET"
	for name, tamper := range map[string]func(capture, ev map[string]any){
		"report summary": func(c, _ map[string]any) {
			c["reports"].([]any)[0].(map[string]any)["summary"] = map[string]any{"fail": 2, "note": secret}
		},
		"sibling reference": func(c, _ map[string]any) {
			r := c["reports"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)
			r["resources"] = append(r["resources"].([]any), map[string]any{"kind": "Pod", "namespace": "shop-prod", "name": "web", "uid": "pod-prod"})
		},
		"collection errors": func(c, _ map[string]any) { c["collectionErrors"] = []any{"policyreports is forbidden in shop-prod"} },
		"projection relabeled": func(c, _ map[string]any) {
			c["projection"].(map[string]any)["namespace"] = "shop-prod"
		},
		"sibling observation": func(_, ev map[string]any) {
			obs := ev["observations"].([]any)
			o := map[string]any{}
			for k, v := range obs[0].(map[string]any) {
				o[k] = v
			}
			o["key"] = "uid-shop-prod/" + secret
			ev["observations"] = append(obs, o)
		},
		"sibling report": func(_, ev map[string]any) {
			ev["observations"].([]any)[0].(map[string]any)["report"] = "sibling-report"
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir, d := collector.NamespacePackage(t)
			docs := map[string]map[string]any{"capture.json": nil, "evaluation.json": nil}
			for file := range docs {
				raw, err := os.ReadFile(filepath.Join(dir, file))
				if err != nil {
					t.Fatal(err)
				}
				var m map[string]any
				if err := json.Unmarshal(raw, &m); err != nil {
					t.Fatal(err)
				}
				docs[file] = m
			}
			tamper(docs["capture.json"], docs["evaluation.json"])
			for file, m := range docs {
				b, err := json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, file), b, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			collector.Rehash(t, dir, d)
			_, err := s3store.ValidatePackage(dir)
			if err == nil {
				t.Fatal("the storage backend accepted a tampered namespace package")
			}
			for _, leak := range []string{secret, "uid-shop-prod", "pod-prod"} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("the refusal repeats %q: %v", leak, err)
				}
			}
		})
	}
}

// A namespace package whose descriptor names another namespace than the
// packaged projection is refused.
func TestStorageRefusesNamespacePackageOfAnotherScope(t *testing.T) {
	for name, relabel := range map[string]func(*publication.RequestRef){
		"another namespace name":     func(r *publication.RequestRef) { r.Namespace = "shop-prod" },
		"another namespace instance": func(r *publication.RequestRef) { r.NamespaceUID = "uid-shop-prod" },
	} {
		t.Run(name, func(t *testing.T) {
			dir, d := collector.NamespacePackage(t)
			req := *d.Scope.Request
			relabel(&req)
			d.Scope.Request = &req
			d.Scope.NamespaceUIDs = []string{req.NamespaceUID}
			d.ScopeSHA256 = d.Scope.Digest()
			collector.Rehash(t, dir, d)
			if _, err := s3store.ValidatePackage(dir); err == nil {
				t.Fatal("the storage backend accepted a namespace package of another scope")
			}
		})
	}
}
