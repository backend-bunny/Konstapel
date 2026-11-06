package s3store

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeS3 is a minimal path-style S3 server for unit tests. Each behavior the
// probe requires can be switched off to show it is detected.
type fakeS3 struct {
	mu          sync.Mutex
	bucket      string
	versioning  string // "", "Enabled", "Suspended"
	conditional bool   // enforce If-None-Match: *
	checksums   bool   // store and return x-amz-checksum-sha256
	versionIDs  bool   // return version IDs when versioned
	skew        time.Duration
	corrupt     bool                     // store truncated bytes and no checksum
	objects     map[string][]fakeVersion // key -> versions, newest last
	seq         int
	accessKeys  []string // access key ID of each signed request
}

type fakeVersion struct {
	id, checksum string
	body         []byte
	deleted      bool
	at           time.Time
}

func newFake() *fakeS3 {
	return &fakeS3{bucket: "evidence", conditional: true, checksums: true, versionIDs: true, objects: map[string][]fakeVersion{}}
}

func (f *fakeS3) serve(t *testing.T) (*httptest.Server, Destination) {
	srv := httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(srv.Close)
	return srv, Destination{ID: "fake", Endpoint: srv.URL, Bucket: "evidence", Region: "us-east-1", Prefix: "konstapel",
		Addressing: AddressingPath, CredentialSecret: &SecretRef{Name: "s3"}, DevelopmentFixture: true}
}

func xmlError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<Error><Code>%s</Code><Message>%s</Message></Error>", code, code)
}

func (f *fakeS3) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, after, ok := strings.Cut(r.Header.Get("Authorization"), "Credential="); ok {
		f.accessKeys = append(f.accessKeys, strings.SplitN(after, "/", 2)[0])
	}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	if parts[0] != f.bucket {
		xmlError(w, 404, "NoSuchBucket")
		return
	}
	q := r.URL.Query()
	if len(parts) == 1 || parts[1] == "" {
		switch {
		case r.Method == http.MethodHead:
			w.WriteHeader(200)
		case q.Has("versioning"):
			fmt.Fprintf(w, `<VersioningConfiguration><Status>%s</Status></VersioningConfiguration>`, f.versioning)
		case q.Has("versions"):
			f.listVersions(w, q.Get("prefix"))
		case q.Get("list-type") == "2":
			f.listV2(w, q.Get("prefix"))
		default:
			xmlError(w, 501, "NotImplemented")
		}
		return
	}
	key := parts[1]
	now := time.Now().UTC().Add(f.skew)
	current := func() (fakeVersion, bool) {
		vs := f.objects[key]
		if vid := q.Get("versionId"); vid != "" {
			for _, v := range vs {
				if v.id == vid && !v.deleted {
					return v, true
				}
			}
			return fakeVersion{}, false
		}
		if len(vs) == 0 || vs[len(vs)-1].deleted {
			return fakeVersion{}, false
		}
		return vs[len(vs)-1], true
	}
	switch r.Method {
	case http.MethodPut:
		if f.conditional && r.Header.Get("If-None-Match") == "*" {
			if _, exists := current(); exists {
				xmlError(w, 412, "PreconditionFailed")
				return
			}
		}
		body, _ := io.ReadAll(r.Body)
		v := fakeVersion{body: body, at: now}
		if f.corrupt && len(body) > 1 {
			v.body = body[:len(body)/2]
		} else if f.checksums {
			v.checksum = r.Header.Get("X-Amz-Checksum-Sha256")
		}
		if f.versioning == "Enabled" {
			f.seq++
			v.id = fmt.Sprintf("v%d", f.seq)
			f.objects[key] = append(f.objects[key], v)
		} else {
			v.id = "null"
			f.objects[key] = []fakeVersion{v}
		}
		if f.versionIDs && f.versioning != "" {
			w.Header().Set("X-Amz-Version-Id", v.id)
		}
		w.WriteHeader(200)
	case http.MethodHead, http.MethodGet:
		v, ok := current()
		if !ok {
			xmlError(w, 404, "NoSuchKey")
			return
		}
		w.Header().Set("Last-Modified", v.at.Format(http.TimeFormat))
		if v.checksum != "" {
			w.Header().Set("X-Amz-Checksum-Sha256", v.checksum)
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(v.body)))
		w.WriteHeader(200)
		if r.Method == http.MethodGet {
			_, _ = w.Write(v.body)
		}
	case http.MethodDelete:
		vs := f.objects[key]
		if vid := q.Get("versionId"); vid != "" {
			kept := vs[:0]
			for _, v := range vs {
				if v.id != vid {
					kept = append(kept, v)
				}
			}
			f.objects[key] = kept
		} else if f.versioning == "Enabled" {
			f.seq++
			f.objects[key] = append(vs, fakeVersion{id: fmt.Sprintf("v%d", f.seq), deleted: true, at: now})
		} else {
			delete(f.objects, key)
		}
		if len(f.objects[key]) == 0 {
			delete(f.objects, key)
		}
		w.WriteHeader(204)
	default:
		xmlError(w, 501, "NotImplemented")
	}
}

func (f *fakeS3) listVersions(w http.ResponseWriter, prefix string) {
	type entry struct {
		Key       string `xml:"Key"`
		VersionID string `xml:"VersionId"`
	}
	var res struct {
		XMLName xml.Name `xml:"ListVersionsResult"`
		Version []entry  `xml:"Version"`
		Marker  []entry  `xml:"DeleteMarker"`
	}
	keys := make([]string, 0, len(f.objects))
	for k := range f.objects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		for _, v := range f.objects[k] {
			if v.deleted {
				res.Marker = append(res.Marker, entry{k, v.id})
			} else {
				res.Version = append(res.Version, entry{k, v.id})
			}
		}
	}
	_ = xml.NewEncoder(w).Encode(res)
}

func probeFake(t *testing.T, f *fakeS3) (Compatibility, error) {
	t.Helper()
	_, d := f.serve(t)
	c, err := NewClient(context.Background(), d, &StaticCredentials{AccessKeyID: "AKIAFAKE", SecretAccessKey: "fake-secret"})
	if err != nil {
		t.Fatal(err)
	}
	return Probe(context.Background(), c, d)
}

func (f *fakeS3) listV2(w http.ResponseWriter, prefix string) {
	type obj struct {
		Key string `xml:"Key"`
	}
	var res struct {
		XMLName  xml.Name `xml:"ListBucketResult"`
		Contents []obj    `xml:"Contents"`
	}
	keys := make([]string, 0, len(f.objects))
	for k, vs := range f.objects {
		if strings.HasPrefix(k, prefix) && len(vs) > 0 && !vs[len(vs)-1].deleted {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		res.Contents = append(res.Contents, obj{k})
	}
	_ = xml.NewEncoder(w).Encode(res)
}
