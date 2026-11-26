// Package s3fake is a minimal, in-memory, path-style S3 server for tests: the
// subset of the S3 API the publisher, the attachment store and the
// compatibility probe use. Each behaviour the probe requires can be switched
// off to show it is detected. It imports nothing of Konstapel, so the S3
// adapter's own tests and the controller's cluster-free tests share it.
package s3fake

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Server is the fake service. Lock it while reading or changing its fields
// once it serves requests.
type Server struct {
	sync.Mutex
	Bucket      string
	Versioning  string // "", "Enabled", "Suspended"
	Conditional bool   // enforce If-None-Match: *
	Checksums   bool   // store and return x-amz-checksum-sha256
	VersionIDs  bool   // return version IDs when versioned
	Skew        time.Duration
	// Now is the service clock (nil: time.Now); Skew is added to it.
	Now     func() time.Time
	Corrupt bool                 // store truncated bytes and no checksum
	Objects map[string][]Version // key -> versions, newest last
	Seq     int
	// AccessKeys is the access key ID of each signed request.
	AccessKeys []string
	// Uploads maps incomplete multipart upload IDs to keys.
	Uploads map[string]string
	// DenyDelete refuses object deletion (object lock / missing permission).
	DenyDelete bool
	// DenyDeleteKey refuses deletion of matching keys only, as an object
	// lock on one object would.
	DenyDeleteKey func(key string) bool
	// LoseCommits stores a conditional create of a commit.json and then
	// answers 500, as if the response were lost after the write landed.
	LoseCommits bool
}

// Version is one stored object version or delete marker.
type Version struct {
	ID, Checksum string
	Body         []byte
	Deleted      bool
	At           time.Time
}

// New returns a fake for bucket "evidence" with conditional writes,
// checksums and version IDs, and versioning not configured.
func New() *Server {
	return &Server{Bucket: "evidence", Conditional: true, Checksums: true, VersionIDs: true, Objects: map[string][]Version{}}
}

func xmlError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<Error><Code>%s</Code><Message>%s</Message></Error>", code, code)
}

func (f *Server) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

// ServeHTTP answers one S3 request.
func (f *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.Lock()
	defer f.Unlock()
	if _, after, ok := strings.Cut(r.Header.Get("Authorization"), "Credential="); ok {
		f.AccessKeys = append(f.AccessKeys, strings.SplitN(after, "/", 2)[0])
	}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	if parts[0] != f.Bucket {
		xmlError(w, 404, "NoSuchBucket")
		return
	}
	q := r.URL.Query()
	if len(parts) == 1 || parts[1] == "" {
		switch {
		case r.Method == http.MethodHead:
			w.WriteHeader(200)
		case q.Has("versioning"):
			fmt.Fprintf(w, `<VersioningConfiguration><Status>%s</Status></VersioningConfiguration>`, f.Versioning)
		case q.Has("versions"):
			f.listVersions(w, q.Get("prefix"))
		case q.Has("uploads"):
			fmt.Fprint(w, `<ListMultipartUploadsResult>`)
			for id, k := range f.Uploads {
				if strings.HasPrefix(k, q.Get("prefix")) {
					fmt.Fprintf(w, `<Upload><Key>%s</Key><UploadId>%s</UploadId></Upload>`, k, id)
				}
			}
			fmt.Fprint(w, `</ListMultipartUploadsResult>`)
		case q.Get("list-type") == "2":
			f.listV2(w, q.Get("prefix"))
		default:
			xmlError(w, 501, "NotImplemented")
		}
		return
	}
	key := parts[1]
	if id := q.Get("uploadId"); id != "" && r.Method == http.MethodDelete {
		if f.Uploads[id] != key {
			xmlError(w, 404, "NoSuchUpload")
			return
		}
		delete(f.Uploads, id)
		w.WriteHeader(204)
		return
	}
	now := f.now().UTC().Add(f.Skew)
	current := func() (Version, bool) {
		vs := f.Objects[key]
		if vid := q.Get("versionId"); vid != "" {
			for _, v := range vs {
				if v.ID == vid && !v.Deleted {
					return v, true
				}
			}
			return Version{}, false
		}
		if len(vs) == 0 || vs[len(vs)-1].Deleted {
			return Version{}, false
		}
		return vs[len(vs)-1], true
	}
	switch r.Method {
	case http.MethodPut:
		if f.Conditional && r.Header.Get("If-None-Match") == "*" {
			if _, exists := current(); exists {
				xmlError(w, 412, "PreconditionFailed")
				return
			}
		}
		body, _ := io.ReadAll(r.Body)
		v := Version{Body: body, At: now}
		if f.Corrupt && len(body) > 1 {
			v.Body = body[:len(body)/2]
		} else if f.Checksums {
			v.Checksum = r.Header.Get("X-Amz-Checksum-Sha256")
		}
		if f.Versioning == "Enabled" {
			f.Seq++
			v.ID = fmt.Sprintf("v%d", f.Seq)
			f.Objects[key] = append(f.Objects[key], v)
		} else {
			v.ID = "null"
			f.Objects[key] = []Version{v}
		}
		if f.LoseCommits && strings.HasSuffix(key, "/commit.json") && r.Header.Get("If-None-Match") == "*" {
			xmlError(w, 500, "InternalError")
			return
		}
		if f.VersionIDs && f.Versioning != "" {
			w.Header().Set("X-Amz-Version-Id", v.ID)
		}
		w.WriteHeader(200)
	case http.MethodHead, http.MethodGet:
		v, ok := current()
		if !ok {
			xmlError(w, 404, "NoSuchKey")
			return
		}
		w.Header().Set("Last-Modified", v.At.Format(http.TimeFormat))
		if f.VersionIDs && v.ID != "" {
			w.Header().Set("X-Amz-Version-Id", v.ID) // as S3 does for versioned objects
		}
		if v.Checksum != "" {
			w.Header().Set("X-Amz-Checksum-Sha256", v.Checksum)
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(v.Body)))
		w.WriteHeader(200)
		if r.Method == http.MethodGet {
			_, _ = w.Write(v.Body)
		}
	case http.MethodDelete:
		if f.DenyDelete || (f.DenyDeleteKey != nil && f.DenyDeleteKey(key)) {
			xmlError(w, 403, "AccessDenied")
			return
		}
		vs := f.Objects[key]
		if vid := q.Get("versionId"); vid != "" {
			kept := vs[:0]
			for _, v := range vs {
				if v.ID != vid {
					kept = append(kept, v)
				}
			}
			f.Objects[key] = kept
		} else if f.Versioning == "Enabled" {
			f.Seq++
			f.Objects[key] = append(vs, Version{ID: fmt.Sprintf("v%d", f.Seq), Deleted: true, At: now})
		} else {
			delete(f.Objects, key)
		}
		if len(f.Objects[key]) == 0 {
			delete(f.Objects, key)
		}
		w.WriteHeader(204)
	default:
		xmlError(w, 501, "NotImplemented")
	}
}

func (f *Server) listVersions(w http.ResponseWriter, prefix string) {
	type entry struct {
		Key       string `xml:"Key"`
		VersionID string `xml:"VersionId"`
	}
	var res struct {
		XMLName xml.Name `xml:"ListVersionsResult"`
		Version []entry  `xml:"Version"`
		Marker  []entry  `xml:"DeleteMarker"`
	}
	keys := make([]string, 0, len(f.Objects))
	for k := range f.Objects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		for _, v := range f.Objects[k] {
			if v.Deleted {
				res.Marker = append(res.Marker, entry{k, v.ID})
			} else {
				res.Version = append(res.Version, entry{k, v.ID})
			}
		}
	}
	_ = xml.NewEncoder(w).Encode(res)
}

func (f *Server) listV2(w http.ResponseWriter, prefix string) {
	type obj struct {
		Key string `xml:"Key"`
	}
	var res struct {
		XMLName  xml.Name `xml:"ListBucketResult"`
		Contents []obj    `xml:"Contents"`
	}
	keys := make([]string, 0, len(f.Objects))
	for k, vs := range f.Objects {
		if strings.HasPrefix(k, prefix) && len(vs) > 0 && !vs[len(vs)-1].Deleted {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		res.Contents = append(res.Contents, obj{k})
	}
	_ = xml.NewEncoder(w).Encode(res)
}
