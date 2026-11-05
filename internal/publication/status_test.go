package publication_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/publication"
)

func receipt() publication.Receipt {
	at := time.Date(2026, 11, 5, 10, 5, 0, 0, time.UTC)
	return publication.Receipt{
		PublicationID:    "pub-1",
		Destination:      publication.Destination{ID: "primary", Endpoint: "https://s3.example.test", Bucket: "evidence", Prefix: "konstapel/", CredentialRef: &publication.SecretRef{Namespace: "konstapel-system", Name: "s3"}},
		Commit:           publication.Commit{ManifestKey: "konstapel/pub-1/commit.json", ManifestVersionID: "m1", ArchiveKey: "konstapel/pub-1/attempts/a1/package.tar", ArchiveVersionID: "a1"},
		DescriptorSHA256: strings.Repeat("1", 64), PackageSHA256: strings.Repeat("2", 64), PackageSize: 4096,
		PublishedAt: at, Retention: publication.Retention{Duration: "2160h", BindingConfiguration: "binding-config-3", SelectedAt: at.Add(-time.Second)},
		ExpiresAt: at.Add(2160 * time.Hour),
	}
}

func TestStatusRoundTrip(t *testing.T) {
	s := publication.Committed(receipt())
	s.OwnedObjects = []publication.OwnedObject{{Role: publication.ObjectArchive, AttemptID: "a1", Key: s.Commit.ArchiveKey, VersionID: "a1"}, {Role: publication.ObjectManifest, Key: s.Commit.ManifestKey, VersionID: "m1"}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var back publication.Status
	if err = json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	b2, _ := json.Marshal(back)
	if string(b) != string(b2) || back.Validate() != nil {
		t.Fatalf("status does not round-trip:\n%s\n%s", b, b2)
	}
}

func TestStatusInvariants(t *testing.T) {
	cases := map[string]func(*publication.Status){
		"expiry from retry clock": func(s *publication.Status) { e := s.ExpiresAt.Add(time.Minute); s.ExpiresAt = &e },
		"committed w/o receipt":   func(s *publication.Status) { s.Commit = nil },
		"zero retention":          func(s *publication.Status) { s.Retention.Duration = "0s" },
		"day suffix":              func(s *publication.Status) { s.Retention.Duration = "90d" },
		"uploading available":     func(s *publication.Status) { s.Phase = publication.PhaseUploading },
		"failed w/o failure": func(s *publication.Status) {
			s.Phase = publication.PhaseFailed
			s.Availability = publication.AvailabilityUnavailable
		},
		"unbounded objects": func(s *publication.Status) {
			s.OwnedObjects = make([]publication.OwnedObject, publication.MaxOwnedObjects+1)
		},
		"unbounded message": func(s *publication.Status) { s.Cleanup.Message = strings.Repeat("x", publication.MaxMessageLength+1) },
	}
	for name, mutate := range cases {
		s := publication.Committed(receipt())
		mutate(&s)
		if s.Validate() == nil {
			t.Errorf("%s: accepted invalid status", name)
		}
	}
}

// TestStatusCarriesNoBulkDataOrCredentials guards the contract structurally:
// status types may hold only bounded scalar references, never raw bytes,
// arbitrary objects, reports, or credential values.
func TestStatusCarriesNoBulkDataOrCredentials(t *testing.T) {
	forbidden := []string{"report", "secretkey", "accesskey", "password", "token", "sessiontoken", "credential"}
	var walk func(reflect.Type, string)
	seen := map[reflect.Type]bool{}
	walk = func(ty reflect.Type, at string) {
		for ty.Kind() == reflect.Pointer || ty.Kind() == reflect.Slice {
			if ty.Kind() == reflect.Slice && ty.Elem().Kind() == reflect.Uint8 {
				t.Errorf("%s holds raw bytes", at)
				return
			}
			ty = ty.Elem()
		}
		switch ty.Kind() {
		case reflect.Map, reflect.Interface:
			t.Errorf("%s holds an arbitrary object", at)
		case reflect.Struct:
			if ty == reflect.TypeOf(time.Time{}) || seen[ty] {
				return
			}
			seen[ty] = true
			for i := range ty.NumField() {
				f := ty.Field(i)
				name := strings.ToLower(f.Name)
				for _, bad := range forbidden {
					// A reference to a Secret is allowed; its value is not.
					if strings.Contains(name, bad) && !(f.Type == reflect.TypeOf(&publication.SecretRef{})) {
						t.Errorf("%s.%s looks like bulk or credential data", at, f.Name)
					}
				}
				walk(f.Type, at+"."+f.Name)
			}
		}
	}
	for _, v := range []any{publication.Status{}, publication.Receipt{}, publication.RunSummary{}, publication.Staged{}} {
		walk(reflect.TypeOf(v), reflect.TypeOf(v).Name())
	}
	if got := reflect.TypeOf(publication.SecretRef{}).NumField(); got != 2 {
		t.Fatalf("SecretRef must only name a Secret, has %d fields", got)
	}
}
