package s3store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

func TestProbeReadyOnCompatibleService(t *testing.T) {
	for _, mode := range []string{"", "Enabled", "Suspended"} {
		f := newFake()
		f.versioning = mode
		f.objects["konstapel/unrelated/keep"] = []fakeVersion{{id: "null", body: []byte("x"), at: time.Now()}}
		r, err := probeFake(t, f)
		if err != nil || !r.Ready || r.Checksum != ChecksumServer || !r.ConditionalCreate {
			t.Fatalf("mode %q: %+v %v", mode, r, err)
		}
		// Probe cleanup removed everything it wrote and nothing else.
		for k := range f.objects {
			if k != "konstapel/unrelated/keep" {
				t.Errorf("mode %q: probe left %s behind", mode, k)
			}
		}
		if _, kept := f.objects["konstapel/unrelated/keep"]; !kept {
			t.Errorf("mode %q: probe deleted an unrelated object", mode)
		}
	}
}

func TestProbeDetectsMissingSemantics(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*fakeS3)
		ready  bool
		want   string
	}{
		"readback when the service keeps no checksums": {func(f *fakeS3) { f.checksums = false }, true, ""},
		"If-None-Match ignored":                        {func(f *fakeS3) { f.conditional = false }, false, "If-None-Match"},
		"clock skew":                                   {func(f *fakeS3) { f.skew = time.Hour }, false, "clock"},
		"versioned without version IDs":                {func(f *fakeS3) { f.versioning = "Enabled"; f.versionIDs = false }, false, "version ID"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake()
			tc.mutate(f)
			r, err := probeFake(t, f)
			if err != nil {
				t.Fatal(err)
			}
			if r.Ready != tc.ready || (tc.want != "" && !strings.Contains(strings.Join(r.Problems, ";"), tc.want)) {
				t.Fatalf("ready=%v problems=%v", r.Ready, r.Problems)
			}
			if name == "readback when the service keeps no checksums" && r.Checksum != ChecksumReadback {
				t.Fatalf("checksum mode %s", r.Checksum)
			}
		})
	}
	f := newFake()
	f.bucket = "other"
	if _, err := probeFake(t, f); err == nil || !strings.Contains(err.Error(), "not reachable") {
		t.Fatalf("missing bucket not reported: %v", err)
	}
}

func validDestination() Destination {
	return Destination{ID: "primary", Endpoint: "https://s3.example.test", Bucket: "evidence", Region: "eu-north-1", Prefix: "konstapel/",
		Addressing: AddressingVirtual, WorkloadIdentity: true}
}

func TestDestinationValidation(t *testing.T) {
	if err := validDestination().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Destination){
		"plain http":           func(d *Destination) { d.Endpoint = "http://s3.example.test" },
		"endpoint with path":   func(d *Destination) { d.Endpoint = "https://s3.example.test/bucket" },
		"endpoint userinfo":    func(d *Destination) { d.Endpoint = "https://user:pw@s3.example.test" },
		"uppercase bucket":     func(d *Destination) { d.Bucket = "Evidence" },
		"ip bucket":            func(d *Destination) { d.Bucket = "10.0.0.1" },
		"short bucket":         func(d *Destination) { d.Bucket = "ab" },
		"no region":            func(d *Destination) { d.Region = "" },
		"absolute prefix":      func(d *Destination) { d.Prefix = "/konstapel" },
		"traversal prefix":     func(d *Destination) { d.Prefix = "a/../b" },
		"double slash prefix":  func(d *Destination) { d.Prefix = "a//b" },
		"bad addressing":       func(d *Destination) { d.Addressing = "dns" },
		"no credential source": func(d *Destination) { d.WorkloadIdentity = false },
		"both credential sources": func(d *Destination) {
			d.CredentialSecret = &SecretRef{Name: "s3"}
		},
		"bad secret name": func(d *Destination) { d.WorkloadIdentity, d.CredentialSecret = false, &SecretRef{Name: "S3/creds"} },
		"bad id":          func(d *Destination) { d.ID = "Primary" },
	} {
		d := validDestination()
		mutate(&d)
		if d.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	d := validDestination()
	d.Endpoint, d.DevelopmentFixture = "http://127.0.0.1:9000", true
	if err := d.Validate(); err != nil {
		t.Fatalf("explicit development fixture rejected: %v", err)
	}
}

func TestLoadDestinationIsStrict(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, fmt.Sprint(len(s), ".yaml"))
		_ = os.WriteFile(p, []byte(s), 0o600)
		return p
	}
	ok := write("id: primary\nendpoint: https://s3.example.test\nbucket: evidence\nregion: eu-north-1\naddressing: path\nworkloadIdentity: true\n")
	if _, err := LoadDestination(ok); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"unknown field":      "id: primary\nendpoint: https://s3.example.test\nbucket: evidence\nregion: r\naddressing: path\nworkloadIdentity: true\ninsecureSkipVerify: true\n",
		"inline credentials": "id: primary\nendpoint: https://s3.example.test\nbucket: evidence\nregion: r\naddressing: path\nworkloadIdentity: true\nsecretAccessKey: x\n",
	} {
		if _, err := LoadDestination(write(body)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// Storage location and credentials exist only in platform-managed
// EvidenceDestinations. Application objects (requests, runs) carry no
// destination field at all. A ComplianceBinding is platform-managed and may
// only reference a destination by name and UID (spec.assessment.
// destinationRef); no spec carries an endpoint, bucket, prefix, or credential.
func TestApplicationObjectsCannotOverrideDestination(t *testing.T) {
	forbidden := []string{"endpoint", "bucket", "region", "prefix", "addressing", "credential", "secret", "destination", "cabundle"}
	const allowedRef = "ComplianceBindingSpec.Assessment.DestinationRef"
	var walk func(reflect.Type, string)
	walk = func(ty reflect.Type, at string) {
		for ty.Kind() == reflect.Pointer || ty.Kind() == reflect.Slice {
			ty = ty.Elem()
		}
		if ty.Kind() != reflect.Struct || ty.PkgPath() != reflect.TypeOf(v1alpha1.BindingReference{}).PkgPath() {
			return
		}
		for i := range ty.NumField() {
			f := ty.Field(i)
			path := at + "." + f.Name
			if path == allowedRef {
				ref := reflect.TypeOf(v1alpha1.DestinationReference{})
				if ft := f.Type; ft.Kind() != reflect.Pointer || ft.Elem() != ref || ref.NumField() != 2 {
					t.Errorf("%s must be a name/UID reference only", path)
				}
				continue
			}
			for _, bad := range forbidden {
				if strings.Contains(strings.ToLower(f.Name), bad) {
					t.Errorf("%s lets an object set %s", path, bad)
				}
			}
			walk(f.Type, path)
		}
	}
	for _, spec := range []any{v1alpha1.AssessmentRequestSpec{}, v1alpha1.AssessmentRunSpec{}, v1alpha1.ComplianceBindingSpec{}} {
		walk(reflect.TypeOf(spec), reflect.TypeOf(spec).Name())
	}
}

func TestCredentialsNeverLeak(t *testing.T) {
	creds := StaticCredentials{AccessKeyID: "AKIASECRETID", SecretAccessKey: "very-secret-value"}
	if s := fmt.Sprint(creds, &creds); strings.Contains(s, "very-secret") || strings.Contains(s, "AKIASECRETID") {
		t.Fatalf("credentials printed: %s", s)
	}
	d := validDestination()
	d.WorkloadIdentity, d.CredentialSecret = false, &SecretRef{Name: "s3"}
	_, err := NewClient(context.Background(), d, &StaticCredentials{AccessKeyID: "AKIASECRETID"})
	if !errors.Is(err, ErrCredentials) || strings.Contains(err.Error(), "AKIASECRETID") {
		t.Fatalf("missing secret key not reported safely: %v", err)
	}
	d.CABundle = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := NewClient(context.Background(), d, &creds); err == nil {
		t.Fatal("unreadable CA bundle accepted")
	}
}
