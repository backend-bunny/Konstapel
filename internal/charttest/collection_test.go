package charttest

import (
	"strconv"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/provider"
)

// renderedCollection reads the controller's --collection-* flags from a
// render.
func renderedCollection(t *testing.T, docs []map[string]any) provider.Limits {
	t.Helper()
	d := find(docs, "Deployment", "konstapel-controller")
	if d == nil {
		t.Fatal("no controller Deployment")
	}
	args := at(d, "spec", "template", "spec", "containers", 0, "args").([]any)
	get := func(name string) int64 {
		v, ok := argValue(args, name)
		if !ok {
			t.Fatalf("controller args lack --%s: %v", name, args)
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			t.Fatalf("--%s=%s: %v", name, v, err)
		}
		return n
	}
	return provider.Limits{PageSize: get("collection-page-size"), MaxPages: int(get("collection-max-requests")),
		MaxObjects: int(get("collection-max-objects")), MaxBytes: get("collection-max-bytes")}
}

// The evidence collection limits are chart values whose defaults are the
// controller's own (provider.DefaultLimits, without a deadline: that stays
// each binding's collectionTimeout), and any accepted value passes the
// controller's startup validation. Values the controller would refuse are
// refused at render.
func TestRuntimeChartCollectionLimits(t *testing.T) {
	docs, _, err := render(t, "konstapel-system", "image.digest="+digest)
	if err != nil {
		t.Fatal(err)
	}
	want := provider.DefaultLimits()
	want.Timeout = 0
	if l := renderedCollection(t, docs); l != want || l.ValidateConfiguration() != nil {
		t.Fatalf("default limits %+v, controller defaults %+v", l, want)
	}
	for name, tc := range map[string]struct {
		set  []string
		want provider.Limits
	}{
		"raised": {set: []string{"controller.collection.maxObjects=1000000", "controller.collection.maxBytes=8589934592", "controller.collection.maxRequests=40000", "controller.collection.pageSize=1000"},
			want: provider.Limits{PageSize: 1000, MaxPages: 40_000, MaxObjects: 1_000_000, MaxBytes: 8 << 30}},
		"largest": {set: []string{"controller.collection.maxObjects=10000000", "controller.collection.maxBytes=68719476736", "controller.collection.maxRequests=1000000", "controller.collection.pageSize=10000"},
			want: provider.Limits{PageSize: provider.MaxPageSize, MaxPages: provider.MaxConfiguredPages, MaxObjects: provider.MaxConfiguredObjects, MaxBytes: provider.MaxConfiguredBytes}},
		"smallest": {set: []string{"controller.collection.maxObjects=1", "controller.collection.maxBytes=1572864", "controller.collection.maxRequests=1", "controller.collection.pageSize=1"},
			want: provider.Limits{PageSize: 1, MaxPages: 1, MaxObjects: 1, MaxBytes: provider.MinMaxBytes}},
		"exactly enough requests and bytes": {set: []string{"controller.collection.pageSize=1000", "controller.collection.maxRequests=100", "controller.collection.maxBytes=4096000"},
			want: provider.Limits{PageSize: 1000, MaxPages: 100, MaxObjects: 100_000, MaxBytes: 4_096_000}},
	} {
		docs, out, err := render(t, "konstapel-system", append([]string{"image.digest=" + digest}, tc.set...)...)
		if err != nil {
			t.Fatalf("%s: %s", name, out)
		}
		if l := renderedCollection(t, docs); l != tc.want || l.ValidateConfiguration() != nil {
			t.Fatalf("%s: limits %+v (%v), want %+v", name, l, l.ValidateConfiguration(), tc.want)
		}
	}
	// schema is the schema's refusal of one value.
	schema := func(field string) string { return "at '/controller/collection/" + field + "'" }
	for name, tc := range map[string]struct {
		set  []string
		want string
	}{
		"zero page size":        {set: []string{"controller.collection.pageSize=0"}, want: schema("pageSize")},
		"page size above 10000": {set: []string{"controller.collection.pageSize=10001", "controller.collection.maxBytes=1073741824"}, want: schema("pageSize")},
		"page above objects":    {set: []string{"controller.collection.maxObjects=499"}, want: "controller.collection.pageSize (500) must not exceed controller.collection.maxObjects (499)"},
		"zero objects":          {set: []string{"controller.collection.maxObjects=0"}, want: schema("maxObjects")},
		"too many objects":      {set: []string{"controller.collection.maxObjects=10000001"}, want: schema("maxObjects")},
		"zero requests":         {set: []string{"controller.collection.maxRequests=0"}, want: schema("maxRequests")},
		"too many requests":     {set: []string{"controller.collection.maxRequests=1000001"}, want: schema("maxRequests")},
		"unreachable objects":   {set: []string{"controller.collection.maxRequests=199"}, want: "controller.collection.maxRequests (199) is fewer than the 200 list requests"},
		"bytes below an object": {set: []string{"controller.collection.maxBytes=1572863"}, want: schema("maxBytes")},
		"bytes below a page":    {set: []string{"controller.collection.pageSize=1000", "controller.collection.maxBytes=4095999"}, want: "controller.collection.maxBytes (4095999) must be at least 4096000"},
		"too many bytes":        {set: []string{"controller.collection.maxBytes=68719476737"}, want: schema("maxBytes")},
		"fractional objects":    {set: []string{"controller.collection.maxObjects=1.5"}, want: schema("maxObjects")},
		"a quantity":            {set: []string{"controller.collection.maxBytes=1Gi"}, want: schema("maxBytes")},
		"a deadline":            {set: []string{"controller.collection.timeout=10m"}, want: "at '/controller/collection': additional properties 'timeout' not allowed"},
	} {
		_, out, err := render(t, "konstapel-system", append([]string{"image.digest=" + digest}, tc.set...)...)
		if err == nil {
			t.Errorf("%s accepted", name)
		} else if !strings.Contains(out, tc.want) {
			t.Errorf("%s: %s", name, out)
		}
	}
}
