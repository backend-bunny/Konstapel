package reporttest_test

import (
	"flag"
	"path/filepath"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/provider/conformance"
	"github.com/backend-bunny/Konstapel/internal/provider/reporttest"
)

var update = flag.Bool("update", false, "rewrite the synthetic reporting conformance golden results")

func TestReportingConformance(t *testing.T) {
	root, err := filepath.Abs("../../../testdata/providers/conformance/v1/konstapel-reporttest")
	if err != nil {
		t.Fatal(err)
	}
	conformance.Run(t, reporttest.Adapter{}, root, *update)
}
