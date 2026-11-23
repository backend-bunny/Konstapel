package reporttest

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/backend-bunny/Konstapel/internal/provider"
)

// Postures is the synthetic provider's only read: cluster-scoped posture
// reports, one per image digest, shared by every workload running that
// image in any namespace.
func Postures() provider.Read {
	return provider.Read{Group: "reporttest.konstapel.io", Version: "v1", Resource: "postures", Kind: "Posture", Verbs: []string{"get", "list"}}
}

// posture is the synthetic source object layout.
type posture struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Digest      string            `json:"digest"`
	EvaluatedAt *time.Time        `json:"evaluatedAt,omitempty"`
	UpdatedAt   *time.Time        `json:"updatedAt,omitempty"`
	Verdicts    map[string]string `json:"verdicts"`
}

// Collect is the synthetic collection adapter, deliberately unlike
// Kyverno's: its source is cluster-scoped and shared across namespaces, so
// it lists the source once and keeps only the reports for a digest some
// frozen subject runs. Other images' reports are never retained. A subject
// outside the host-frozen scope is an error: collection never widens scope.
// An object of another layout is a limitation and is not used, never empty
// evidence; a failed list is a limitation with no reports, so every
// observation stays missing. A tag-only subject needs no report: it cannot
// be attributed (Unresolved at evaluation). With no subjects nothing is
// read.
func Collect(ctx context.Context, scope provider.Scope, subjects []Subject, sources provider.Sources) ([]Report, []string, error) {
	wanted := map[string]bool{}
	for _, s := range subjects {
		if !scope.HasNamespaceUID(s.NamespaceUID) {
			return nil, nil, fmt.Errorf("subject %s is outside the collection scope", s.key())
		}
		if d := s.digest(); d != "" {
			wanted[d] = true
		}
	}
	if len(wanted) == 0 {
		return []Report{}, nil, nil
	}
	reader, err := sources.Source(Postures())
	if err != nil {
		return nil, nil, err
	}
	objects, err := reader.List(ctx, "")
	if err != nil {
		return []Report{}, []string{"postures unavailable: " + err.Error()}, nil
	}
	reports := []Report{}
	var limits []string
	for _, o := range objects {
		raw, err := json.Marshal(o)
		var p posture
		if err == nil {
			err = json.Unmarshal(raw, &p)
		}
		switch {
		case err != nil:
		case p.APIVersion != Postures().Group+"/"+Postures().Version || p.Kind != Postures().Kind:
			err = fmt.Errorf("layout %s/%s is not supported", p.APIVersion, p.Kind)
		case p.Metadata.Name == "":
			err = fmt.Errorf("has no name")
		case (Subject{Image: "x@" + p.Digest}).digest() == "":
			err = fmt.Errorf("digest %q is not a sha256 digest", p.Digest)
		}
		if err != nil {
			limits = append(limits, fmt.Sprintf("posture %q is not used as evidence: %v", p.Metadata.Name, err))
			continue
		}
		if !wanted[p.Digest] {
			continue
		}
		reports = append(reports, Report{ID: p.Metadata.Name, Digest: p.Digest, EvaluatedAt: p.EvaluatedAt, UpdatedAt: p.UpdatedAt, Verdicts: p.Verdicts})
	}
	slices.SortFunc(reports, func(a, b Report) int { return cmp.Compare(a.ID, b.ID) })
	return reports, limits, nil
}
