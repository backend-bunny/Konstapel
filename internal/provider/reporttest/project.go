package reporttest

// Namespace extraction of the synthetic payload (add-assessment-provider-
// contract 3.3). It exercises the shared projection seam with a shape
// unlike Kyverno's. A posture report is cluster-wide, names no namespace and
// is shared by every workload, in any namespace, that runs its image.

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/backend-bunny/Konstapel/internal/provider/projection"
)

// Extractor is the synthetic provider's projection.Extractor for
// payload version 1.
type Extractor struct{}

var _ projection.Extractor = Extractor{}

// Extract keeps the subjects of the namespace instance ns.UID. It keeps only
// the posture reports for an image digest that one of those subjects runs,
// rebuilt with the frozen checks' verdicts only. The extract is traceable
// to its source, because a kept report keeps its ID and digest.
//
// A report shared with other namespaces' workloads describes the image,
// which this namespace runs, and names none of them, so it is kept. A report
// that only other namespaces' subjects use is dropped, and so is one that
// only a subject of unknown scope (no namespace UID) uses. Such a subject is
// never disclosed.
func (Extractor) Extract(raw json.RawMessage, ns projection.Scope) (json.RawMessage, error) {
	if ns.UID == "" {
		return nil, errors.New("the scope names no namespace instance")
	}
	in, _, err := decode(raw)
	if err != nil {
		return nil, err
	}
	out := Input{PayloadVersion: in.PayloadVersion, MaxEvidenceAge: in.MaxEvidenceAge, Checks: slices.Clone(in.Checks), Subjects: []Subject{}, Reports: []Report{}}
	digests := map[string]bool{}
	for _, s := range in.Subjects {
		if s.NamespaceUID != ns.UID {
			continue
		}
		out.Subjects = append(out.Subjects, s)
		if d := s.digest(); d != "" {
			digests[d] = true
		}
	}
	for _, r := range in.Reports {
		if !digests[r.Digest] {
			continue
		}
		kept := Report{ID: r.ID, Digest: r.Digest, EvaluatedAt: r.EvaluatedAt, UpdatedAt: r.UpdatedAt, Verdicts: map[string]string{}}
		for _, c := range in.Checks {
			if v, ok := r.Verdicts[c]; ok {
				kept.Verdicts[c] = v
			}
		}
		out.Reports = append(out.Reports, kept)
	}
	return json.Marshal(out)
}

// Disclosures lists the namespaces an extract names. A subject names its
// namespace UID. A report names no namespace, so it is attributed to the
// subjects of the extract that run its digest. A report that no subject runs
// has unknown scope. An extract that keeps a verdict for a check outside
// the frozen checks could not have been extracted and is an error.
func (Extractor) Disclosures(raw json.RawMessage) ([]projection.Disclosure, error) {
	in, _, err := decode(raw)
	if err != nil {
		return nil, err
	}
	var out []projection.Disclosure
	runners := map[string]map[string]bool{}
	for i, s := range in.Subjects {
		out = append(out, projection.Disclosure{Item: fmt.Sprintf("subjects[%d]", i), NamespaceUID: s.NamespaceUID})
		if d := s.digest(); d != "" && s.NamespaceUID != "" {
			if runners[d] == nil {
				runners[d] = map[string]bool{}
			}
			runners[d][s.NamespaceUID] = true
		}
	}
	for i, r := range in.Reports {
		item := fmt.Sprintf("reports[%d]", i)
		for c := range r.Verdicts {
			if !slices.Contains(in.Checks, c) {
				return nil, fmt.Errorf("%s keeps a verdict for a check that is not frozen", item)
			}
		}
		uids := slices.Sorted(maps.Keys(runners[r.Digest]))
		if len(uids) == 0 {
			out = append(out, projection.Disclosure{Item: item})
		}
		for _, uid := range uids {
			out = append(out, projection.Disclosure{Item: item, NamespaceUID: uid})
		}
	}
	return out, nil
}
