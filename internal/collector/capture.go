package collector

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// CaptureV2Version is the controller capture format. The prototype's
// single-policy assessment.Capture (version 1) and its commands remain unchanged.
const CaptureV2Version = 2

// Check is one logical check of a delivered engine policy: one CEL
// sub-validation. Kyverno reports identify it by the validationIndex result
// property; the vendored content does not name validations.
type Check struct {
	EnginePolicy string `json:"enginePolicy"`
	Index        int    `json:"validationIndex"`
	// Name is set only when the content names the validation.
	Name string `json:"name,omitempty"`
	// SHA256 digests the validation together with the policy variables it can
	// read, so a changed expression is a different check.
	SHA256 string `json:"sha256"`
}

// Workload is one listed resource instance and the digest of the state that
// policies and exception selection can read.
type Workload struct {
	// Resource is "group/version/resource", with "" for the core group.
	Resource     string `json:"resource"`
	Namespace    string `json:"namespace"`
	NamespaceUID string `json:"namespaceUID"`
	Name         string `json:"name"`
	UID          string `json:"uid"`
	StateSHA256  string `json:"stateSha256"`
}

// Contribution identifies the binding contribution an observation belongs to.
// Overlapping bindings are distinct contributions of the same logical check.
type Contribution struct {
	BindingUID    string `json:"bindingUID"`
	Revision      string `json:"revision"`
	EnginePolicy  string `json:"enginePolicy"`
	LogicalPolicy string `json:"logicalPolicy"`
	Mode          string `json:"mode"`
}

// Expected is one expected observation: a check of one contribution against
// one workload state in one namespace instance.
type Expected struct {
	Cluster       string       `json:"cluster"`
	NamespaceUID  string       `json:"namespaceUID"`
	Workload      Workload     `json:"workload"`
	Check         Check        `json:"check"`
	Contribution  Contribution `json:"contribution"`
	SourceSHA256  string       `json:"sourceSha256"`
	MappingSHA256 string       `json:"mappingSha256"`
}

// Key is the observation identity. Any change to cluster, namespace instance,
// workload instance or state, check, contribution, or source/mapping revision
// is a different expected observation.
func (e Expected) Key() string {
	return strings.Join([]string{e.Cluster, e.NamespaceUID, e.Workload.Resource, e.Workload.UID, e.Workload.StateSHA256,
		e.Check.EnginePolicy, strconv.Itoa(e.Check.Index), e.Check.SHA256,
		e.Contribution.BindingUID, e.Contribution.Revision, e.SourceSHA256, e.MappingSHA256}, "\x00")
}

// CaptureWindow is the bounded observation window of a controller capture.
type CaptureWindow struct {
	Started time.Time `json:"started"`
	Closed  time.Time `json:"closed"`
}

// CaptureV2 is the versioned controller capture. Its expected inventory is
// derived from targeting subjects, rendered-policy checks, and listed
// workloads, never from received reports, so missing reports stay missing.
type CaptureV2 struct {
	Version          int                         `json:"version"`
	Cluster          string                      `json:"cluster"`
	Window           CaptureWindow               `json:"window"`
	MappingSHA256    string                      `json:"mappingSha256"`
	Subjects         []targeting.EvidenceSubject `json:"subjects"`
	Stale            []targeting.StaleScope      `json:"stale"`
	Checks           []Check                     `json:"checks"`
	Workloads        []Workload                  `json:"workloads"`
	Expected         []Expected                  `json:"expected"`
	Reports          []assessment.Object         `json:"reports"`
	CollectionErrors []string                    `json:"collectionErrors,omitempty"`
	// ScopeChanges are changes observed during collection. They never alter
	// the frozen subjects, workloads, or expected inventory.
	ScopeChanges []ScopeChange `json:"scopeChanges,omitempty"`
	// Projection is set when the capture was projected to one namespace.
	Projection *Projection `json:"projection,omitempty"`
}

// PolicyChecks enumerates a rendered engine policy's sub-validations in
// index order. named supplies validation names when the content has them.
func PolicyChecks(rendered assessment.Object, named []string) ([]Check, error) {
	name := assessment.Str(assessment.At(rendered, "metadata", "name"))
	validations, _ := assessment.At(rendered, "spec", "validations").([]any)
	if name == "" || len(validations) == 0 {
		return nil, fmt.Errorf("policy %q has no validations", name)
	}
	if len(named) > 0 && len(named) != len(validations) {
		return nil, fmt.Errorf("policy %s: %d names for %d validations", name, len(named), len(validations))
	}
	variables := assessment.At(rendered, "spec", "variables")
	out := make([]Check, len(validations))
	for i, v := range validations {
		out[i] = Check{EnginePolicy: name, Index: i, SHA256: assessment.Digest(assessment.Object{"validation": v, "variables": variables})}
		if len(named) > 0 {
			out[i].Name = named[i]
		}
	}
	return out, nil
}

// WorkloadState digests the inputs a supported policy or exception selector
// can read: spec, labels, and annotations. Status, resourceVersion, and
// managed fields are excluded, so status-only updates keep the same state.
func WorkloadState(obj assessment.Object) string {
	meta := assessment.Map(obj["metadata"])
	return assessment.Digest(assessment.Object{"spec": obj["spec"], "labels": meta["labels"], "annotations": meta["annotations"]})
}

// BuildInventory derives the expected observations. checks must contain
// every subject's engine policy. Overlapping bindings yield distinct
// contributions; namespaces match by UID only.
func BuildInventory(subjects []targeting.EvidenceSubject, checks []Check, workloads []Workload, mappingSHA256 string) ([]Expected, error) {
	byPolicy := map[string][]Check{}
	for _, c := range checks {
		byPolicy[c.EnginePolicy] = append(byPolicy[c.EnginePolicy], c)
	}
	out := []Expected{}
	seen := map[string]bool{}
	for _, s := range subjects {
		policyChecks := byPolicy[s.EnginePolicy]
		if len(policyChecks) == 0 {
			return nil, fmt.Errorf("no checks for engine policy %s", s.EnginePolicy)
		}
		for _, w := range workloads {
			if w.NamespaceUID != string(s.NamespaceUID) || !slices.Contains(s.Resources, w.Resource) {
				continue
			}
			for _, c := range policyChecks {
				e := Expected{
					Cluster: s.Cluster, NamespaceUID: string(s.NamespaceUID), Workload: w, Check: c,
					Contribution:  Contribution{BindingUID: string(s.BindingUID), Revision: s.Revision, EnginePolicy: s.EnginePolicy, LogicalPolicy: s.LogicalPolicy, Mode: string(s.Mode)},
					SourceSHA256:  s.SourceDigest,
					MappingSHA256: mappingSHA256,
				}
				k := e.Key()
				if seen[k] {
					return nil, fmt.Errorf("duplicate expected observation for %s/%s %s check %d", w.Namespace, w.Name, s.EnginePolicy, c.Index)
				}
				seen[k] = true
				out = append(out, e)
			}
		}
	}
	slices.SortFunc(out, func(a, b Expected) int { return cmp.Compare(a.Key(), b.Key()) })
	return out, nil
}

// Validate checks the capture's version and that its expected inventory is
// exactly the inventory derived from its recorded inputs, so a capture cannot
// narrow its denominator or add unexplained observations.
func (c CaptureV2) Validate() error {
	if c.Version != CaptureV2Version {
		return fmt.Errorf("capture version %d is not %d", c.Version, CaptureV2Version)
	}
	if c.Cluster == "" || c.MappingSHA256 == "" || c.Window.Started.IsZero() || c.Window.Closed.Before(c.Window.Started) {
		return errors.New("capture requires cluster, mapping digest, and an ordered window")
	}
	for _, s := range c.Subjects {
		if s.Cluster != c.Cluster {
			return fmt.Errorf("subject for cluster %q in capture of %q", s.Cluster, c.Cluster)
		}
	}
	for _, ch := range c.ScopeChanges {
		if ch.Observed.Before(c.Window.Started) || ch.Observed.After(c.Window.Closed) {
			return fmt.Errorf("%s change at %s is outside the capture window", ch.Kind, ch.Observed)
		}
	}
	want, err := BuildInventory(c.Subjects, c.Checks, c.Workloads, c.MappingSHA256)
	if err != nil {
		return err
	}
	a, _ := json.Marshal(want)
	b, _ := json.Marshal(c.Expected)
	if string(a) != string(b) {
		return errors.New("expected inventory does not match its recorded subjects, checks, and workloads")
	}
	return nil
}

// CaptureVersion reports a capture document's format version without
// decoding the rest, so callers can dispatch to the v1 or v2 path.
func CaptureVersion(b []byte) (int, error) {
	var v struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return 0, err
	}
	switch v.Version {
	case 1, CaptureV2Version:
		return v.Version, nil
	}
	return 0, fmt.Errorf("unsupported capture version %d", v.Version)
}

// ListedObject is a resource instance listed when a run starts, with the
// namespace UID resolved by the lister.
type ListedObject struct {
	// Resource is "group/version/resource", with "" for the core group.
	Resource     string
	NamespaceUID string
	Object       assessment.Object
}

// FreezeScope captures a run's initial scope: the targeting subjects and
// stale scopes, the checks of every rendered engine policy, and the listed
// workloads. It derives the expected inventory before any report is read.
func FreezeScope(cluster string, started time.Time, mappingSHA256 string, subjects []targeting.EvidenceSubject, stale []targeting.StaleScope, rendered []assessment.Object, listed []ListedObject) (CaptureV2, error) {
	c := CaptureV2{Version: CaptureV2Version, Cluster: cluster, Window: CaptureWindow{Started: started}, MappingSHA256: mappingSHA256,
		Subjects: slices.Clone(subjects), Stale: slices.Clone(stale), Checks: []Check{}, Workloads: []Workload{}, Reports: []assessment.Object{}}
	if c.Subjects == nil {
		c.Subjects = []targeting.EvidenceSubject{}
	}
	if c.Stale == nil {
		c.Stale = []targeting.StaleScope{}
	}
	named := map[string][]string{}
	for _, s := range subjects {
		named[s.EnginePolicy] = s.Checks
	}
	for _, p := range rendered {
		checks, err := PolicyChecks(p, named[assessment.Str(assessment.At(p, "metadata", "name"))])
		if err != nil {
			return c, err
		}
		c.Checks = append(c.Checks, checks...)
	}
	for _, l := range listed {
		meta := assessment.Map(l.Object["metadata"])
		w := Workload{Resource: l.Resource, Namespace: assessment.Str(meta["namespace"]), NamespaceUID: l.NamespaceUID, Name: assessment.Str(meta["name"]), UID: assessment.Str(meta["uid"]), StateSHA256: WorkloadState(l.Object)}
		if w.UID == "" || w.Name == "" || w.NamespaceUID == "" || w.Resource == "" {
			return c, fmt.Errorf("listed %s object %s/%s lacks identity", l.Resource, w.Namespace, w.Name)
		}
		c.Workloads = append(c.Workloads, w)
	}
	slices.SortFunc(c.Workloads, func(a, b Workload) int {
		return cmp.Or(cmp.Compare(a.NamespaceUID, b.NamespaceUID), cmp.Compare(a.Resource, b.Resource), cmp.Compare(a.Name, b.Name), cmp.Compare(a.UID, b.UID))
	})
	inv, err := BuildInventory(c.Subjects, c.Checks, c.Workloads, mappingSHA256)
	if err != nil {
		return c, err
	}
	c.Expected = inv
	if c.Expected == nil {
		c.Expected = []Expected{}
	}
	return c, nil
}
