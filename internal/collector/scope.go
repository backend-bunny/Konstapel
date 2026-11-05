package collector

import (
	"cmp"
	"fmt"
	"slices"
	"time"

	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// ChangeKind classifies a change observed while a capture's scope is frozen.
type ChangeKind string

const (
	// WorkloadUpdated: an expected workload's relevant state changed in place.
	WorkloadUpdated ChangeKind = "WorkloadUpdated"
	// WorkloadRemoved: an expected workload was deleted.
	WorkloadRemoved ChangeKind = "WorkloadRemoved"
	// WorkloadReplaced: a workload with an expected workload's namespace,
	// resource, and name appeared under a new UID.
	WorkloadReplaced ChangeKind = "WorkloadReplaced"
	// WorkloadAdded: a new workload appeared in a frozen namespace. It is not
	// added to the snapshot.
	WorkloadAdded ChangeKind = "WorkloadAdded"
	// NamespaceJoined: a namespace instance started matching. It is not added
	// to the snapshot.
	NamespaceJoined ChangeKind = "NamespaceJoined"
	// NamespaceLeft: a frozen namespace instance stopped matching or was deleted.
	NamespaceLeft ChangeKind = "NamespaceLeft"
	// NamespaceRecreated: a frozen namespace name returned under a new UID.
	NamespaceRecreated ChangeKind = "NamespaceRecreated"
	// ConfigurationChanged: a frozen contribution's revision changed or its
	// scope became stale.
	ConfigurationChanged ChangeKind = "ConfigurationChanged"
)

// ScopeChange is one recorded change. Frozen identities stay in the expected
// inventory; changes explain why their evidence may be unattributable.
type ScopeChange struct {
	Kind         ChangeKind `json:"kind"`
	Observed     time.Time  `json:"observed"`
	Namespace    string     `json:"namespace,omitempty"`
	NamespaceUID string     `json:"namespaceUID,omitempty"`
	// Previous is the frozen workload; Current is what was observed.
	Previous      *Workload `json:"previous,omitempty"`
	Current       *Workload `json:"current,omitempty"`
	BindingUID    string    `json:"bindingUID,omitempty"`
	LogicalPolicy string    `json:"logicalPolicy,omitempty"`
	Revision      string    `json:"revision,omitempty"`
	Detail        string    `json:"detail,omitempty"`
}

// Tracker records changes against a frozen capture scope. It never alters the
// frozen subjects, workloads, or expected inventory.
type Tracker struct {
	c          *CaptureV2
	workloads  map[string]Workload // frozen, by UID
	byName     map[string]Workload // frozen, by namespace UID/resource/name
	namespaces map[string]string   // frozen namespace UID -> name
	nsByName   map[string]string   // frozen namespace name -> UID
	resources  map[string]bool     // resources any frozen subject matches
	latest     map[string]string   // workload UID -> last recorded state
	recorded   map[string]bool
}

// NewTracker starts tracking changes for c, whose scope is frozen.
func NewTracker(c *CaptureV2) *Tracker {
	t := &Tracker{c: c, workloads: map[string]Workload{}, byName: map[string]Workload{}, namespaces: map[string]string{},
		nsByName: map[string]string{}, resources: map[string]bool{}, latest: map[string]string{}, recorded: map[string]bool{}}
	for _, s := range c.Subjects {
		t.namespaces[string(s.NamespaceUID)] = s.Namespace
		t.nsByName[s.Namespace] = string(s.NamespaceUID)
		for _, r := range s.Resources {
			t.resources[r] = true
		}
	}
	for _, w := range c.Workloads {
		t.workloads[w.UID] = w
		t.byName[w.NamespaceUID+"/"+w.Resource+"/"+w.Name] = w
		t.latest[w.UID] = w.StateSHA256
	}
	return t
}

func (t *Tracker) record(ch ScopeChange) {
	if ch.Observed.Before(t.c.Window.Started) || (!t.c.Window.Closed.IsZero() && ch.Observed.After(t.c.Window.Closed)) {
		return // outside the collection window
	}
	key := fmt.Sprint(ch.Kind, ch.NamespaceUID, ch.BindingUID, ch.LogicalPolicy, ch.Revision, ch.Detail, ch.Current, ch.Previous)
	if t.recorded[key] {
		return
	}
	t.recorded[key] = true
	t.c.ScopeChanges = append(t.c.ScopeChanges, ch)
}

// Workload records an observed workload add/update (deleted=false) or delete.
func (t *Tracker) Workload(at time.Time, w Workload, deleted bool) {
	if !t.resources[w.Resource] {
		return
	}
	if frozen, ok := t.workloads[w.UID]; ok {
		prev := frozen
		switch {
		case deleted:
			t.record(ScopeChange{Kind: WorkloadRemoved, Observed: at, Namespace: w.Namespace, NamespaceUID: w.NamespaceUID, Previous: &prev})
		case w.StateSHA256 != t.latest[w.UID]:
			t.latest[w.UID] = w.StateSHA256
			cur := w
			t.record(ScopeChange{Kind: WorkloadUpdated, Observed: at, Namespace: w.Namespace, NamespaceUID: w.NamespaceUID, Previous: &prev, Current: &cur})
		}
		return
	}
	if _, frozenNS := t.namespaces[w.NamespaceUID]; !frozenNS || deleted {
		return // outside the frozen scope; namespace joins are configuration changes
	}
	cur := w
	if frozen, ok := t.byName[w.NamespaceUID+"/"+w.Resource+"/"+w.Name]; ok {
		prev := frozen
		t.record(ScopeChange{Kind: WorkloadReplaced, Observed: at, Namespace: w.Namespace, NamespaceUID: w.NamespaceUID, Previous: &prev, Current: &cur})
		return
	}
	t.record(ScopeChange{Kind: WorkloadAdded, Observed: at, Namespace: w.Namespace, NamespaceUID: w.NamespaceUID, Current: &cur})
}

// Configuration records namespace membership and contribution changes found
// by re-resolving targeting during collection.
func (t *Tracker) Configuration(at time.Time, subjects []targeting.EvidenceSubject, stale []targeting.StaleScope) {
	type contribution struct{ ns, binding, policy string }
	frozen := map[contribution]string{}
	for _, s := range t.c.Subjects {
		frozen[contribution{string(s.NamespaceUID), string(s.BindingUID), s.LogicalPolicy}] = s.Revision
	}
	current := map[contribution]string{}
	currentNS := map[string]string{}
	for _, s := range subjects {
		current[contribution{string(s.NamespaceUID), string(s.BindingUID), s.LogicalPolicy}] = s.Revision
		currentNS[string(s.NamespaceUID)] = s.Namespace
	}
	for uid, name := range sortedMap(currentNS) {
		if _, ok := t.namespaces[uid]; ok {
			continue
		}
		if old, ok := t.nsByName[name]; ok && old != uid {
			t.record(ScopeChange{Kind: NamespaceRecreated, Observed: at, Namespace: name, NamespaceUID: uid, Detail: "replaces namespace UID " + old})
			continue
		}
		t.record(ScopeChange{Kind: NamespaceJoined, Observed: at, Namespace: name, NamespaceUID: uid})
	}
	for uid, name := range sortedMap(t.namespaces) {
		if _, ok := currentNS[uid]; !ok {
			t.record(ScopeChange{Kind: NamespaceLeft, Observed: at, Namespace: name, NamespaceUID: uid})
		}
	}
	keys := make([]contribution, 0, len(frozen))
	for k := range frozen {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b contribution) int {
		return cmp.Or(cmp.Compare(a.ns, b.ns), cmp.Compare(a.binding, b.binding), cmp.Compare(a.policy, b.policy))
	})
	for _, k := range keys {
		rev, ok := current[k]
		if _, nsPresent := currentNS[k.ns]; ok && rev != frozen[k] || !ok && nsPresent {
			t.record(ScopeChange{Kind: ConfigurationChanged, Observed: at, NamespaceUID: k.ns, BindingUID: k.binding, LogicalPolicy: k.policy, Revision: rev, Detail: "frozen revision " + frozen[k]})
		}
	}
	for _, s := range stale {
		t.record(ScopeChange{Kind: ConfigurationChanged, Observed: at, BindingUID: string(s.Binding.UID), LogicalPolicy: s.Policy, Detail: "stale: " + string(s.Reason) + ": " + s.Message})
	}
}

// ChangeFor returns the first recorded change that makes evidence for e
// unattributable to its frozen identity.
func (c CaptureV2) ChangeFor(e Expected) (ScopeChange, bool) {
	for _, ch := range c.ScopeChanges {
		switch ch.Kind {
		case WorkloadUpdated, WorkloadRemoved, WorkloadReplaced:
			if ch.Previous != nil && ch.Previous.UID == e.Workload.UID {
				return ch, true
			}
		case NamespaceLeft:
			if ch.NamespaceUID == e.NamespaceUID {
				return ch, true
			}
		case ConfigurationChanged:
			if ch.BindingUID == e.Contribution.BindingUID && (ch.LogicalPolicy == "" || ch.LogicalPolicy == e.Contribution.LogicalPolicy) && (ch.NamespaceUID == "" || ch.NamespaceUID == e.NamespaceUID) {
				return ch, true
			}
		}
	}
	return ScopeChange{}, false
}

// sortedMap iterates a string map in key order.
func sortedMap(m map[string]string) func(func(string, string) bool) {
	return func(yield func(string, string) bool) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			if !yield(k, m[k]) {
				return
			}
		}
	}
}
