package controller

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Display bounds for engine readiness diagnostics in EngineReady. They are
// chosen so the first diagnostic, the omitted count, the inspection command
// and the retained list always fit in maxMessage together
// (TestPendingMessageWorstCaseFits).
const (
	maxDiagReason   = 64
	maxDiagMessage  = 200
	maxDiagPolicies = 2
	maxDiagRetained = 200
	maxDiagUID      = 64
	// omittedReserve fits "; N more diagnostics not shown" for any count.
	omittedReserve = 48
)

// readinessGroup is one distinct failing condition and the policies that
// report it.
type readinessGroup struct {
	condition string
	state     targeting.ReadinessState
	reason    string
	message   string
	policies  []string
}

// pendingMessage explains ReplacementPending: the failing Kyverno readiness
// conditions with policy attribution first, then the retained revisions.
// Equivalent failures are grouped, groups are ordered by their first policy
// and condition, and engine text is sanitized and truncated. When anything
// is left out, the message gives the omitted count and a kubectl command
// that lists the binding's policies with their full conditions. The output
// depends only on its inputs, so an unchanged engine state never rewrites
// status.
func pendingMessage(s targeting.DeliveryResult, binding types.UID) string {
	const head = "waiting for engine readiness"
	details := s.Readiness
	for _, name := range s.NotReady {
		// Delivery attributes every NotReady policy; keep that true for
		// any other caller.
		if !slices.ContainsFunc(details, func(d targeting.ReadinessDetail) bool { return d.Policy == name }) {
			details = append(slices.Clip(details), targeting.ReadinessDetail{Policy: name, State: targeting.ReadinessUnknown})
		}
	}
	groups := groupReadiness(details)
	parts := make([]string, len(groups))
	clipped := false
	for i, g := range groups {
		var c bool
		parts[i], c = g.format()
		clipped = clipped || c
	}
	tail := ""
	if len(s.Retained) > 0 {
		list, c := boundedList(s.Retained, maxDiagRetained)
		clipped = clipped || c
		tail = "; retained until ready: " + list
	}
	hint := "inspect: kubectl get validatingpolicies -l " + targeting.LabelBindingUID + "=" +
		clipText(sanitizeDisplay(string(binding)), maxDiagUID) + " -o yaml"

	budget := maxMessage - len(head) - len(": ") - omittedReserve - len("; ") - len(hint) - len(tail)
	shown, used := 0, 0
	for i, p := range parts {
		add := len(p)
		if i > 0 {
			add += len("; ")
		}
		// The first diagnostic is always shown; the bounds above make
		// it fit.
		if i > 0 && used+add > budget {
			break
		}
		used += add
		shown++
	}
	var b strings.Builder
	b.WriteString(head)
	if shown > 0 {
		b.WriteString(": ")
		b.WriteString(strings.Join(parts[:shown], "; "))
	}
	omitted := len(parts) - shown
	if omitted > 0 {
		fmt.Fprintf(&b, "; %d more diagnostics not shown", omitted)
	}
	if omitted > 0 || clipped {
		b.WriteString("; ")
		b.WriteString(hint)
	}
	b.WriteString(tail)
	return truncateUTF8(b.String(), maxMessage)
}

// groupReadiness deduplicates details that report the same condition, state,
// reason and message after sanitization.
func groupReadiness(ds []targeting.ReadinessDetail) []readinessGroup {
	type key struct {
		condition string
		state     targeting.ReadinessState
		reason    string
		message   string
	}
	index := map[key]int{}
	var groups []readinessGroup
	for _, d := range ds {
		k := key{sanitizeDisplay(d.Condition), d.State, sanitizeDisplay(d.Reason), sanitizeDisplay(d.Message)}
		i, ok := index[k]
		if !ok {
			i = len(groups)
			index[k] = i
			groups = append(groups, readinessGroup{condition: k.condition, state: k.state, reason: k.reason, message: k.message})
		}
		if p := sanitizeDisplay(d.Policy); !slices.Contains(groups[i].policies, p) {
			groups[i].policies = append(groups[i].policies, p)
		}
	}
	for i := range groups {
		slices.Sort(groups[i].policies)
	}
	slices.SortFunc(groups, func(a, b readinessGroup) int {
		return cmp.Or(cmp.Compare(a.policies[0], b.policies[0]), cmp.Compare(a.condition, b.condition),
			cmp.Compare(a.state, b.state), cmp.Compare(a.reason, b.reason), cmp.Compare(a.message, b.message))
	})
	return groups
}

// format renders the group, reporting whether anything was cut.
func (g readinessGroup) format() (string, bool) {
	var b strings.Builder
	clipped := false
	if g.condition == "" {
		b.WriteString("not ready (no failing readiness condition reported)")
	} else {
		b.WriteString(clipText(g.condition, maxDiagReason))
		switch g.state {
		case targeting.ReadinessFalse:
			b.WriteString("=False")
		case targeting.ReadinessMissing:
			b.WriteString("=Unknown (condition missing)")
		case targeting.ReadinessMalformed:
			b.WriteString("=Unknown (condition malformed)")
		default:
			b.WriteString("=Unknown")
		}
	}
	if g.reason != "" {
		r := clipText(g.reason, maxDiagReason)
		clipped = clipped || r != g.reason
		b.WriteString(" " + r)
	}
	if g.message != "" {
		m := clipText(g.message, maxDiagMessage)
		clipped = clipped || m != g.message
		b.WriteString(`: "` + m + `"`)
	}
	b.WriteString(" on ")
	shown := g.policies[:min(len(g.policies), maxDiagPolicies)]
	b.WriteString(strings.Join(shown, ", "))
	if n := len(g.policies) - len(shown); n > 0 {
		fmt.Fprintf(&b, " and %d more", n)
		clipped = true
	}
	return b.String(), clipped
}

// boundedList joins names until max bytes, then counts the rest.
func boundedList(names []string, max int) (string, bool) {
	var b strings.Builder
	for i, n := range names {
		sep := ""
		if i > 0 {
			sep = ", "
		}
		if i > 0 && b.Len()+len(sep)+len(n) > max {
			fmt.Fprintf(&b, " and %d more", len(names)-i)
			return b.String(), true
		}
		b.WriteString(sep + clipText(sanitizeDisplay(n), max))
	}
	return b.String(), false
}

// sanitizeDisplay makes engine-supplied text safe for a one-line status
// message: invalid UTF-8 becomes U+FFFD, control and format characters
// (including line breaks and bidirectional overrides) and whitespace runs
// become one space, and double quotes become single quotes so a quoted
// message cannot be confused with the surrounding text.
func sanitizeDisplay(s string) string {
	s = strings.ToValidUTF8(s, "�")
	var b strings.Builder
	space := false
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		if r == '"' {
			r = '\''
		}
		b.WriteRune(r)
	}
	return b.String()
}

// clipText bounds s to max bytes, marking a cut with "...".
func clipText(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return truncateUTF8(s, max)
}

// truncateUTF8 is truncate for any byte bound that never splits a rune.
func truncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max - 3
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}
