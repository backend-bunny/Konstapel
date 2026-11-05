package v1alpha1_test

import (
	"strings"
	"testing"
)

// Assessment RBAC rules, checked against every Role and ClusterRole shipped in
// config/rbac. Admission policy (config/admission) additionally restricts which
// run scopes and triggers non-controller identities may create; that is
// verified live by scripts/check-assessment-access.sh.

const (
	teamRequesterRole = "konstapel-assessment-requester"
	platformRunRole   = "konstapel-assessment-operator"
)

func TestAssessmentStatusIsWritableOnlyByTheController(t *testing.T) {
	for _, r := range loadRoles(t) {
		if strings.HasPrefix(r.name, "konstapel-controller") {
			continue
		}
		for _, res := range []string{"assessmentrequests/status", "assessmentruns/status"} {
			for _, verb := range []string{"update", "patch", "create"} {
				if grants(r.rules, verb, res) {
					t.Errorf("%s may %s %s; status is controller-owned", r.name, verb, res)
				}
			}
		}
	}
}

func TestOnlyPlatformAndControllerCanCreateRuns(t *testing.T) {
	foundPlatform := false
	for _, r := range loadRoles(t) {
		allowed := grants(r.rules, "create", "assessmentruns")
		switch {
		case r.name == platformRunRole:
			foundPlatform = true
			if !allowed || r.kind != "ClusterRole" {
				t.Errorf("%s must be a ClusterRole allowing create assessmentruns", r.name)
			}
		case strings.HasPrefix(r.name, "konstapel-controller"):
		case allowed:
			t.Errorf("%s %s must not create assessmentruns", r.kind, r.name)
		}
	}
	if !foundPlatform {
		t.Fatalf("ClusterRole %s not found", platformRunRole)
	}
}

func TestTeamRoleIsNamespaceBoundAndCannotTouchRuns(t *testing.T) {
	var team *role
	roles := loadRoles(t)
	for i := range roles {
		if roles[i].name == teamRequesterRole {
			team = &roles[i]
		}
	}
	if team == nil {
		t.Fatalf("ClusterRole %s not found", teamRequesterRole)
	}
	for _, verb := range []string{"get", "list", "watch", "create"} {
		if !grants(team.rules, verb, "assessmentrequests") {
			t.Errorf("team role must allow %s assessmentrequests", verb)
		}
	}
	if !grants(team.rules, "get", "assessmentrequests/download") {
		t.Error("team role must carry the namespace download attribute")
	}
	for _, res := range []string{"assessmentruns", "assessmentruns/status", "assessmentruns/download"} {
		for _, verb := range []string{"get", "list", "watch", "create", "update", "patch", "delete"} {
			if grants(team.rules, verb, res) {
				t.Errorf("team role must not %s %s", verb, res)
			}
		}
	}
	// Requests are immutable and requester identity is admission-owned.
	for _, verb := range []string{"update", "patch"} {
		if grants(team.rules, verb, "assessmentrequests") {
			t.Errorf("team role must not %s assessmentrequests", verb)
		}
	}
	for _, rule := range team.rules {
		for _, v := range rule.Verbs {
			if v == "*" {
				t.Error("team role must not use wildcard verbs")
			}
		}
	}
}
