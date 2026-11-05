package assessment

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	oscal "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/oscal-compass/compliance-to-policy-go/v2/framework/actions"
	"github.com/oscal-compass/compliance-to-policy-go/v2/plugin"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
)

func pod(name, ns, owner string, privileged bool) Object {
	return Object{"apiVersion": "v1", "kind": "Pod", "metadata": Object{"name": name, "namespace": ns, "labels": Object{OwnerLabel: owner}}, "spec": Object{"containers": []any{Object{"name": "app", "image": WorkloadImage, "command": []any{"sleep", "3600"}, "securityContext": Object{"privileged": privileged}}}}}
}

const WorkloadImage = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"

// Keep the API server's admission message in diagnostic evidence and denial checks.
func admissionResponse(obj Object, err error) []byte {
	if err != nil {
		return []byte(err.Error())
	}
	data, _ := json.Marshal(obj)
	return data
}

func CheckAdmission(response []byte, requestErr error, denied bool) error {
	if denied {
		if requestErr == nil || !strings.Contains(string(response), "Policy "+PolicyName+" failed") || !strings.Contains(string(response), "Privileged mode is disallowed") {
			return fmt.Errorf("expected policy-specific denial, got %v: %s", requestErr, response)
		}
	} else if requestErr != nil {
		return fmt.Errorf("unexpected rejection: %w", requestErr)
	}
	return nil
}

func resource(o Object) Resource {
	return Resource{APIVersion: Str(o["apiVersion"]), Kind: Str(o["kind"]), Namespace: Str(At(o, "metadata", "namespace")), Name: Str(At(o, "metadata", "name")), UID: Str(At(o, "metadata", "uid"))}
}

func (t *Target) Capture(ctx context.Context, root string, p Object, expected []Resource, boundary time.Time) Capture {
	c := Capture{Version: 1, Cluster: t.Cluster, Context: t.Context, Boundary: boundary, Policy: p, PolicyDigest: Digest(p["spec"]), MappingDigest: FileHash(filepath.Join(root, "content/component-definition.json")), Expected: expected, Reports: []Object{}}
	for _, gvk := range []schema.GroupVersionKind{reportGVK, clusterReportGVK} {
		list, err := t.List(ctx, gvk)
		if err != nil {
			c.CollectionErrors = append(c.CollectionErrors, err.Error())
			continue
		}
		items, ok := list["items"].([]any)
		if !ok {
			c.CollectionErrors = append(c.CollectionErrors, "missing report items")
			continue
		}
		for _, item := range items {
			c.Reports = append(c.Reports, Map(item))
		}
	}
	current, err := t.Get(ctx, policyGVK, "", PolicyName)
	if err != nil {
		c.CollectionErrors = append(c.CollectionErrors, err.Error())
	} else if Str(At(current, "metadata", "uid")) != Str(At(p, "metadata", "uid")) || Digest(current["spec"]) != c.PolicyDigest {
		c.CollectionErrors = append(c.CollectionErrors, "policy identity/revision changed during collection")
	}
	// Inventory is independent of reports: an old report cannot establish that
	// an admitted resource still exists with the original identity.
	for _, r := range expected {
		current, err := t.Get(ctx, schema.FromAPIVersionAndKind(r.APIVersion, r.Kind), r.Namespace, r.Name)
		if err != nil || Str(At(current, "metadata", "uid")) != r.UID {
			c.CollectionErrors = append(c.CollectionErrors, "expected resource missing/replaced: "+r.Key(t.Cluster))
		}
	}
	c.Collected = time.Now().UTC()
	return c
}

// Acceptance only operates against the documented disposable context. All cleanup
// checks ownership; diagnostic packages are retained even on failure.
func Acceptance(ctx context.Context, t *Target, root, out, ns, owner string, timeout time.Duration, input *actions.InputContext, plan *oscal.AssessmentPlan, p policy.Provider, providers map[plugin.ID]policy.Provider) (returnErr error) {
	if !regexp.MustCompile(`^kind-konstapel-assessment(-[a-z0-9-]+)?$`).MatchString(t.Context) || ns != "konstapel-acceptance" {
		return fmt.Errorf("acceptance requires a disposable kind-konstapel-assessment context and konstapel-acceptance namespace")
	}
	if err := os.MkdirAll(out, 0755); err != nil {
		return err
	}
	var admission []Object
	namespaceCreated, policyCreated := false, false
	defer func() {
		_ = Write(filepath.Join(out, "admission.json"), admission)
		for _, snapshot := range []struct {
			file  string
			kinds []schema.GroupVersionKind
		}{
			{"final-policies.json", []schema.GroupVersionKind{policyGVK}},
			{"final-reports.json", []schema.GroupVersionKind{reportGVK}},
			{"final-workloads.json", []schema.GroupVersionKind{podGVK, deploymentGVK}},
			{"events.json", []schema.GroupVersionKind{eventGVK}},
		} {
			items := []any{}
			var collectionErrors []string
			for _, gvk := range snapshot.kinds {
				list, err := t.List(context.Background(), gvk)
				if err != nil {
					collectionErrors = append(collectionErrors, err.Error())
					continue
				}
				found, _ := list["items"].([]any)
				items = append(items, found...)
			}
			diagnostic := Object{"apiVersion": "v1", "kind": "List", "items": items}
			if len(collectionErrors) > 0 {
				diagnostic["collectionErrors"] = collectionErrors
			}
			_ = Write(filepath.Join(out, snapshot.file), diagnostic)
		}
		for _, item := range []struct {
			gvk     schema.GroupVersionKind
			name    string
			created bool
		}{{policyGVK, PolicyName, policyCreated}, {namespaceGVK, ns, namespaceCreated}} {
			if item.created {
				if err := t.DeleteOwned(context.Background(), item.gvk, "", item.name, owner); err != nil && returnErr == nil {
					returnErr = err
				}
			}
		}
		if returnErr != nil {
			_ = Write(filepath.Join(out, "failure.json"), Object{"error": returnErr.Error(), "diagnosticsRetained": true})
		}
	}()
	if err := t.Prerequisites(ctx); err != nil {
		return err
	}
	// Refuse existing namespace, even if it has the same owner label.
	if _, err := t.Get(ctx, namespaceGVK, "", ns); err == nil {
		return fmt.Errorf("acceptance namespace already exists")
	} else if !apierrors.IsNotFound(err) {
		return err
	}
	if _, err := t.Create(ctx, Object{"apiVersion": "v1", "kind": "Namespace", "metadata": Object{"name": ns, "labels": Object{OwnerLabel: owner, "pod-security.kubernetes.io/enforce": "privileged"}}}, false); err != nil {
		return err
	}
	namespaceCreated = true
	// Namespace creation and creation of its default ServiceAccount are asynchronous.
	if err := t.Wait(ctx, serviceAccountGVK, ns, "default", 60*time.Second, func(Object) bool { return true }); err != nil {
		return err
	}
	// Reject an existing policy before seeding, even if a different namespace would scope it out.
	if _, err := t.Get(ctx, policyGVK, "", PolicyName); err == nil {
		return fmt.Errorf("acceptance policy already exists")
	} else if !apierrors.IsNotFound(err) {
		return err
	}
	existing, err := t.Apply(ctx, pod("existing-privileged", ns, owner, true))
	if err != nil {
		return err
	}
	expected := []Resource{resource(existing)}
	var rendered Object
	if err = Read(filepath.Join(out, "generated/policy.json"), &rendered); err != nil {
		return err
	}
	// Acceptance always starts with the default enforcing mode.
	if At(rendered, "spec", "validationActions").([]any)[0] != "Deny" {
		return fmt.Errorf("acceptance must start in Deny mode")
	}
	policyCreated = true
	applied, err := t.Deliver(ctx, rendered, owner)
	if err != nil {
		return err
	}
	again, err := t.Deliver(ctx, rendered, owner)
	if err != nil {
		return err
	}
	if At(applied, "metadata", "uid") != At(again, "metadata", "uid") {
		return fmt.Errorf("repeated delivery replaced policy identity")
	}
	// Check webhook propagation using non-persisting requests before testing behavior.
	request := func(label string, denied bool, call func() (Object, error)) error {
		if os.Getenv("KONSTAPEL_TEST_EXPECT_ACTION") == "Audit" {
			denied = false
		}
		result, e := call()
		response := admissionResponse(result, e)
		admission = append(admission, Object{"check": label, "expectedDenial": denied, "response": string(response), "error": fmt.Sprint(e)})
		if err := CheckAdmission(response, e, denied); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		return nil
	}
	deadline := time.Now().Add(timeout)
	for {
		result, e := t.Create(ctx, pod("probe", ns, owner, true), true)
		response := admissionResponse(result, e)
		if e != nil && strings.Contains(string(response), "Policy "+PolicyName+" failed") {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("enforcing webhook did not become observable: %s", response)
		}
		if e = pause(ctx, time.Second); e != nil {
			return e
		}
	}
	good, err := t.Apply(ctx, pod("good", ns, owner, false))
	if err != nil {
		return err
	}
	expected = append(expected, resource(good))
	deployment := Object{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": Object{"name": "good-deployment", "namespace": ns, "labels": Object{OwnerLabel: owner}}, "spec": Object{"replicas": 0, "selector": Object{"matchLabels": Object{"app": "acceptance"}}, "template": Object{"metadata": Object{"labels": Object{"app": "acceptance", OwnerLabel: owner}}, "spec": Map(pod("unused", ns, owner, false)["spec"])}}}
	dep, err := t.Apply(ctx, deployment)
	if err != nil {
		return err
	}
	expected = append(expected, resource(dep))
	if err = request("privileged Pod create", true, func() (Object, error) { return t.Create(ctx, pod("denied", ns, owner, true), false) }); err != nil {
		return err
	}
	badInit := pod("denied-init", ns, owner, false)
	Map(badInit["spec"])["initContainers"] = []any{Object{"name": "init", "image": WorkloadImage, "command": []any{"true"}, "securityContext": Object{"privileged": true}}}
	if err = request("privileged init create", true, func() (Object, error) { return t.Create(ctx, badInit, false) }); err != nil {
		return err
	}
	goodInit := pod("good-init", ns, owner, false)
	Map(goodInit["spec"])["initContainers"] = []any{Object{"name": "init", "image": WorkloadImage, "command": []any{"true"}, "securityContext": Object{"privileged": false}}}
	if err = request("compliant init create", false, func() (Object, error) { return t.Create(ctx, goodInit, true) }); err != nil {
		return err
	}
	// Independent clone: do not mutate the already-admitted deployment's desired copy.
	data, _ := json.Marshal(deployment)
	var badDeployment Object
	_ = json.Unmarshal(data, &badDeployment)
	Map(At(badDeployment, "spec", "template", "spec"))["containers"] = Map(pod("unused", ns, owner, true)["spec"])["containers"]
	Map(badDeployment["metadata"])["name"] = "denied-deployment"
	if err = request("privileged Deployment create", true, func() (Object, error) { return t.Create(ctx, badDeployment, false) }); err != nil {
		return err
	}
	Map(badDeployment["metadata"])["name"] = "good-deployment"
	if err = request("privileged Deployment update", true, func() (Object, error) { return t.Apply(ctx, badDeployment) }); err != nil {
		return err
	}
	if err = t.Wait(ctx, podGVK, ns, "good", 120*time.Second, func(obj Object) bool { return At(obj, "status", "phase") == "Running" }); err != nil {
		return err
	}
	eph := Object{"apiVersion": "v1", "kind": "Pod", "metadata": Object{"name": "good", "namespace": ns}, "spec": Object{"ephemeralContainers": []any{Object{"name": "debug", "image": WorkloadImage, "command": []any{"sleep", "30"}, "securityContext": Object{"privileged": true}}}}}
	if err = request("privileged ephemeral update", true, func() (Object, error) { return t.PatchEphemeralContainers(ctx, eph) }); err != nil {
		return err
	}
	// Audit permits the same otherwise-valid violating Pod; then restore Deny for
	// stable background evidence and independently inventory that admitted Pod.
	audit, err := Render(root, "Audit", ns, owner)
	if err != nil {
		return err
	}
	if _, err = t.Deliver(ctx, audit, owner); err != nil {
		return err
	}
	deadline = time.Now().Add(timeout)
	var auditPod Object
	for {
		auditPod, err = t.Apply(ctx, pod("audit-privileged", ns, owner, true))
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("Audit did not permit violating request: %w", err)
		}
		if err = pause(ctx, time.Second); err != nil {
			return err
		}
	}
	admission = append(admission, Object{"check": "Audit admits privileged Pod", "resourceUID": At(auditPod, "metadata", "uid"), "expectedDenial": false})
	expected = append(expected, resource(auditPod))
	applied, err = t.Deliver(ctx, rendered, owner)
	if err != nil {
		return err
	}
	boundary := time.Now().UTC()
	deadline = time.Now().Add(timeout)
	if os.Getenv("KONSTAPEL_TEST_MISSING_EVIDENCE") == "1" {
		expected = append(expected, Resource{APIVersion: "v1", Kind: "Pod", Namespace: ns, Name: "required-missing-resource", UID: "missing-resource-uid"})
		deadline = time.Now().Add(3 * time.Second)
	}
	var capture Capture
	var ev Evidence
	for {
		capture = t.Capture(ctx, root, applied, expected, boundary)
		if err = Write(filepath.Join(out, "capture.json"), capture); err != nil {
			return err
		}
		ev, _, err = Reconcile(capture)
		_ = Write(filepath.Join(out, "evidence.json"), ev)
		if err != nil {
			return err
		}
		if ev.Complete {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("background evidence incomplete: %v; errors: %v", ev.Missing, capture.CollectionErrors)
		}
		if err = pause(ctx, 2*time.Second); err != nil {
			return err
		}
	}
	for _, e := range ev.Evaluations {
		want := "pass"
		if e.Resource.Name == "existing-privileged" || e.Resource.Name == "audit-privileged" {
			want = "fail"
		}
		if e.Outcome != want {
			return fmt.Errorf("unexpected background result for %s: %s", e.Resource.Name, e.Outcome)
		}
	}
	retained, err := t.Get(ctx, podGVK, ns, "existing-privileged")
	if err != nil {
		return err
	}
	if At(retained, "metadata", "uid") != At(existing, "metadata", "uid") || At(retained, "metadata", "deletionTimestamp") != nil {
		return fmt.Errorf("existing violation removed/replaced")
	}
	config := map[string]string{"root": root, "output": out, "action": "Deny", "namespace": ns, "owner": owner, "capture": filepath.Join(out, "capture.json")}
	if err = p.Configure(ctx, config); err != nil {
		return err
	}
	results, err := actions.AggregateResults(ctx, input, providers)
	if err != nil {
		return err
	}
	if err = Export(ctx, root, out, input, plan, results, capture); err != nil {
		return err
	}
	return Write(filepath.Join(out, "acceptance.json"), Object{"passed": true, "cluster": t.Cluster, "coverage": Coverage, "complete": ev.Complete, "existingViolationRetained": true, "deniedCreatesRequireReports": false})
}
