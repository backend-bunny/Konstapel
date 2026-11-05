package targeting

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
)

func equalJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func jsonParams(s string) *apiextensionsv1.JSON { return &apiextensionsv1.JSON{Raw: []byte(s)} }

func fakeClient(objs ...client.Object) client.Client {
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(ValidatingPolicyGVK, meta.RESTScopeRoot)
	return fake.NewClientBuilder().WithScheme(runtime.NewScheme()).WithRESTMapper(mapper).WithObjects(objs...).Build()
}

// readyNames lets tests decide which engine policies Kyverno has accepted.
func readyNames(names ...string) ReadyFunc {
	return func(o *unstructured.Unstructured) bool { return slices.Contains(names, o.GetName()) }
}

// desiredFor renders one contribution for binding uid with the given revision.
func desiredFor(t *testing.T, uid types.UID, policy, revision string, mode v1alpha1.EnforcementMode) *unstructured.Unstructured {
	t.Helper()
	ref := v1alpha1.BundleReference{Name: "konstapel-vendored", Digest: vendoredDigest(t)}
	content, err := vendored().Content(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	c := Contribution{Cluster: "c", Binding: ObjectRevision{Name: "binding-" + string(uid), UID: uid, Generation: 1},
		Profile: ObjectRevision{Name: "p", UID: "p", Generation: 1}, Policy: policy, Mode: mode, Revision: revision,
		BundleName: ref.Name, BundleDigest: ref.Digest}
	obj, err := Render(c, content.Policies["disallow-privileged-containers"])
	if err != nil {
		t.Fatal(err)
	}
	return obj
}

func policyNames(t *testing.T, c client.Client) []string {
	t.Helper()
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(ValidatingPolicyGVK.GroupVersion().WithKind("ValidatingPolicyList"))
	if err := c.List(context.Background(), list); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, o := range list.Items {
		out = append(out, o.GetName())
	}
	slices.Sort(out)
	return out
}

const pol = "disallow-privileged-containers"

func TestSyncCreatesAndConverges(t *testing.T) {
	c := fakeClient()
	v1 := desiredFor(t, "b1", pol, "sha256:r1", v1alpha1.ModeDeny)
	d := &Delivery{Client: c, Ready: readyNames(v1.GetName())}
	for i := range 3 {
		res, err := d.Sync(context.Background(), "b1", []*unstructured.Unstructured{v1}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Ready(1) || len(res.Removed)+len(res.Retained)+len(res.Conflicts) != 0 {
			t.Fatalf("sync %d: %+v", i, res)
		}
	}
	if got := policyNames(t, c); !slices.Equal(got, []string{v1.GetName()}) {
		t.Fatalf("policies %v", got)
	}
}

func TestSyncRepairsDriftOnOwnedPolicy(t *testing.T) {
	c := fakeClient()
	v1 := desiredFor(t, "b1", pol, "sha256:r1", v1alpha1.ModeDeny)
	d := &Delivery{Client: c, Ready: readyNames(v1.GetName())}
	if _, err := d.Sync(context.Background(), "b1", []*unstructured.Unstructured{v1}, nil); err != nil {
		t.Fatal(err)
	}
	live := &unstructured.Unstructured{}
	live.SetGroupVersionKind(ValidatingPolicyGVK)
	_ = c.Get(context.Background(), client.ObjectKey{Name: v1.GetName()}, live)
	_ = unstructured.SetNestedStringSlice(live.Object, []string{"Audit"}, "spec", "validationActions")
	if err := c.Update(context.Background(), live); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Sync(context.Background(), "b1", []*unstructured.Unstructured{v1}, nil); err != nil {
		t.Fatal(err)
	}
	_ = c.Get(context.Background(), client.ObjectKey{Name: v1.GetName()}, live)
	if got, _, _ := unstructured.NestedStringSlice(live.Object, "spec", "validationActions"); !slices.Equal(got, []string{"Deny"}) {
		t.Fatalf("drift not repaired: %v", got)
	}
}

func TestReplacementRetiresOldRevisionOnlyWhenReady(t *testing.T) {
	c := fakeClient()
	v1 := desiredFor(t, "b1", pol, "sha256:r1", v1alpha1.ModeAudit)
	v2 := desiredFor(t, "b1", pol, "sha256:r2", v1alpha1.ModeDeny)
	ctx := context.Background()
	if _, err := (&Delivery{Client: c, Ready: readyNames(v1.GetName())}).Sync(ctx, "b1", []*unstructured.Unstructured{v1}, nil); err != nil {
		t.Fatal(err)
	}

	// The engine has not accepted v2 yet, so v1 keeps enforcing.
	notYet := &Delivery{Client: c, Ready: readyNames(v1.GetName())}
	res, err := notYet.Sync(ctx, "b1", []*unstructured.Unstructured{v2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Ready(1) || !slices.Equal(res.NotReady, []string{v2.GetName()}) || !slices.Equal(res.Retained, []string{v1.GetName()}) || len(res.Removed) != 0 {
		t.Fatalf("pending replacement: %+v", res)
	}
	if got := policyNames(t, c); len(got) != 2 {
		t.Fatalf("old and new must overlap during transition: %v", got)
	}

	// A failed replacement leaves v1 in place on every retry.
	for range 3 {
		if res, _ = notYet.Sync(ctx, "b1", []*unstructured.Unstructured{v2}, nil); !slices.Equal(res.Retained, []string{v1.GetName()}) {
			t.Fatalf("retry retired the last applied revision: %+v", res)
		}
	}

	ready := &Delivery{Client: c, Ready: readyNames(v1.GetName(), v2.GetName())}
	if res, err = ready.Sync(ctx, "b1", []*unstructured.Unstructured{v2}, nil); err != nil {
		t.Fatal(err)
	}
	if !res.Ready(1) || !slices.Equal(res.Removed, []string{v1.GetName()}) {
		t.Fatalf("ready replacement: %+v", res)
	}
	if got := policyNames(t, c); !slices.Equal(got, []string{v2.GetName()}) {
		t.Fatalf("policies %v", got)
	}
}

func TestRollbackGetsANewNameAndNeverResurrectsTheOldOne(t *testing.T) {
	// A -> B -> A: the second A has a new revision, so a new name.
	a1 := desiredFor(t, "b1", pol, "sha256:A-gen1", v1alpha1.ModeDeny)
	b := desiredFor(t, "b1", pol, "sha256:B-gen2", v1alpha1.ModeAudit)
	a3 := desiredFor(t, "b1", pol, "sha256:A-gen3", v1alpha1.ModeDeny)
	if a1.GetName() == a3.GetName() {
		t.Fatal("rollback reused the original engine policy name")
	}
	c := fakeClient()
	d := &Delivery{Client: c, Ready: func(*unstructured.Unstructured) bool { return true }}
	for _, step := range []*unstructured.Unstructured{a1, b, a3} {
		if _, err := d.Sync(context.Background(), "b1", []*unstructured.Unstructured{step}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if got := policyNames(t, c); !slices.Equal(got, []string{a3.GetName()}) {
		t.Fatalf("policies %v", got)
	}
}

func TestHeldPoliciesAreNeverWithdrawn(t *testing.T) {
	c := fakeClient()
	v1 := desiredFor(t, "b1", pol, "sha256:r1", v1alpha1.ModeDeny)
	d := &Delivery{Client: c, Ready: func(*unstructured.Unstructured) bool { return true }}
	if _, err := d.Sync(context.Background(), "b1", []*unstructured.Unstructured{v1}, nil); err != nil {
		t.Fatal(err)
	}
	// The policy failed to resolve this time (e.g. content unavailable).
	res, err := d.Sync(context.Background(), "b1", nil, []string{pol})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Retained, []string{v1.GetName()}) || len(res.Removed) != 0 {
		t.Fatalf("held policy withdrawn: %+v", res)
	}
	// Without a hold, a policy removed from the profile is withdrawn.
	if res, _ = d.Sync(context.Background(), "b1", nil, nil); !slices.Equal(res.Removed, []string{v1.GetName()}) {
		t.Fatalf("removed policy not withdrawn: %+v", res)
	}
}

func TestOtherBindingsAndUnmanagedResourcesAreUntouched(t *testing.T) {
	other := desiredFor(t, "b2", pol, "sha256:other", v1alpha1.ModeAudit)
	mine := desiredFor(t, "b1", pol, "sha256:r1", v1alpha1.ModeDeny)

	// An unmanaged policy squatting on the desired name.
	squatter := &unstructured.Unstructured{}
	squatter.SetGroupVersionKind(ValidatingPolicyGVK)
	squatter.SetName(mine.GetName())
	squatter.Object["spec"] = map[string]any{"validationActions": []any{"Audit"}}
	// A copy of the ownership labels without the controller reference.
	forged := squatter.DeepCopy()
	forged.SetName("forged")
	forged.SetLabels(map[string]string{LabelManagedBy: ManagedByValue, LabelBindingUID: "b1", LabelPolicyHash: PolicyHash(pol)})

	c := fakeClient(squatter, forged)
	all := func(*unstructured.Unstructured) bool { return true }
	if _, err := (&Delivery{Client: c, Ready: all}).Sync(context.Background(), "b2", []*unstructured.Unstructured{other}, nil); err != nil {
		t.Fatal(err)
	}
	d := &Delivery{Client: c, Ready: all}
	res, err := d.Sync(context.Background(), "b1", []*unstructured.Unstructured{mine}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Conflicts, []string{mine.GetName()}) || res.Ready(1) || len(res.Removed) != 0 {
		t.Fatalf("conflict: %+v", res)
	}
	live := &unstructured.Unstructured{}
	live.SetGroupVersionKind(ValidatingPolicyGVK)
	_ = c.Get(context.Background(), client.ObjectKey{Name: mine.GetName()}, live)
	if live.GetLabels()[LabelManagedBy] != "" {
		t.Fatal("unmanaged resource was adopted")
	}

	removed, err := d.Withdraw(context.Background(), "b1")
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Fatalf("withdraw removed resources b1 does not own: %v", removed)
	}
	if got := policyNames(t, c); !slices.Equal(got, []string{"forged", mine.GetName(), other.GetName()}) {
		t.Fatalf("policies %v", got)
	}
}

func TestWithdrawRemovesEveryOwnedRevision(t *testing.T) {
	c := fakeClient()
	v1 := desiredFor(t, "b1", pol, "sha256:r1", v1alpha1.ModeAudit)
	v2 := desiredFor(t, "b1", pol, "sha256:r2", v1alpha1.ModeDeny)
	keep := desiredFor(t, "b2", pol, "sha256:k", v1alpha1.ModeDeny)
	none := func(*unstructured.Unstructured) bool { return false }
	d := &Delivery{Client: c, Ready: none}
	_, _ = d.Sync(context.Background(), "b1", []*unstructured.Unstructured{v1}, nil)
	_, _ = d.Sync(context.Background(), "b1", []*unstructured.Unstructured{v2}, nil) // v1 retained, superseded
	_, _ = d.Sync(context.Background(), "b2", []*unstructured.Unstructured{keep}, nil)
	removed, err := d.Withdraw(context.Background(), "b1")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{v1.GetName(), v2.GetName()}
	slices.Sort(want)
	if !slices.Equal(removed, want) {
		t.Fatalf("removed %v, want %v", removed, want)
	}
	if got := policyNames(t, c); !slices.Equal(got, []string{keep.GetName()}) {
		t.Fatalf("policies %v", got)
	}
}

func TestSyncRefusesAnotherBindingsDesiredPolicy(t *testing.T) {
	d := &Delivery{Client: fakeClient()}
	if _, err := d.Sync(context.Background(), "b1", []*unstructured.Unstructured{desiredFor(t, "b2", pol, "sha256:x", v1alpha1.ModeDeny)}, nil); err == nil {
		t.Fatal("sync accepted a policy rendered for another binding")
	}
}

func TestKyvernoReady(t *testing.T) {
	o := &unstructured.Unstructured{Object: map[string]any{}}
	if KyvernoReady(o) {
		t.Fatal("no status is not ready")
	}
	cond := func(typ, status string) any { return map[string]any{"type": typ, "status": status} }
	_ = unstructured.SetNestedSlice(o.Object, []any{cond("RBACPermissionsGranted", "True"), cond("WebhookConfigured", "False")}, "status", "conditionStatus", "conditions")
	if KyvernoReady(o) {
		t.Fatal("webhook not configured is not ready")
	}
	_ = unstructured.SetNestedSlice(o.Object, []any{cond("RBACPermissionsGranted", "True"), cond("WebhookConfigured", "True")}, "status", "conditionStatus", "conditions")
	if !KyvernoReady(o) {
		t.Fatal("both conditions true is ready")
	}
}

// The assessment-loop prototype delivers an unmanaged policy under its source
// name with its own owner label. Targeting must never adopt or remove it.
func TestPrototypePolicyIsNeverAdopted(t *testing.T) {
	raw, _ := os.ReadFile("../../" + vendoredPolicy)
	proto := &unstructured.Unstructured{}
	if err := yaml.Unmarshal(raw, &proto.Object); err != nil {
		t.Fatal(err)
	}
	proto.SetLabels(map[string]string{assessment.OwnerLabel: "prototype-run"})
	c := fakeClient(proto)
	d := &Delivery{Client: c, Ready: func(*unstructured.Unstructured) bool { return true }}
	mine := desiredFor(t, "b1", pol, "sha256:r1", v1alpha1.ModeDeny)
	if mine.GetName() == proto.GetName() {
		t.Fatal("rendered name collides with the prototype policy name")
	}
	if _, err := d.Sync(context.Background(), "b1", []*unstructured.Unstructured{mine}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Withdraw(context.Background(), "b1"); err != nil {
		t.Fatal(err)
	}
	if got := policyNames(t, c); !slices.Equal(got, []string{proto.GetName()}) {
		t.Fatalf("prototype policy touched: %v", got)
	}
}
