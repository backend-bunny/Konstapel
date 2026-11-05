package assessment

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	policyGVK         = schema.FromAPIVersionAndKind("policies.kyverno.io/v1", "ValidatingPolicy")
	reportGVK         = schema.FromAPIVersionAndKind("wgpolicyk8s.io/v1alpha2", "PolicyReport")
	clusterReportGVK  = schema.FromAPIVersionAndKind("wgpolicyk8s.io/v1alpha2", "ClusterPolicyReport")
	namespaceGVK      = schema.FromAPIVersionAndKind("v1", "Namespace")
	podGVK            = schema.FromAPIVersionAndKind("v1", "Pod")
	deploymentGVK     = schema.FromAPIVersionAndKind("apps/v1", "Deployment")
	serviceAccountGVK = schema.FromAPIVersionAndKind("v1", "ServiceAccount")
	eventGVK          = schema.FromAPIVersionAndKind("v1", "Event")
)

// Target is the sole cluster client passed to delivery and collection. It uses
// only the explicit kubeconfig and context, never ambient or in-cluster config.
type Target struct {
	Context, Cluster string
	Timeout          time.Duration
	client           client.Client
	discovery        rest.Interface
}

func NewTarget(kubeconfig, contextName string, timeout time.Duration) (*Target, error) {
	if kubeconfig == "" || contextName == "" || timeout <= 0 {
		return nil, fmt.Errorf("explicit kubeconfig/context and positive timeout required")
	}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig},
		&clientcmd.ConfigOverrides{CurrentContext: contextName},
	).ClientConfig()
	if err != nil {
		return nil, err
	}
	config.Timeout = min(timeout, 30*time.Second)
	config.UserAgent = "konstapel-assessment"
	c, err := client.New(config, client.Options{})
	if err != nil {
		return nil, err
	}
	d, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, err
	}
	t := &Target{Context: contextName, Timeout: timeout, client: c, discovery: d.RESTClient()}
	ns, err := t.Get(context.Background(), namespaceGVK, "", "kube-system")
	if err != nil {
		return nil, err
	}
	uid := Str(At(ns, "metadata", "uid"))
	if uid == "" {
		return nil, fmt.Errorf("target kube-system UID missing")
	}
	t.Cluster = "kube-system:" + uid
	return t, nil
}

func (t *Target) Get(ctx context.Context, gvk schema.GroupVersionKind, namespace, name string) (Object, error) {
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(gvk)
	if err := t.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, obj); err != nil {
		return nil, err
	}
	return assessmentObject(obj)
}

// List collects across all namespaces, including cluster-scoped resources.
func (t *Target) List(ctx context.Context, gvk schema.GroupVersionKind) (Object, error) {
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(gvk.GroupVersion().WithKind(gvk.Kind + "List"))
	if err := t.client.List(ctx, list); err != nil {
		return nil, err
	}
	return assessmentObject(list)
}

// Assessment Objects use encoding/json's numeric representation, also used by
// saved captures. Kubernetes unstructured responses instead decode integers as
// int64; normalize at this boundary so live and replayed evidence agree.
func assessmentObject(value json.Marshaler) (Object, error) {
	data, err := value.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var obj Object
	err = json.Unmarshal(data, &obj)
	return obj, err
}

func objectForRequest(obj Object) (*unstructured.Unstructured, error) {
	// Normalize numbers and copy input: callers retain desired objects for later
	// requests and must not inherit server metadata/status from earlier responses.
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	u := &unstructured.Unstructured{}
	err = u.UnmarshalJSON(b)
	return u, err
}

func (t *Target) Apply(ctx context.Context, obj Object) (Object, error) {
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	u, err := objectForRequest(obj)
	if err != nil {
		return nil, err
	}
	// Do not force conflicts with fields owned by another client.
	err = t.client.Patch(ctx, u, client.Apply, client.FieldOwner("konstapel-assessment"))
	if err != nil {
		return nil, err
	}
	return assessmentObject(u)
}

func (t *Target) Create(ctx context.Context, obj Object, dryRun bool) (Object, error) {
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	u, err := objectForRequest(obj)
	if err != nil {
		return nil, err
	}
	opts := []client.CreateOption{}
	if dryRun {
		opts = append(opts, client.DryRunAll)
	}
	err = t.client.Create(ctx, u, opts...)
	if err != nil {
		return nil, err
	}
	return assessmentObject(u)
}

func (t *Target) PatchEphemeralContainers(ctx context.Context, obj Object) (Object, error) {
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	u, err := objectForRequest(obj)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	err = t.client.SubResource("ephemeralcontainers").Patch(ctx, u, client.RawPatch(types.MergePatchType, b))
	if err != nil {
		return nil, err
	}
	return assessmentObject(u)
}

func (t *Target) Wait(ctx context.Context, gvk schema.GroupVersionKind, namespace, name string, timeout time.Duration, ready func(Object) bool) error {
	return wait.PollUntilContextTimeout(ctx, time.Second, min(timeout, t.Timeout), true, func(ctx context.Context) (bool, error) {
		obj, err := t.Get(ctx, gvk, namespace, name)
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return ready(obj), nil
	})
}

// DeleteOwned rechecks ownership and uses UID/resourceVersion preconditions so
// a replacement or a concurrent ownership change cannot be deleted by cleanup.
func (t *Target) DeleteOwned(ctx context.Context, gvk schema.GroupVersionKind, namespace, name, owner string) error {
	ctx, cancel := context.WithTimeout(ctx, min(t.Timeout, 60*time.Second))
	defer cancel()
	obj, err := t.Get(ctx, gvk, namespace, name)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	u := &unstructured.Unstructured{Object: obj}
	if u.GetLabels()[OwnerLabel] != owner {
		return nil
	}
	uid, rv := u.GetUID(), u.GetResourceVersion()
	if uid == "" || rv == "" {
		return fmt.Errorf("refusing deletion without UID/resourceVersion")
	}
	if err := t.client.Delete(ctx, u, client.Preconditions{UID: &uid, ResourceVersion: &rv}); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return wait.PollUntilContextCancel(ctx, time.Second, true, func(ctx context.Context) (bool, error) {
		current, err := t.Get(ctx, gvk, namespace, name)
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		return Str(At(current, "metadata", "uid")) != string(uid), nil
	})
}

func (t *Target) Prerequisites(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	for _, api := range []struct {
		path      string
		resources []string
	}{
		{"/apis/policies.kyverno.io/v1", []string{"validatingpolicies"}},
		{"/apis/wgpolicyk8s.io/v1alpha2", []string{"policyreports", "clusterpolicyreports"}},
	} {
		var list metav1.APIResourceList
		if err := t.discovery.Get().AbsPath(api.path).Do(ctx).Into(&list); err != nil {
			return fmt.Errorf("required API %s unavailable: %w", api.path, err)
		}
		for _, name := range api.resources {
			found := false
			for _, resource := range list.APIResources {
				if resource.Name == name {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("required resource %s unavailable", name)
			}
		}
	}
	return nil
}
