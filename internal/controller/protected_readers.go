package controller

// Protected-package readers (add-supporting-evidence-attachments 7.1).
//
// A platform package whose supporting context names a document is
// protected: serving it needs the document-read grant on top of run access.
// Download services older than the supporting-evidence packages don't read
// descriptors and would serve such a package to anyone with run access, so
// the controller writes one only while every deployed reader is known to
// enforce the check. The controller and the download service ship in the
// same image; a reader running exactly this controller's image does.
//
// The check runs when a platform run with supporting entries closes. While
// it fails (an older or different image in the reader Deployment's template
// or among its pods, a rollout in progress, or nothing configured) the run's
// supporting context is reported unavailable (ProtectedReadersUnverified):
// the package carries neither the context nor document copies, and coverage
// shows a blocking limitation instead of an empty list. Technical evidence
// is unaffected. The closure is frozen, so a re-export after a crash keeps
// the same answer.

import (
	"context"
	"errors"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The reader check reads the controller's own Pod and the reader
// Deployment and its Pods, uncached. The controller's ClusterRole already
// grants these for workload collection; the markers record the dependency.
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list

const (
	// ControllerContainer and DownloadContainer are the container names
	// the runtime chart gives the controller and the download service.
	ControllerContainer = "controller"
	DownloadContainer   = "download"

	// reasonReadersUnverified: the deployed package readers could not be
	// shown to enforce the document-read check.
	reasonReadersUnverified = "ProtectedReadersUnverified"
)

// errNoReaderCheck is the answer while no reader check is configured.
var errNoReaderCheck = errors.New("no protected-package reader check is configured")

// NoProtectedReaders is the reader check when no Konstapel download service
// is deployed: nothing serves packages through Konstapel, so none can serve
// a protected one without the document-read check.
func NoProtectedReaders(context.Context) error { return nil }

// DeployedReaders verifies that the download Deployment and every Pod its
// selector matches run this controller's image.
type DeployedReaders struct {
	// Reader must be uncached: a stale cache could miss a rollout.
	Reader     client.Reader
	Namespace  string
	Deployment string
	// Pod is this controller's own Pod; its controller container's image
	// is the build that enforces the check.
	Pod string
}

// Verify returns nil only when every reader runs this controller's image.
func (d DeployedReaders) Verify(ctx context.Context) error {
	self := &corev1.Pod{}
	if err := d.Reader.Get(ctx, client.ObjectKey{Namespace: d.Namespace, Name: d.Pod}, self); err != nil {
		return fmt.Errorf("this controller's pod %s/%s: %w", d.Namespace, d.Pod, err)
	}
	want := containerImage(self.Spec.Containers, ControllerContainer)
	if want == "" {
		return fmt.Errorf("this controller's pod %s/%s has no %s container", d.Namespace, d.Pod, ControllerContainer)
	}
	dep := &appsv1.Deployment{}
	if err := d.Reader.Get(ctx, client.ObjectKey{Namespace: d.Namespace, Name: d.Deployment}, dep); err != nil {
		return fmt.Errorf("reader Deployment %s/%s: %w", d.Namespace, d.Deployment, err)
	}
	if dep.DeletionTimestamp != nil {
		return fmt.Errorf("reader Deployment %s/%s is being deleted", d.Namespace, d.Deployment)
	}
	if got := containerImage(dep.Spec.Template.Spec.Containers, DownloadContainer); got != want {
		return fmt.Errorf("reader Deployment %s/%s runs image %q, not this controller's %q", d.Namespace, d.Deployment, got, want)
	}
	if dep.Spec.Selector == nil {
		return fmt.Errorf("reader Deployment %s/%s has no selector", d.Namespace, d.Deployment)
	}
	sel, err := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if err != nil || sel.Empty() {
		return fmt.Errorf("reader Deployment %s/%s has no usable selector: %v", d.Namespace, d.Deployment, err)
	}
	var pods corev1.PodList
	if err := d.Reader.List(ctx, &pods, client.InNamespace(d.Namespace), client.MatchingLabelsSelector{Selector: sel}); err != nil {
		return fmt.Errorf("reader pods of %s/%s: %w", d.Namespace, d.Deployment, err)
	}
	for _, p := range pods.Items {
		// A terminating pod may still finish downloads it accepted, so
		// only finished pods are ignored.
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		if got := containerImage(p.Spec.Containers, DownloadContainer); got != want {
			return fmt.Errorf("reader pod %s/%s runs image %q, not this controller's %q", d.Namespace, p.Name, got, want)
		}
	}
	return nil
}

func containerImage(cs []corev1.Container, name string) string {
	for _, c := range cs {
		if c.Name == name {
			return c.Image
		}
	}
	return ""
}

// protectedReaders runs the configured reader check; none configured fails.
func (r *AssessmentRunReconciler) protectedReaders(ctx context.Context) error {
	if r.Runtime.ProtectedReaders == nil {
		return errNoReaderCheck
	}
	return r.Runtime.ProtectedReaders(ctx)
}
