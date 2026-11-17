package controller

import (
	"context"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	readerNS  = "konstapel-system"
	thisImage = "ghcr.io/backend-bunny/konstapel@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	oldImage  = "ghcr.io/backend-bunny/konstapel@sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

var readerLabels = map[string]string{"app.kubernetes.io/name": "konstapel", "app.kubernetes.io/component": "download"}

func readerPod(name, container, image string, phase corev1.PodPhase, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: readerNS, Name: name, Labels: labels},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: container, Image: image}}},
		Status: corev1.PodStatus{Phase: phase}}
}

// terminating marks a pod deleted while it drains.
func terminating(p *corev1.Pod) *corev1.Pod {
	now := metav1.Now()
	p.DeletionTimestamp, p.Finalizers = &now, []string{"test/drain"}
	return p
}

func readerDeployment(image string) *appsv1.Deployment {
	return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: readerNS, Name: "konstapel-download"},
		Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: readerLabels},
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: readerLabels},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: DownloadContainer, Image: image}}}}}}
}

// The check passes only while the reader Deployment's template and every
// pod its selector matches run this controller's own image.
func TestDeployedReadersVerify(t *testing.T) {
	self := readerPod("konstapel-controller-a", ControllerContainer, thisImage, corev1.PodRunning, map[string]string{"app.kubernetes.io/component": "controller"})
	ready := []client.Object{self, readerDeployment(thisImage),
		readerPod("dl-1", DownloadContainer, thisImage, corev1.PodRunning, readerLabels),
		readerPod("dl-2", DownloadContainer, thisImage, corev1.PodRunning, readerLabels)}
	for _, tc := range []struct {
		name    string
		objects []client.Object
		wantErr string
	}{
		{"rolled out", ready, ""},
		{"no reader pods yet", []client.Object{self, readerDeployment(thisImage)}, ""},
		{"finished old pod ignored", append(ready[:4:4], readerPod("dl-old", DownloadContainer, oldImage, corev1.PodSucceeded, readerLabels)), ""},
		{"other components ignored", append(ready[:4:4], readerPod("other", "main", oldImage, corev1.PodRunning, map[string]string{"app.kubernetes.io/component": "other"})), ""},
		{"older reader pod still serving", append(ready[:4:4], readerPod("dl-old", DownloadContainer, oldImage, corev1.PodRunning, readerLabels)), `reader pod konstapel-system/dl-old runs image "` + oldImage},
		{"older reader pod pending", append(ready[:4:4], readerPod("dl-old", DownloadContainer, oldImage, corev1.PodPending, readerLabels)), "dl-old"},
		{"older reader pod terminating", append(ready[:4:4], terminating(readerPod("dl-old", DownloadContainer, oldImage, corev1.PodRunning, readerLabels))), "dl-old"},
		{"reader pod without the download container", append(ready[:4:4], readerPod("dl-x", "sidecar", thisImage, corev1.PodRunning, readerLabels)), "dl-x"},
		{"template still older", []client.Object{self, readerDeployment(oldImage), readerPod("dl-1", DownloadContainer, thisImage, corev1.PodRunning, readerLabels)}, "reader Deployment konstapel-system/konstapel-download runs image"},
		{"no reader Deployment", []client.Object{self}, "reader Deployment"},
		{"own pod unknown", ready[1:], "this controller's pod"},
		{"own pod without controller container", append([]client.Object{readerPod("konstapel-controller-a", "manager", thisImage, corev1.PodRunning, nil)}, ready[1:]...), "has no controller container"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(Scheme()).WithObjects(tc.objects...).Build()
			err := DeployedReaders{Reader: c, Namespace: readerNS, Deployment: "konstapel-download", Pod: self.Name}.Verify(context.Background())
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// A Deployment without a usable selector is never trusted, even when every
// pod in the namespace would pass (an empty selector matches them all).
func TestDeployedReadersRefuseEmptySelector(t *testing.T) {
	self := readerPod("me", ControllerContainer, thisImage, corev1.PodRunning, nil)
	self.Spec.Containers = append(self.Spec.Containers, corev1.Container{Name: DownloadContainer, Image: thisImage})
	for _, sel := range []*metav1.LabelSelector{nil, {}} {
		dep := readerDeployment(thisImage)
		dep.Spec.Selector = sel
		c := fake.NewClientBuilder().WithScheme(Scheme()).WithObjects(self, dep).Build()
		if err := (DeployedReaders{Reader: c, Namespace: readerNS, Deployment: dep.Name, Pod: "me"}).Verify(context.Background()); err == nil {
			t.Fatalf("selector %v accepted", sel)
		}
	}
}

// A Deployment being deleted is not a deployed reader.
func TestDeployedReadersRefuseDeletingDeployment(t *testing.T) {
	self := readerPod("me", ControllerContainer, thisImage, corev1.PodRunning, nil)
	dep := readerDeployment(thisImage)
	now := metav1.Now()
	dep.DeletionTimestamp, dep.Finalizers = &now, []string{"test/hold"}
	c := fake.NewClientBuilder().WithScheme(Scheme()).WithObjects(self, dep).Build()
	err := DeployedReaders{Reader: c, Namespace: readerNS, Deployment: dep.Name, Pod: "me"}.Verify(context.Background())
	if err == nil || !strings.Contains(err.Error(), "being deleted") {
		t.Fatalf("error %v", err)
	}
}
