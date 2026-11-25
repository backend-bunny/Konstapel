package controller

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/exception"
)

// writeLog records every write that reaches the API client, as an API
// server audit log would: the fake client authorizes everything, as a
// ServiceAccount manually granted every exception verb would be.
type writeLog struct {
	mu     sync.Mutex
	writes []string
}

func (w *writeLog) add(verb string, obj runtime.Object, sub string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	kind := "object"
	switch obj.(type) {
	case *v1alpha1.ComplianceException, *v1alpha1.ComplianceExceptionList:
		kind = "complianceexception"
	case *corev1.ConfigMap:
		kind = "configmap"
	}
	if o, ok := obj.(client.Object); ok {
		kind += " " + o.GetNamespace() + "/" + o.GetName()
	}
	if sub != "" {
		kind += "/" + sub
	}
	w.writes = append(w.writes, verb+" "+kind)
}

// exceptionWrites returns the writes of ComplianceExceptions other than
// status, and of revocation records.
func (w *writeLog) exceptionWrites() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for _, s := range w.writes {
		if (strings.Contains(s, "complianceexception") && !strings.HasSuffix(s, "/status")) || strings.Contains(s, "configmap "+DefaultSnapshotNamespace+"/revocation-") {
			out = append(out, s)
		}
	}
	return out
}

func (w *writeLog) funcs() interceptor.Funcs {
	return interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			w.add("create", obj, "")
			return c.Create(ctx, obj, opts...)
		},
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			w.add("update", obj, "")
			return c.Update(ctx, obj, opts...)
		},
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			w.add("patch", obj, "")
			return c.Patch(ctx, obj, patch, opts...)
		},
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			w.add("delete", obj, "")
			return c.Delete(ctx, obj, opts...)
		},
		DeleteAllOf: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteAllOfOption) error {
			w.add("deletecollection", obj, "")
			return c.DeleteAllOf(ctx, obj, opts...)
		},
		SubResourceCreate: func(ctx context.Context, c client.Client, sub string, obj, subObj client.Object, opts ...client.SubResourceCreateOption) error {
			w.add("create", obj, sub)
			return c.SubResource(sub).Create(ctx, obj, subObj, opts...)
		},
		SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			w.add("update", obj, sub)
			return c.SubResource(sub).Update(ctx, obj, opts...)
		},
		SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			w.add("patch", obj, sub)
			return c.SubResource(sub).Patch(ctx, obj, patch, opts...)
		},
	}
}

// With --exception-revocation-processing off, the exception reconciler
// sends no ComplianceException write other than status, and no revocation
// record, although its client may write everything (a ServiceAccount
// manually granted update and patch on complianceexceptions): revoked,
// terminating and renewed exceptions are reconciled, their status reports
// RevocationProcessingDisabled, and even a direct release or edit through
// the reconciler's client is refused before it is sent. Enabled, the same
// constructor releases as before.
func TestRevocationDisabledSendsNoExceptionWrite(t *testing.T) {
	renewedRevoked := revoke(t, acceptedException(t, 2, "carol", revA), "dave", exRevokedAt)
	for name, ex := range map[string]*v1alpha1.ComplianceException{
		"revoked":     revoke(t, acceptedException(t, 1, "alice", revA), "dave", exRevokedAt),
		"terminating": terminatingException(revoke(t, acceptedException(t, 1, "alice", revA), "dave", exRevokedAt)),
		"renewed":     renewedRevoked,
		"never accepted": revoke(t, func() *v1alpha1.ComplianceException {
			e := acceptedException(t, 1, "alice", revA)
			delete(e.Annotations, exception.AcceptanceAnnotation)
			return e
		}(), "dave", exRevokedAt),
		"not revoked": acceptedException(t, 1, "alice", revA),
	} {
		t.Run(name, func(t *testing.T) {
			log := &writeLog{}
			c := fake.NewClientBuilder().WithScheme(Scheme()).WithObjects(ex).WithStatusSubresource(&v1alpha1.ComplianceException{}).
				WithInterceptorFuncs(log.funcs()).Build()
			checks := 0
			r := newExceptionReconciler(c, c, DefaultSnapshotNamespace, RevocationGate{Protected: func(context.Context) error { checks++; return nil }})
			for range 3 {
				if _, err, _ := step(t, c, r); err != nil {
					t.Fatalf("reconcile: %v", err)
				}
			}
			got := mustGet(t, c)
			if ex.Spec.Revoked {
				if !holds(got) {
					t.Fatalf("the finalizer is gone: %+v", got.ObjectMeta)
				}
				if cond := historyCondition(got); cond == nil || cond.Reason != v1alpha1.ReasonRevocationProcessingDisabled {
					t.Fatalf("RevocationRecorded = %+v", cond)
				}
			}
			// A release or edit through the reconciler's own client is
			// refused before it is sent.
			released := got.DeepCopy()
			released.Finalizers = nil
			for what, err := range map[string]error{
				"release": r.Client.Patch(context.Background(), released, client.MergeFrom(got)),
				"update":  r.Client.Update(context.Background(), got.DeepCopy()),
				"delete":  r.Client.Delete(context.Background(), got.DeepCopy()),
				"record": r.Client.Create(context.Background(), &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: DefaultSnapshotNamespace,
					Name: exception.RevocationRecordName(got.UID, got.Spec.AcceptanceRevision), Labels: map[string]string{exception.LabelComponent: exception.ComponentRevocation}}}),
				"subresource": r.Client.SubResource("finalize").Update(context.Background(), got.DeepCopy()),
			} {
				if !errors.Is(err, ErrRevocationWriterDisabled) {
					t.Errorf("%s through the disabled reconciler's client: %v", what, err)
				}
			}
			if _, err := r.release(context.Background(), got); !errors.Is(err, ErrRevocationWriterDisabled) {
				t.Errorf("release with processing disabled: %v", err)
			}
			if w := log.exceptionWrites(); len(w) != 0 || checks != 0 || revocationRecord(t, c, got.UID, got.Spec.AcceptanceRevision) != nil {
				t.Fatalf("with processing disabled: exception writes %v, protection checks %d", w, checks)
			}
			// Status and acceptance snapshots are still written.
			if accepted := ex.Annotations[exception.AcceptanceAnnotation] != ""; accepted && len(got.Status.Conditions) == 0 {
				t.Fatalf("no status written: %+v", got.Status)
			}
		})
	}

	t.Run("enabled", func(t *testing.T) {
		log := &writeLog{}
		c := fake.NewClientBuilder().WithScheme(Scheme()).WithObjects(revoke(t, acceptedException(t, 1, "alice", revA), "dave", exRevokedAt)).
			WithStatusSubresource(&v1alpha1.ComplianceException{}).WithInterceptorFuncs(log.funcs()).Build()
		r := newExceptionReconciler(c, c, DefaultSnapshotNamespace, revocationOn)
		if _, err, got := step(t, c, r); err != nil || holds(got) || revocationRecord(t, c, "ex-1", 1) == nil {
			t.Fatalf("enabled: %v holds %v", err, holds(got))
		}
		if w := log.exceptionWrites(); len(w) != 2 || !strings.HasPrefix(w[0], "create configmap") || !strings.HasPrefix(w[1], "patch complianceexception team-a/priv") {
			t.Fatalf("enabled writes %v, want the record, then the release", w)
		}
	})
}
