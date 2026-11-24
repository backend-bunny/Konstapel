package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/exception"
)

// ErrRevocationWriterDisabled reports a write the exception reconciler
// refused to send because revocation processing is off.
var ErrRevocationWriterDisabled = errors.New("revocation processing is disabled (--exception-revocation-processing is off): the controller sends no ComplianceException write other than status, and no revocation record")

// exceptionWriteGuard is the exception reconciler's client while revocation
// processing is off (add-self-service-policy-exceptions task 3.6). Then the
// controller has no reason to write a ComplianceException other than its
// status, or to write a revocation record, so it refuses to send such a
// request at all, whatever the ServiceAccount is granted. Everything else,
// reads, status writes and acceptance snapshots, passes through.
//
// It enforces the flag in this process only. It cannot revoke a grant
// someone bound to the ServiceAccount, and it does not stop another process
// using that identity: RBAC and the exception admission webhooks remain
// the authorization controls.
type exceptionWriteGuard struct{ client.Client }

// refuseWrite returns ErrRevocationWriterDisabled for an object the
// reconciler must not write while processing is off.
func refuseWrite(verb string, obj runtime.Object) error {
	switch o := obj.(type) {
	case *v1alpha1.ComplianceException:
		return fmt.Errorf("%w: refused %s of complianceexception %s/%s", ErrRevocationWriterDisabled, verb, o.Namespace, o.Name)
	case *v1alpha1.ComplianceExceptionList:
		return fmt.Errorf("%w: refused %s of complianceexceptions", ErrRevocationWriterDisabled, verb)
	case *corev1.ConfigMap:
		if o.Labels[exception.LabelComponent] == exception.ComponentRevocation || strings.HasPrefix(o.Name, "revocation-") {
			return fmt.Errorf("%w: refused %s of revocation record %s/%s", ErrRevocationWriterDisabled, verb, o.Namespace, o.Name)
		}
	}
	return nil
}

func (g exceptionWriteGuard) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if err := refuseWrite("create", obj); err != nil {
		return err
	}
	return g.Client.Create(ctx, obj, opts...)
}

func (g exceptionWriteGuard) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if err := refuseWrite("update", obj); err != nil {
		return err
	}
	return g.Client.Update(ctx, obj, opts...)
}

func (g exceptionWriteGuard) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	if err := refuseWrite("patch", obj); err != nil {
		return err
	}
	return g.Client.Patch(ctx, obj, patch, opts...)
}

func (g exceptionWriteGuard) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if err := refuseWrite("delete", obj); err != nil {
		return err
	}
	return g.Client.Delete(ctx, obj, opts...)
}

func (g exceptionWriteGuard) DeleteAllOf(ctx context.Context, obj client.Object, opts ...client.DeleteAllOfOption) error {
	if err := refuseWrite("deletecollection", obj); err != nil {
		return err
	}
	return g.Client.DeleteAllOf(ctx, obj, opts...)
}

// Apply is refused: the reconciler never applies, and an apply
// configuration's target is not checked here.
func (g exceptionWriteGuard) Apply(context.Context, runtime.ApplyConfiguration, ...client.ApplyOption) error {
	return fmt.Errorf("%w: refused server-side apply", ErrRevocationWriterDisabled)
}

// SubResource passes status through, the controller's own write; every
// other subresource write is refused.
func (g exceptionWriteGuard) SubResource(name string) client.SubResourceClient {
	if name == "status" {
		return g.Client.SubResource(name)
	}
	return refusingSubResource{SubResourceClient: g.Client.SubResource(name), name: name}
}

// refusingSubResource reads through and refuses every write.
type refusingSubResource struct {
	client.SubResourceClient
	name string
}

func (r refusingSubResource) refused() error {
	return fmt.Errorf("%w: refused a write of subresource %s", ErrRevocationWriterDisabled, r.name)
}

func (r refusingSubResource) Create(context.Context, client.Object, client.Object, ...client.SubResourceCreateOption) error {
	return r.refused()
}

func (r refusingSubResource) Update(context.Context, client.Object, ...client.SubResourceUpdateOption) error {
	return r.refused()
}

func (r refusingSubResource) Patch(context.Context, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
	return r.refused()
}

func (r refusingSubResource) Apply(context.Context, runtime.ApplyConfiguration, ...client.SubResourceApplyOption) error {
	return r.refused()
}
