package controller

// The ComplianceException lifecycle (add-self-service-policy-exceptions) is
// reconciled by the controller alone: it reads exceptions and is the only
// identity that writes their status. Application roles
// (config/rbac/exception-editor.yaml) never get status writes. It updates an
// exception only to release the revocation finalizer once the revocation is
// recorded independently (task 3.6); the validating webhook rejects any other
// update by the controller identity, which it learns with a
// SelfSubjectReview.
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=complianceexceptions,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=complianceexceptions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=authentication.k8s.io,resources=selfsubjectreviews,verbs=create
