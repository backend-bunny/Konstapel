package controller

// The ComplianceException lifecycle (add-self-service-policy-exceptions) is
// reconciled by the controller alone: it reads exceptions and is the only
// identity that writes their status. Application roles
// (config/rbac/exception-editor.yaml) never get status writes.
//
// Revocation processing (task 3.6) also updates an exception, only to
// release the revocation finalizer once the revocation is recorded
// independently; the validating webhook rejects any other update by the
// controller identity, which it learns with a SelfSubjectReview. That write
// and the lookup are not generated here: they are the gated ClusterRole in
// config/rbac/controller/exception-revocation.yaml, bound only together
// with --exception-revocation-processing and the fail-closed exception
// webhooks, so the default role grants no exception write.
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=complianceexceptions,verbs=get;list;watch
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=complianceexceptions/status,verbs=get;update;patch
