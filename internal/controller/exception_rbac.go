package controller

// The ComplianceException lifecycle (add-self-service-policy-exceptions) is
// reconciled by the controller alone: it reads exceptions and is the only
// identity that writes their status. Application roles
// (config/rbac/exception-editor.yaml) never get status writes.
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=complianceexceptions,verbs=get;list;watch
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=complianceexceptions/status,verbs=get;update;patch
