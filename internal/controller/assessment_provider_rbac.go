package controller

// External assessment provider registrations
// (add-external-assessment-providers 2.1). The controller reads
// AssessmentProviders and is the only identity that writes their status
// (RBAC, and the konstapel-assessment-provider-status-writer admission
// policy). It never creates, changes or deletes a registration: those are
// administrator configuration (konstapel-assessment-provider-admin). A
// registration's serverTrust ConfigMap is read through the controller's
// existing controller-namespace grants. No provider's source permissions
// are ever granted to the controller.
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=assessmentproviders,verbs=get;list;watch
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=assessmentproviders/status,verbs=get;update;patch
