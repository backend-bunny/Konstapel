package controller

// Evidence signing recovery (add-evidence-signing-recovery). The controller
// reads EvidenceSigningRequests and is the only identity that writes their
// status (RBAC, and the konstapel-evidence-signing-status-writer admission
// policy). It neither creates, updates nor deletes requests: they are the
// administrators' audit record. The run status, signing Secret and
// destination access recovery needs are the controller's existing grants.
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=evidencesigningrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=evidencesigningrequests/status,verbs=get;update;patch
