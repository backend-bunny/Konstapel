// Package v1alpha1 contains the compliance.erenius.io/v1alpha1 API.
//
// The package is shared: add-compliance-targeting-api owns this file and the
// ComplianceProfile/ComplianceBinding types; other changes add their kinds in
// separate *_types.go files and register them through SchemeBuilder.
//
// +kubebuilder:object:generate=true
// +groupName=compliance.erenius.io
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is the group and version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "compliance.erenius.io", Version: "v1alpha1"}

	// SchemeBuilder registers the Go types with a runtime.Scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds every registered type in this group-version to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
