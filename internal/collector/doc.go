// Package collector implements the continuous-assessment controller's
// evidence capture: the versioned (v2) capture format, the expected-evidence
// inventory derived from targeting subjects, and scope-change tracking during
// collection. The prototype's single-policy v1 path stays in
// internal/assessment, which this package reuses but does not change.
package collector
