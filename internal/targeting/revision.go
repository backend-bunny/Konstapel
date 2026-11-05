package targeting

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// EnforcementInput is everything that changes enforcement semantics for one
// contribution. Namespace membership is deliberately absent. A selector match
// change does not change the revision, and evidence records the observed
// namespace UIDs instead.
type EnforcementInput struct {
	Cluster    string
	BindingUID types.UID
	// BindingEpoch is the single binding-side change counter. It is the
	// binding's metadata.generation today. add-continuous-assessments replaces
	// it with an admission-maintained enforcement epoch, so reporting-only edits
	// do not rotate policies or invalidate exceptions. Callers set this field;
	// nothing else in the revision reads the binding generation.
	BindingEpoch        int64
	ProfileUID          types.UID
	ProfileGeneration   int64
	Policy              string
	BundleDigest        string
	ConfigurationDigest string
	Mode                v1alpha1.EnforcementMode
	NamespaceSelector   v1alpha1.NamespaceSelector
}

// EnforcementRevision returns the configuration revision for a contribution.
// It is the only place the revision is calculated. Engine policy names and
// exception acceptances bind to it, so a change to any input, including a
// rollback to earlier spec values (which advances the epoch or generation),
// yields a new revision.
func EnforcementRevision(in EnforcementInput) string {
	return digest(struct {
		V int              `json:"v"`
		I EnforcementInput `json:"i"`
	}{ContractVersion, in})
}

// ConfigurationDigest covers a profile policy's parameters and exception
// settings. Parameter JSON is canonicalised, so key order does not matter.
func ConfigurationDigest(p v1alpha1.ProfilePolicy) (string, error) {
	var params any
	if p.Parameters != nil && len(p.Parameters.Raw) > 0 {
		if err := json.Unmarshal(p.Parameters.Raw, &params); err != nil {
			return "", fmt.Errorf("policy %s: parameters: %w", p.Name, err)
		}
	}
	ex := p.Exceptions
	if ex.Eligibility == "" {
		ex.Eligibility = v1alpha1.ExceptionsForbidden
	}
	return digest(struct {
		Parameters any                        `json:"parameters"`
		Exceptions v1alpha1.ExceptionSettings `json:"exceptions"`
	}{params, ex}), nil
}

// digest hashes the JSON encoding. encoding/json sorts map keys, so the
// encoding of decoded JSON values and fixed structs is canonical.
func digest(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		// Only json.Marshal of the fixed types above reaches here; failure is a bug.
		panic(fmt.Sprintf("targeting: digest: %v", err))
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
