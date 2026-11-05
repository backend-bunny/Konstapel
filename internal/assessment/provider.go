package assessment

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
)

type Provider struct{ Config map[string]string }

var _ policy.Provider = (*Provider)(nil)

func (s *Provider) Configure(_ context.Context, m map[string]string) error {
	for _, key := range []string{"root", "output", "namespace", "owner"} {
		if m[key] == "" {
			return fmt.Errorf("missing provider configuration %s", key)
		}
	}
	if _, err := ValidateMapping(m["root"]); err != nil {
		return err
	}
	if _, err := Render(m["root"], m["action"], m["namespace"], m["owner"]); err != nil {
		return err
	}
	s.Config = m
	return nil
}
func (s *Provider) check(p policy.Policy) error {
	if s.Config == nil {
		return fmt.Errorf("provider not configured")
	}
	for _, r := range p {
		if r.Rule.ID == PolicyName {
			return nil
		}
	}
	return fmt.Errorf("provider did not receive expected rule %s", PolicyName)
}
func (s *Provider) Generate(_ context.Context, p policy.Policy) error {
	if err := s.check(p); err != nil {
		return err
	}
	root, out := s.Config["root"], s.Config["output"]
	raw, err := os.ReadFile(filepath.Join(root, SourcePolicy))
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Join(out, "generated/upstream"), 0755); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(out, "generated/upstream", PolicyName+".yaml"), raw, 0644); err != nil {
		return err
	}
	rendered, err := Render(root, s.Config["action"], s.Config["namespace"], s.Config["owner"])
	if err != nil {
		return err
	}
	if err = Write(filepath.Join(out, "generated/policy.json"), rendered); err != nil {
		return err
	}
	return Write(filepath.Join(out, "generated/manifest.json"), Object{"sourceSha256": Hash(raw), "renderedSha256": FileHash(filepath.Join(out, "generated/policy.json")), "policySpecSha256": Digest(rendered["spec"]), "sourceRevision": "fac1ccda72ab53594921ca1c040ac90b80afadcd", "action": At(rendered, "spec", "validationActions"), "namespace": s.Config["namespace"]})
}
func (s *Provider) GetResults(_ context.Context, p policy.Policy) (policy.PVPResult, error) {
	if err := s.check(p); err != nil {
		return policy.PVPResult{}, err
	}
	if s.Config["capture"] == "" {
		return policy.PVPResult{}, fmt.Errorf("missing capture path")
	}
	var c Capture
	if err := Read(s.Config["capture"], &c); err != nil {
		return policy.PVPResult{}, err
	}
	if _, err := VerifyPolicy(s.Config["root"], c); err != nil {
		return policy.PVPResult{}, err
	}
	_, result, err := Reconcile(c)
	return result, err
}
