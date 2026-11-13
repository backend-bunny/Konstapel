//go:build live

package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"testing"

	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/observability"
)

func liveSeries(t *testing.T, hub *observability.Hub) map[string]float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(hub)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, f := range families {
		for _, m := range f.Metric {
			var ls []string
			for _, l := range m.Label {
				ls = append(ls, fmt.Sprintf("%s=%q", l.GetName(), l.GetValue()))
			}
			if m.Gauge != nil {
				out[f.GetName()+"{"+strings.Join(ls, ",")+"}"] = m.Gauge.GetValue()
			}
		}
	}
	return out
}

// The manager's owners publish their projections through the Hub: binding
// Conditions and capabilities from the synchronized cache, the storage
// backlog from run records; a binding's deletion removes its series and
// the end of leadership clears every projection.
func TestLiveObservability(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	l.setNamespace("observe-prod", "production")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "observe-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	b := bindingObj("observe-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "production"})
	for _, o := range []client.Object{p, b} {
		o.SetUID("")
		o.SetGeneration(0)
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = l.c.Delete(context.Background(), &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: b.Name}})
		_ = l.c.Delete(context.Background(), &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: p.Name}})
	})

	hub, err := observability.NewHub(observability.Options{Enabled: []observability.Domain{observability.DomainTargeting, observability.DomainEvidenceStorage}})
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := NewManager(l.cfg, Options{Content: content, MetricsAddr: "0", ProbeAddr: "0", EnginePoll: 2 * time.Second,
		SkipControllerNameValidation: true, Observability: hub})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(l.ctx)
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			cancel()
			if err := <-done; err != nil {
				t.Errorf("manager exited: %v", err)
			}
		}
	}
	t.Cleanup(stop)

	l.waitReady(b.Name, 1)
	ready := fmt.Sprintf(`konstapel_binding_condition{binding=%q,condition="EngineReady",status="true"}`, b.Name)
	l.eventually("projected binding", func() (bool, string) {
		s := liveSeries(t, hub)
		return s[`konstapel_observation_ready{domain="targeting"}`] == 1 && s[ready] == 1 &&
			s[fmt.Sprintf(`konstapel_binding_target_namespaces{binding=%q}`, b.Name)] == 1 &&
			s[`konstapel_capability_condition{capability="policy_delivery",status="true"}`] == 1 &&
			s[`konstapel_observation_ready{domain="evidence_storage"}`] == 1, fmt.Sprint(s)
	})
	s := liveSeries(t, hub)
	if _, ok := s["konstapel_publication_failed{}"]; !ok {
		t.Fatal("ready storage projection lacks its backlog")
	}
	if s[`konstapel_observation_enabled{domain="assessment"}`] != 0 || s[`konstapel_observation_ready{domain="assessment"}`] != 0 {
		t.Fatal("an unwired domain is reported enabled or ready")
	}
	l.record("projected", map[string]any{"series": len(s)})

	if err := l.c.Delete(l.ctx, l.binding(b.Name)); err != nil {
		t.Fatal(err)
	}
	l.eventually("deleted binding's series removed", func() (bool, string) {
		for k := range liveSeries(t, hub) {
			if strings.Contains(k, fmt.Sprintf("binding=%q", b.Name)) {
				return false, k
			}
		}
		return true, ""
	})

	stop()
	s = liveSeries(t, hub)
	for k, v := range s {
		if strings.HasPrefix(k, "konstapel_observation_ready") && v != 0 || strings.HasPrefix(k, "konstapel_capability_") || strings.HasPrefix(k, "konstapel_publication_") {
			t.Errorf("after leadership ended: %s = %v", k, v)
		}
	}
	l.record("released", map[string]any{"series": len(s)})
}
