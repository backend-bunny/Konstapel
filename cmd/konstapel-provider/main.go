package main

import (
	"github.com/backend-bunny/Konstapel/internal/provider/c2p"
	"github.com/hashicorp/go-hclog"
	hplugin "github.com/hashicorp/go-plugin"
	"github.com/oscal-compass/compliance-to-policy-go/v2/plugin"
)

func main() {
	plugin.Register(plugin.ServeConfig{PluginSet: map[string]hplugin.Plugin{plugin.PVPPluginName: &plugin.PVPPlugin{Impl: &c2p.Provider{}}}, Logger: hclog.NewNullLogger()})
}
