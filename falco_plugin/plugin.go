package main

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

type Plugin struct {
	plugins.BasePlugin
}

func (k *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          999,
		Name:        "nodrop",
		Description: "NoDrop FIFO JSON source",
		EventSource: "nodrop",
		Version:     "0.1.0",
	}
}

func (k *Plugin) Init(config string) error {
	return nil
}

func main() {}

func init() {
	plugins.SetFactory(func() plugins.Plugin {
		p := &Plugin{}
		source.Register(p)
		return p
	})
}