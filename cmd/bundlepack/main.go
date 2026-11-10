// Command bundlepack builds and freezes a policy bundle. It is a build tool
// driven by `task bundles:package`; it is not part of the shipped image.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

var revision = regexp.MustCompile(`^[0-9a-f]{40}$`)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "bundlepack:", err)
		os.Exit(1)
	}
}

func run() error {
	root := flag.String("root", ".", "source checkout the definition's files are read from")
	name := flag.String("name", "", "bundle name (directory under bundles/)")
	rev := flag.String("revision", "", "full source commit the bundle is built from")
	when := flag.String("time", "", "source commit time, RFC 3339")
	out := flag.String("out", "", "new directory for the frozen OCI layout and package.json")
	flag.Parse()
	if *name == "" || *out == "" || !revision.MatchString(*rev) {
		return fmt.Errorf("usage: bundlepack -name NAME -revision <40-hex> -time RFC3339 -out NEWDIR [-root DIR]")
	}
	ts, err := time.Parse(time.RFC3339, *when)
	if err != nil {
		return fmt.Errorf("-time: %w", err)
	}
	// The name selects a directory; refuse anything that could leave bundles/.
	if filepath.Base(*name) != *name || *name == "." || *name == ".." {
		return fmt.Errorf("invalid bundle name %q", *name)
	}
	raw, err := os.ReadFile(filepath.Join(*root, "bundles", *name, "definition.json"))
	if err != nil {
		return err
	}
	def, err := bundle.LoadDefinition(raw)
	if err != nil {
		return err
	}
	if def.Name != *name {
		return fmt.Errorf("definition names %q but lives under bundles/%s", def.Name, *name)
	}
	def.Source.Revision = *rev
	a, err := bundle.Build(def, os.DirFS(*root), ts)
	if err != nil {
		return err
	}
	_, payload, err := bundle.Unpack(a.Layer)
	if err != nil {
		return err
	}
	if err := bundle.ValidateContent(a.Descriptor, payload); err != nil {
		return fmt.Errorf("content validation: %w", err)
	}
	if err := bundle.WriteLayout(*out+".tmp", a); err != nil {
		return err
	}
	if _, _, err := bundle.VerifyLayout(*out + ".tmp"); err != nil {
		os.RemoveAll(*out + ".tmp")
		return fmt.Errorf("frozen layout failed verification: %w", err)
	}
	if err := os.Rename(*out+".tmp", *out); err != nil {
		return err
	}
	record, err := json.MarshalIndent(map[string]any{
		"name": a.Descriptor.Name, "version": a.Descriptor.Version,
		"source":         map[string]string{"repository": def.Source.Repository, "revision": *rev, "time": ts.UTC().Format(time.RFC3339)},
		"manifestDigest": a.ManifestDigest, "layerDigest": a.LayerDigest,
		"tools": map[string]string{"go": runtime.Version()},
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "package.json"), append(record, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("%s %s\n", a.Descriptor.Name+"@"+a.Descriptor.Version, a.ManifestDigest)
	return nil
}
