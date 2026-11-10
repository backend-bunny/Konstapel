// Command bundlerelease validates an independent policy-bundle release and
// creates or verifies its bundle/<name>/vX.Y.Z Git tag. It is a build tool
// run by .github/workflows/bundle-release.yml; it is not part of the shipped
// image.
//
//	bundlerelease verify -name NAME -commit SHA [-main REF] [-package DIR]
//	bundlerelease tag    -name NAME -commit SHA -version V [-main REF] [-remote NAME]
//
// verify is read-only. It prints name, version, commit and tag (and digest
// when -package is given) as key=value lines for $GITHUB_OUTPUT. tag
// re-validates, requires the packaged version, then creates the tag on the
// remote or verifies that it already marks the same commit.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/backend-bunny/Konstapel/internal/bundle/release"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "bundlerelease:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 || (args[0] != "verify" && args[0] != "tag") {
		return fmt.Errorf("usage: bundlerelease verify|tag -name NAME -commit SHA ...")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	repo := fs.String("repo", ".", "repository checkout with reviewed main history and tags fetched")
	name := fs.String("name", "", "bundle name (directory under bundles/)")
	commit := fs.String("commit", "", "full reviewed source commit on main")
	mainRef := fs.String("main", "refs/remotes/origin/main", "fully qualified ref of reviewed main history")
	pkg := fs.String("package", "", "verify: frozen layout written by scripts/bundles/package.sh")
	version := fs.String("version", "", "tag: the version that was packaged")
	remote := fs.String("remote", "origin", "tag: remote that holds release tags")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments %q", fs.Args())
	}
	g := release.ExecGit{Dir: *repo}
	req := release.Request{Name: *name, Commit: *commit, MainRef: *mainRef}

	if args[0] == "verify" {
		rel, err := release.Validate(ctx, g, req)
		if err != nil {
			return err
		}
		fmt.Printf("name=%s\nversion=%s\ncommit=%s\ntag=%s\n", rel.Name, rel.Version, rel.Commit, rel.Tag)
		if *pkg != "" {
			digest, err := release.VerifyPackage(*pkg, rel)
			if err != nil {
				return err
			}
			fmt.Printf("digest=%s\n", digest)
		}
		return nil
	}
	if *version == "" {
		return fmt.Errorf("tag requires -version, the version that was packaged")
	}
	req.Version = *version
	rel, state, err := release.EnsureTag(ctx, g, req, *remote)
	if err != nil {
		return err
	}
	fmt.Printf("tag=%s\ncommit=%s\nstate=%s\n", rel.Tag, rel.Commit, state)
	return nil
}
