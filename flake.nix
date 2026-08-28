{
  description = "Konstapel — Kopf-based Kubernetes operator for continuous compliance (C2P / cATO)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    # dagger is not in nixpkgs; upstream publishes it through NUR.
    nur = {
      url = "github:nix-community/NUR";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    nixpkgs,
    flake-utils,
    nur,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {inherit system;};
      nurPkgs = nur.legacyPackages.${system};

      # Pinned to 3.11 deliberately. Ticket #17 verified compliance-trestle
      # 5.0.0 round-trips the CCM catalog on Python 3.11.16; that result is
      # the basis for the "OSCAL models: zero lines" cost estimate in #2, so
      # the version it was proven on is the version we develop against.
      python = pkgs.python311;

      kubernetes = [
        pkgs.kubectl
        pkgs.kind
        pkgs.kubernetes-helm
        pkgs.kyverno # policy CLI: lint and test policies without a cluster
      ];

      testing = [
        pkgs.kyverno-chainsaw # declarative e2e against a kind cluster
      ];

      ci = [
        nurPkgs.repos.dagger.dagger # CI as code; same pipeline local and remote
      ];

      # Registry and signing tooling. Needed by the zero-egress verifyImages
      # spike (#15): signature artifacts are OCI objects that live beside the
      # image, so a mirror only works if they are copied too — `crane copy`,
      # not `docker pull` + `docker push`.
      supplyChain = [
        pkgs.go-containerregistry # provides `crane`
        pkgs.cosign
        pkgs.notation # the Notary path, no transparency log at all
        pkgs.skopeo
      ];

      utils = [
        pkgs.jq
        pkgs.yq-go
        pkgs.gh
        pkgs.git
        pkgs.unzip # the CSA bundles ship as zips
      ];

      pythonTools = [
        python
        pkgs.uv # operator deps: kopf, compliance-trestle, pytest, check-jsonschema
      ];
    in {
      devShells.default = pkgs.mkShell {
        name = "konstapel";

        packages = kubernetes ++ testing ++ ci ++ supplyChain ++ utils ++ pythonTools;

        shellHook = ''
          echo "konstapel devshell"
          echo "  python   $(python --version 2>&1 | cut -d' ' -f2)"
          echo "  kyverno  $(kyverno version 2>/dev/null | awk '/^Version/{print $2}')"
          echo "  chainsaw $(chainsaw version 2>/dev/null | awk -F': ' '/^Version/{print $2}')"
          echo "  dagger   $(dagger version 2>/dev/null | awk '{print $2}')"
          echo "  cosign   $(cosign version 2>/dev/null | awk -F': ' '/GitVersion/{print $2}')"
          echo
          echo "Record these versions in any research or spike finding —"
          echo "a result that cannot be attributed to a version is not reproducible."
        '';
      };

      formatter = pkgs.alejandra;
    });
}
