{
  inputs = {
    nixpkgs = {
      url = "github:NixOS/nixpkgs/nixos-unstable";
    };
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
    };
    crane = {
      url = "github:ipetkov/crane";
    };
    fenix = {
      url = "github:nix-community/fenix";
      inputs = {
        nixpkgs = {
          follows = "nixpkgs";
        };
      };
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs = {
          follows = "nixpkgs";
        };
      };
    };
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
    nix-filter = {
      url = "github:numtide/nix-filter";
    };
    lpi = {
      url = "github:cymenix/lpi";
    };
  };

  outputs = {...} @ inputs:
    with inputs;
      flake-parts.lib.mkFlake {inherit inputs;} {
        systems = [
          "x86_64-linux"
          "aarch64-linux"
        ];
        perSystem = {
          pkgs,
          system,
          ...
        }: let
          rustToolchain = fenix.packages.${system}.fromToolchainFile {
            file = ./rust-toolchain.toml;
            sha256 = "sha256-VZZnlyP69+Y3crrLHQyJirqlHrTtGTsyiSnZB8jEvVo=";
          };

          pkgs = import nixpkgs {
            inherit system;
            overlays = [
              (import rust-overlay)
              (final: prev: {
                lpi = inputs.lpi.packages.${system}.default;
              })
            ];
          };

          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

          src = nix-filter.lib {
            root = ./.;
            include = [
              ./Cargo.toml
              ./Cargo.lock
              ./taplo.toml
              ./rustfmt.toml
              ./rust-toolchain.toml
              ./deny.toml
              ./.config
              ./crates
            ];
          };

          inherit (craneLib.crateNameFromCargoToml {inherit src;}) pname version;

          args = {
            inherit src;
            strictDeps = true;
            buildInputs = with pkgs; [openssl];
            nativeBuildInputs = with pkgs; [pkg-config];
          };

          individualCrateArgs =
            args
            // {
              inherit cargoArtifacts version;
              doCheck = false;
            };

          fileSetForCrate = crateFiles:
            nix-filter.lib {
              root = ./.;
              include =
                [
                  ./Cargo.toml
                  ./Cargo.lock
                  ./crates/workspace
                ]
                ++ crateFiles;
            };

          cargoArtifacts = craneLib.buildDepsOnly args;

          cryptology = craneLib.buildPackage (individualCrateArgs
            // {
              cargoExtraArgs = "-p ${pname}";
              src = fileSetForCrate [
                ./crates/cryptology
              ];
            });
        in {
          checks = {
            inherit cryptology;

            clippy = craneLib.cargoClippy (args
              // {
                inherit cargoArtifacts;
                cargoClippyExtraArgs = "--all-targets -- --deny warnings";
              });

            doc = craneLib.cargoDoc (args
              // {
                inherit cargoArtifacts;
              });

            fmt = craneLib.cargoFmt {
              inherit src;
            };

            toml-fmt = craneLib.taploFmt {
              src = pkgs.lib.sources.sourceFilesBySuffices src [".toml"];
              taploExtraArgs = "--config ./taplo.toml";
            };

            audit = craneLib.cargoAudit {
              inherit src advisory-db;
            };

            deny = craneLib.cargoDeny {
              inherit src;
            };

            nextest = craneLib.cargoNextest (args
              // {
                inherit cargoArtifacts;
                partitions = 1;
                partitionType = "count";
              });

            coverage = craneLib.cargoLlvmCov (args
              // {
                inherit cargoArtifacts;
              });

            hakari = craneLib.mkCargoDerivation {
              inherit src;
              pname = "workspace";
              cargoArtifacts = null;
              doInstallCargoArtifacts = false;

              buildPhaseCargoCommand = ''
                cargo hakari generate --diff
                cargo hakari manage-deps --dry-run
                cargo hakari verify
              '';

              nativeBuildInputs = [
                pkgs.cargo-hakari
              ];
            };
          };

          packages = {
            inherit cryptology;
            default = self.packages.${system}.cryptology;
          };

          devShells = {
            default = craneLib.devShell {
              checks = self.checks.${system};
              packages = with pkgs; [
                rust-analyzer
                proto
                moon
                alejandra
                hadolint
                cargo-watch
                cargo-audit
                cargo-deny
                cargo-llvm-cov
                cargo-tarpaulin
                cargo-nextest
                cargo-hakari
                taplo
                lpi
                lazydocker
              ];
              RUST_SRC_PATH = "${craneLib.rustc}/lib/rustlib/src/rust/library";
              RUST_BACKTRACE = 1;
              shellHook = ''
                moon sync projects
                export MOON=$(pwd)
              '';
            };
          };
          formatter = pkgs.alejandra;
        };
      };

  nixConfig = {
    extra-substituters = [
      "https://nix-community.cachix.org"
      "https://clemenscodes.cachix.org"
    ];
    extra-trusted-public-keys = [
      "nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs="
      "clemenscodes.cachix.org-1:yEwW1YgttL2xdsyfFDz/vv8zZRhRGMeDQsKKmtV1N18="
    ];
  };
}
