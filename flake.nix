{
  description = "Corndog protocol prototype";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    crane.url = "github:ipetkov/crane";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs@{ nixpkgs, flake-parts, ... }:
              flake-parts.lib.mkFlake
                { inherit inputs; }
                (top@{ config, withSystem, moduleWithSystem, ...}: {

                systems = [ "x86_64-linux" ];

                perSystem = { config, lib, pkgs, ... }:
                let
                  rustBin = inputs.rust-overlay.lib.mkRustBin {} pkgs;
                  toolchain = rustBin.fromRustupToolchainFile ./rust-toolchain.toml;
                  craneLib = (inputs.crane.mkLib pkgs).overrideToolchain (p: toolchain);
                  witOrCargo = path: type:
                    (craneLib.filterCargoSources path type) || (null != builtins.match ".*\\.wit$" path);

                  sources = lib.cleanSourceWith {
                    src = ./.;
                    filter = witOrCargo;
                    name = "source";
                  };

                  commonArgs = {
                    src = sources;
                    strictDeps = true;
                  };

                  wasmArgs = commonArgs // {
                    CARGO_BUILD_TARGET = "wasm32-wasip2";
                    doCheck = false;
                  };

                  nativeArtifacts = craneLib.buildDepsOnly ( commonArgs // {
                      pname = "corndog-native";
                      version = "0.0.0";
                      cargoExtraArgs = "-p runtime_source -p runtime_destination -p runtime_ttp";
                    });

                  wasmArtifacts = craneLib.buildDepsOnly ( wasmArgs // {
                      pname = "corndog-wasm";
                      version = "0.0.0";
                      cargoExtraArgs = "-p agent_ttp -p agent_source_destination";
                    });

                  agent-component = craneLib.buildPackage ( wasmArgs // craneLib.crateNameFromCargoToml { cargoToml = ./agent_source_destination/Cargo.toml; } // {
                    cargoArtifacts = wasmArtifacts;
                    cargoExtraArgs = "-p agent_source_destination";
                  });

                  ttp-component = craneLib.buildPackage ( wasmArgs // craneLib.crateNameFromCargoToml { cargoToml = ./agent_ttp/Cargo.toml; } // {
                    cargoArtifacts = wasmArtifacts;
                    cargoExtraArgs = "-p agent_ttp";
                  });

                  runtime-ttp = craneLib.buildPackage ( commonArgs // craneLib.crateNameFromCargoToml { cargoToml = ./runtime_ttp/Cargo.toml; } // {
                    cargoArtifacts = nativeArtifacts;
                    cargoExtraArgs = "-p runtime_ttp";
                  });

                  runtime-source = craneLib.buildPackage ( commonArgs // craneLib.crateNameFromCargoToml { cargoToml = ./runtime_source/Cargo.toml; } // {
                    cargoArtifacts = nativeArtifacts;
                    cargoExtraArgs = "-p runtime_source";
                  });

                  runtime-destination = craneLib.buildPackage ( commonArgs // craneLib.crateNameFromCargoToml { cargoToml = ./runtime_destination/Cargo.toml; } // {
                    cargoArtifacts = nativeArtifacts;
                    cargoExtraArgs = "-p runtime_destination";
                  });

                in {

                  packages.agent-component = agent-component;
                  packages.ttp-component = ttp-component;

                  packages.ttp = pkgs.writeShellApplication {
                    name = "corndog-ttp";
                    text = ''
                      ${runtime-ttp}/bin/runtime_ttp --component-path ${ttp-component}/lib/agent_ttp.wasm
                    '';
                  };

                  packages.source = pkgs.writeShellApplication {
                    name = "corndog-source";
                    text = ''
                      ${runtime-source}/bin/runtime_source --component-path ${agent-component}/lib/agent_source_destination.wasm
                    '';
                  };

                  packages.destination = pkgs.writeShellApplication {
                    name = "corndog-destination";
                    text = ''
                      ${runtime-destination}/bin/runtime_destination --component-path ${agent-component}/lib/agent_source_destination.wasm
                    '';
                  };

                  checks.clippy-wasm = craneLib.cargoClippy ( commonArgs // {
                    inherit agent-component ttp-component;
                    pname = "corndog-wasm";
                    version = "0.0.0";
                    cargoArtifacts = wasmArtifacts;
                    cargoClippyExtraArgs = "-p agent_source_destination -p agent_ttp";
                  });

                  devShells.default = craneLib.devShell {
                    packages = with pkgs; [
                      wasm-tools
                    ];
                  };

                };
              });

}
