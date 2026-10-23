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

                  ttp-wrapper = pkgs.writeShellApplication {
                    name = "corndog-ttp";
                    text = ''
                      ${runtime-ttp}/bin/runtime_ttp --component-path ${ttp-component}/lib/agent_ttp.wasm "$@"
                    '';
                  };

                  source-wrapper = pkgs.writeShellApplication {
                    name = "corndog-source";
                    text = ''
                      ${runtime-source}/bin/runtime_source --component-path ${agent-component}/lib/agent_source_destination.wasm "$@"
                    '';
                  };

                  destination-wrapper = pkgs.writeShellApplication {
                    name = "corndog-destination";
                    text = ''
                      ${runtime-destination}/bin/runtime_destination --component-path ${agent-component}/lib/agent_source_destination.wasm "$@"
                    '';
                  };

                  testMachines = {
                      source = { config, pkgs, ... }: {
                        system.stateVersion = "26.05";
                        environment.systemPackages = [ source-wrapper pkgs.jq ];
                      };

                      destination = { config, pkgs, ... }: {
                        system.stateVersion = "26.05";
                        environment.systemPackages = [ destination-wrapper pkgs.jq ];
                        networking.firewall.allowedTCPPorts = [ 7760 ];
                      };

                      ttp = { config, pkgs, ... }: {
                        system.stateVersion = "26.05";
                        environment.systemPackages = [ ttp-wrapper ];
                        networking.firewall.allowedTCPPorts = [ 9705 ];
                      };
                  };

                  testScript = { nodes, ... }: ''
                      start_all();
                      source.wait_for_unit('default.target')

                      with subtest('Generate key material'):
                        source.succeed('corndog-source --force --generate-keypair /tmp/shared/source.key')
                        source.wait_for_file('/tmp/shared/source.key', 0)
                        source.wait_for_file('/tmp/shared/source.key.pub', 0)
                        destination.wait_for_file('/tmp/shared/source.key.pub', 0)

                        destination.succeed('corndog-destination --force --generate-keypair /tmp/shared/destination.key')
                        destination.wait_for_file('/tmp/shared/destination.key', 0)
                        destination.wait_for_file('/tmp/shared/destination.key.pub', 0)
                        source.wait_for_file('/tmp/shared/destination.key.pub', 0)

                      with subtest('Run the protocol'):
                          ttp.succeed("(corndog-ttp >/tmp/ttp.log 2>/tmp/ttp.err; echo $?>/tmp/ttp.rc) >/dev/null &");
                          ttp.wait_until_succeeds("ss -Htln sport = :9705 | grep -q .", timeout=30)

                          destination.succeed("(echo Test | corndog-destination --dest-private-key /tmp/shared/destination.key --source-public-key /tmp/shared/source.key.pub --ttp-addr ttp:9705 >/tmp/dest.log 2>/tmp/dest.err; echo $? > /tmp/dest.rc)  >/dev/null &")
                          destination.wait_until_succeeds("ss -Htln sport = :7760 | grep -q .", timeout=30)

                          source.succeed("echo Test | corndog-source --source-private-key /tmp/shared/source.key --destination-public-key /tmp/shared/destination.key.pub --destination-addr destination:7760 --ttp-addr ttp:9705 > /tmp/source.log", timeout=60)
                          destination.wait_for_file("/tmp/dest.rc", timeout=5)
                          destination.succeed('[ "$(cat /tmp/dest.rc)" -eq 0 ]')

                          source.succeed('[ "$(jq -r .status < /tmp/source.log)"  = commit ]')
                          source.succeed('[ "$(jq -r .method < /tmp/source.log)"  = direct ]')

                          destination.succeed('[ "$(jq -r .status < /tmp/dest.log)" = commit ]')
                          destination.succeed('[ "$(jq -r .method < /tmp/dest.log)" = direct ]')
                    '';



                in {

                  packages.agent-component = agent-component;
                  packages.ttp-component = ttp-component;

                  packages.ttp = ttp-wrapper;
                  packages.source = source-wrapper;
                  packages.destination = destination-wrapper;

                  apps.ttp = {
                    type  = "app";
                    program = ttp-wrapper;
                    meta = {
                      description = "Trusted arbitrator for Corndog protocol";
                    };
                  };

                  apps.source = {
                    type  = "app";
                    program = source-wrapper;
                    meta = {
                      description = "Migration source for Corndog protocol";
                    };
                  };

                  apps.destination = {
                    type  = "app";
                    program = destination-wrapper;
                    meta = {
                      description = "Migration destination for Corndog protocol";
                    };
                  };

                  apps.demo = {
                    type = "app";
                    program = pkgs.writeShellApplication {
                      name = "corndog-demo";
                      runtimeInputs = [
                        pkgs.tmux pkgs.tmuxp
                        ttp-wrapper source-wrapper destination-wrapper
                        ];
                      text = ''
                        DEMO_PATH="$(mktemp -d --suffix "corndog")" 
                        DEMO_PATH="$DEMO_PATH" tmuxp load ${./corndog-demo.tmuxp.yaml}
                        rm -rf "$DEMO_PATH"
                      '';
                    };
                  };

                  checks.clippy-wasm = craneLib.cargoClippy ( commonArgs // {
                    inherit agent-component ttp-component;
                    pname = "corndog-wasm";
                    version = "0.0.0";
                    cargoArtifacts = wasmArtifacts;
                    cargoClippyExtraArgs = "-p agent_source_destination -p agent_ttp";
                  });

                  checks.end-to-end = pkgs.testers.runNixOSTest {
                    name = "end-to-end corndog";
                    nodes = testMachines;
                    inherit testScript;
                  };

                  devShells.default = craneLib.devShell {
                    packages = with pkgs; [
                      wasm-tools
                    ];
                  };

                };
              });

}
