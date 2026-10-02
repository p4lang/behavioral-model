# SPDX-FileCopyrightText: 2026 The P4 Language Consortium
#
# SPDX-License-Identifier: Apache-2.0

{
  description = "BMv2, the reference P4 software switch";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (
        system: pkgs: {
          bmv2 = pkgs.callPackage ./package.nix { };
          default = self.packages.${system}.bmv2;
        }
      );

      devShells = forAllSystems (
        system: pkgs: {
          # The build dependencies of the package; the CMake build steps in
          # README.md work unchanged inside this shell.
          default = pkgs.mkShell {
            inputsFrom = [ self.packages.${system}.bmv2 ];
            # Keep the compiler flags the same as on any other toolchain. The
            # nixpkgs compiler wrapper would otherwise add hardening flags
            # (fortify, stack protector, ...) that no other build of bmv2 uses,
            # and that -Werror turns into errors in -O0 builds; see
            # https://github.com/NixOS/nixpkgs/issues/60919.
            hardeningDisable = [ "all" ];
          };
        }
      );

      formatter = forAllSystems (system: pkgs: pkgs.nixfmt);
    };
}
