{
  description = "nospoon — P2P VPN over HyperDHT";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];

      forAllSystems = f:
        nixpkgs.lib.genAttrs supportedSystems (system: f {
          pkgs = nixpkgs.legacyPackages.${system};
        });
    in
    {
      packages = forAllSystems ({ pkgs }: let
        nospoon = pkgs.callPackage ./package.nix { };
      in {
        default = nospoon;
        nospoon = nospoon;
      });
    };
}
