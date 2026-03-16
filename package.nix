{
  lib,
  buildNpmPackage,
  nodejs,
  makeWrapper,
  iptables,
  iproute2,
  procps,
}:

buildNpmPackage rec {
  pname = "nospoon";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./bin
      ./lib
      ./package.json
      ./package-lock.json
    ];
  };

  npmDepsHash = "sha256-CfKFQ7Sdqvm5JSdNjvDTwb676PhYmEIJp54ogttm9+s=";

  # koffi ships prebuilds — no native compilation needed
  makeCacheWritable = true;
  dontNpmBuild = true;

  nativeBuildInputs = [
    makeWrapper
  ];

  # Wrap the binary so runtime tools are on PATH.
  # The tool calls iptables, ip (iproute2), and sysctl (procps) via execFileSync.
  postInstall = ''
    wrapProgram "$out/bin/${pname}" \
      --prefix PATH : "${lib.makeBinPath [ iptables iproute2 procps ]}"
  '';

  meta = {
    description = "P2P VPN over HyperDHT — WireGuard-like interface using Hyperswarm";
    license = lib.licenses.gpl3Only;
    mainProgram = "nospoon";
    platforms = lib.platforms.linux;
  };
}
