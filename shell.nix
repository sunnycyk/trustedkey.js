with import <nixpkgs> {};
let
  pnpm = (nodePackages_8_x.pnpm.override (old: {
    preRebuild = ''
      sed -i 's|link:|file:|' package.json
    '';
  }));
in mkShell {
  buildInputs = [
    nodejs-8_x
    pnpm
  ];

  shellHook = ''
    export LANG="en_US.UTF-8"
    export PATH="$PATH:"$(pwd)/node_modules/.bin
  '';
}
