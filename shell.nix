with import <nixpkgs> {};

mkShell {
  buildInputs = [
    nodejs-8_x
    nodePackages_8_x.pnpm
    nodePackages_8_x.yarn
  ];

  shellHook = ''
    export LANG="en_US.UTF-8"
    export PATH="$PATH:"$(pwd)/node_modules/.bin
  '';
}
