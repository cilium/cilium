{ pkgsPath ? <nixpkgs> }:

let
  # First we setup our overlays. These are overrides of the official nix packages.
  # We do this to pin the versions we want to use of the software that is in
  # the official nixpkgs repo.
  pkgs = import pkgsPath {
    overlays = [(self: super: {

      go = super.go.overrideAttrs ( old: rec {
        version = "1.14.5";
        src = super.fetchurl {
          url = "https://dl.google.com/go/go${version}.src.tar.gz";
          sha256 = "0p1i80j3dk597ph5h6mvvv8p7rbzwmxdfb6558amcpkkj060hk6a";
        };
      });

    })];
  };
in with pkgs; let
  go-protobuf = buildGoModule rec {
    pname = "go-protobuf";
    version = "v1.4.2";

    src = fetchFromGitHub {
      owner = "golang";
      repo = "protobuf";
      rev = "v1.4.2";
      sha256 = "0m5z81im4nsyfgarjhppayk4hqnrwswr3nix9mj8pff8x9jvcjqw";
    };

    modSha256 = "0lnk1zpl6y9vnq6h3l42ssghq6iqvmixd86g2drpa4z8xxk116wf";

    subPackages = [ "protoc-gen-go" ];
  };
in pkgs.mkShell rec {
  name = "waypoint";

  # The packages in the `buildInputs` list will be added to the PATH in our shell
  buildInputs = [
    pkgs.go
    go-protobuf
  ];
}
