{ pkgs, lib, config, inputs, ... }:

{
  packages = [
    pkgs.git
    pkgs.libmnl
    pkgs.libnftnl
  ];

  languages = {
    rust = {
      enable = true;
      toolchainFile = ./rust-toolchain.toml;
    };
  };
}
