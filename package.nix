# SPDX-FileCopyrightText: 2026 The P4 Language Consortium
#
# SPDX-License-Identifier: Apache-2.0

# bmv2 as a Nix package: the CMake build with its default options, without PI.
#
# It follows nixpkgs conventions so that it can move there with one change,
# replacing `version` and `src` with a `fetchFromGitHub` call.
{
  lib,
  stdenv,
  cmake,
  ninja,
  ctestCheckHook,
  boost,
  gmp,
  jsoncpp,
  libpcap,
  nanomsg,
  thrift,
  xxhash,
  python3,
}:

stdenv.mkDerivation {
  pname = "bmv2";
  version = lib.trim (builtins.readFile ./VERSION);

  # What the CMake build reads. Changes elsewhere (docs, CI, these Nix files)
  # do not rebuild the package.
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./CMakeLists.txt
      ./LICENSES
      ./README.md
      ./VERSION
      ./cmake
      ./include
      ./src
      ./targets
      ./tests
      ./third_party
      ./thrift_src
      ./tools
    ];
  };

  # The test suite runs tools/runtime_CLI.py through its shebang, and the Nix
  # build sandbox has no /usr/bin/env.
  postPatch = ''
    patchShebangs --build tools
  '';

  strictDeps = true;

  nativeBuildInputs = [
    cmake
    ninja
    # The test suite drives the switch through runtime_CLI.py, which needs the
    # Thrift module.
    (python3.withPackages (ps: [ ps.thrift ]))
    python3.pkgs.wrapPython
    thrift # the compiler
  ];

  buildInputs = [
    boost
    gmp
    jsoncpp
    libpcap
    nanomsg
    thrift # the runtime library
    xxhash
  ];

  cmakeFlags = [
    # The Python modules would otherwise go to the interpreter's own
    # site-packages directory, a different store path.
    (lib.cmakeFeature "CMAKE_INSTALL_PYTHON_SET_DIR" "${placeholder "out"}/${python3.sitePackages}")
    # The queueing timing tests depend on the load of the build machine.
    (lib.cmakeBool "ENABLE_UNDETERMINISTIC_TESTS" false)
  ];

  doCheck = true;
  nativeCheckInputs = [ ctestCheckHook ];
  # test_devmgr and simple_switch/test_packet_redirect bind the same nanomsg
  # IPC socket path under /tmp, so they cannot run at the same time.
  enableParallelChecking = false;
  # These two check that an out-of-bounds meter index is rejected, but the
  # PSA and PNA meter externs only do that check `#ifndef NDEBUG`, and a
  # Release build (the default here) defines NDEBUG. The repo's own CI does
  # not build with CMAKE_BUILD_TYPE=Release, so it never sees this.
  disabledTests = [
    "psa_switch/test_meter_counter_bounds"
    "pna_nic/test_meter_counter_bounds"
  ];
  # Run ctest through the hook above (in parallel, with output on failure)
  # rather than through `ninja test`.
  dontUseNinjaCheck = true;

  # What the Python CLIs (bm_CLI, simple_switch_CLI, bm_p4dbg, ...) import.
  # (`python3.pkgs.thrift` spelled out: inside a `with`, `thrift` would still
  # be the C++ library from the arguments above.)
  pythonPath = [
    python3.pkgs.thrift
    python3.pkgs.pynng
  ];
  postFixup = ''
    wrapPythonPrograms
  '';

  meta = {
    description = "BMv2, the reference P4 software switch";
    homepage = "https://github.com/p4lang/behavioral-model";
    license = lib.licenses.asl20;
    platforms = lib.platforms.unix;
    mainProgram = "simple_switch";
  };
}
