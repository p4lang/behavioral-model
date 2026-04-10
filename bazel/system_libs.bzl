"""
Module extension for system-installed libraries.

These libraries are installed via install_deps_ubuntu_22.04.sh:
  - p4lang/PI:  pi, pifeproto, pigrpcserver, pip4info, piprotogrpc, piprotobuf
  - Boost:      program_options, filesystem, thread, system
  - GMP, PCAP, nanomsg
"""

def _system_libs_impl(rctx):
    rctx.file("BUILD.bazel", """
# p4lang/PI libraries (installed via apt: p4lang-pi)
cc_library(
    name = "pi",
    linkopts = ["-lpi"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "pifeproto",
    linkopts = ["-lpifeproto"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "pigrpcserver",
    linkopts = ["-lpigrpcserver"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "pip4info",
    linkopts = ["-lpip4info"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "piprotogrpc",
    linkopts = ["-lpiprotogrpc"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "piprotobuf",
    linkopts = ["-lpiprotobuf"],
    visibility = ["//visibility:public"],
)

# Boost libraries
cc_library(
    name = "boost_program_options",
    linkopts = ["-lboost_program_options"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "boost_filesystem",
    linkopts = ["-lboost_filesystem"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "boost_thread",
    linkopts = ["-lboost_thread"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "boost_system",
    linkopts = ["-lboost_system"],
    visibility = ["//visibility:public"],
)

# GMP (GNU Multiple Precision)
cc_library(
    name = "gmp",
    linkopts = ["-lgmp"],
    visibility = ["//visibility:public"],
)

# PCAP
cc_library(
    name = "pcap",
    linkopts = ["-lpcap"],
    visibility = ["//visibility:public"],
)

# nanomsg
cc_library(
    name = "nanomsg",
    linkopts = ["-lnanomsg"],
    visibility = ["//visibility:public"],
)
""")

_system_libs_repo = repository_rule(
    implementation = _system_libs_impl,
)

def _system_libs_ext_impl(mctx):
    _system_libs_repo(name = "system_libs")

system_libs = module_extension(
    implementation = _system_libs_ext_impl,
)
