"""
Module extension for system-installed libraries.
"""

def _ubuntu2204_impl(rctx):
    rctx.file("BUILD.bazel", """
load("@rules_cc//cc:cc_library.bzl", "cc_library")

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

# grpc
cc_library(
    name = "grpc",
    linkopts = [
        "-lgrpc++",
        "-lgrpc",
        "-lprotobuf",
        "-lgpr",
    ],
    visibility = ["//visibility:public"],
)
""")

_ubuntu2204_repo = repository_rule(
    implementation = _ubuntu2204_impl,
)

def _ubuntu2204_ext_impl(_):
    _ubuntu2204_repo(name = "ubuntu2204")

ubuntu2204 = module_extension(
    implementation = _ubuntu2204_ext_impl,
)
