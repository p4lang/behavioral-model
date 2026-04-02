load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "gmp",
    hdrs = ["include/gmp.h"],
    includes = ["include"],
    linkopts = [
        "-L/opt/homebrew/opt/gmp/lib",
        "-lgmp",
    ],
    visibility = ["//visibility:public"],
)
