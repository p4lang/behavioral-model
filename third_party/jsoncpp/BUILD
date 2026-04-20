load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "jsoncpp",
    hdrs = glob(["jsoncpp/*.h"]),
    includes = ["."],
    deps = ["@jsoncpp//:jsoncpp"],
    visibility = ["//visibility:public"],
)
