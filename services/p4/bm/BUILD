load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "dataplane_interface_grpc",
    srcs = [
        "//services:generated/p4/bm/dataplane_interface.pb.cc",
        "//services:generated/p4/bm/dataplane_interface.grpc.pb.cc",
    ],
    hdrs = [
        "//services:generated/p4/bm/dataplane_interface.pb.h",
        "//services:generated/p4/bm/dataplane_interface.grpc.pb.h",
    ],
    deps = [
        "@protobuf//:protobuf",
        "@grpc//:grpc++",
    ],
    visibility = ["//visibility:public"],
)
