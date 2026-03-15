load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "dataplane_interface_grpc",
    srcs = [
        "generated/p4/bm/dataplane_interface.pb.cc",
        "generated/p4/bm/dataplane_interface.grpc.pb.cc",
    ],
    hdrs = [
        "generated/p4/bm/dataplane_interface.pb.h",
        "generated/p4/bm/dataplane_interface.grpc.pb.h",
    ],
    includes = ["generated"],
    deps = [
        "@protobuf//:protobuf",
        "@grpc//:grpc++",
    ],
    visibility = ["//visibility:public"],
)
