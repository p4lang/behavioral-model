load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "bmv2_core",
    srcs = glob(
        [
            "src/**/*.cpp",
            "src/**/*.c",
            "PI/src/*.cpp",
            "targets/simple_switch/simple_switch.cpp",
            "targets/simple_switch/primitives.cpp",
        ],
        exclude = [
            "src/bm_apps/**",
            "src/bm_runtime/**",
            "src/bf_lpm_trie/**",
            "src/bm_sim/md5.c",
        ],
    ),
    hdrs = glob([
        "include/**/*.h",
        "src/**/*.h",
        "targets/**/*.h",
        "third_party/spdlog/**/*.h",
        "third_party/spdlog/**/*.cc",
        "PI/**/*.h",
    ]),
    includes = [
        "include",
        "third_party/spdlog",
        "PI",
        "src/BMI",
        "src/bm_sim",
        "targets/simple_switch",
        "PI/src",
    ],
    linkopts = [
        "-L/opt/homebrew/opt/gmp/lib", "-lgmp",
        "-L/opt/homebrew/opt/libpcap/lib", "-lpcap",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "@protobuf//:protobuf",
        "//third_party/gmp:gmp",
        "//third_party/jsoncpp:jsoncpp",
        "//third_party/PI:PI",
        "@grpc//:grpc++",
        "@boost.thread//:boost.thread",
        "@boost.filesystem//:boost.filesystem",
        "@boost.program_options//:boost.program_options",
        "@boost.multiprecision//:boost.multiprecision",
        "@boost.variant//:boost.variant",
    ],
)
