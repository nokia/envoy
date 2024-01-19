load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_cc_test_library",
    "envoy_contrib_package",
    "envoy_proto_library",
)

licenses(["notice"])  # Apache 2

envoy_contrib_package()

envoy_cc_test_library(
    name = "ldap_test_utils_lib",
    srcs = ["ldap_test_utils.cc"],
    hdrs = ["ldap_test_utils.h"],
    deps = [
        "//contrib/ldap_proxy/filters/network/source:filter",
        "//source/common/buffer:buffer_lib",
    ],
)

envoy_cc_test(
    name = "ldap_decoder_tests",
    srcs = [
        "ldap_decoder_test.cc",
    ],
    deps = [
        ":ldap_test_utils_lib",
        "//contrib/ldap_proxy/filters/network/source:filter",
        "//test/mocks/network:network_mocks",
    ],
)

envoy_cc_test(
    name = "ldap_message_tests",
    srcs = [
        "ldap_message_test.cc",
    ],
    deps = [
        "//contrib/ldap_proxy/filters/network/source:filter",
        "//source/common/buffer:buffer_lib",
    ],
)

envoy_cc_test(
    name = "ldap_filter_tests",
    srcs = [
        "ldap_filter_test.cc",
    ],
    deps = [
        ":ldap_test_utils_lib",
        "//contrib/ldap_proxy/filters/network/source:filter",
        "//test/mocks/network:network_mocks",
    ],
)

envoy_proto_library(
    name = "ldap_integration_proto",
    srcs = [":ldap_integration_test.proto"],
)

envoy_cc_test(
    name = "ldap_integration_test",
    srcs = [
        "ldap_integration_test.cc",
    ],
    data = [
        "ldap_test_config.yaml-template",
        "//test/config/integration/certs",
    ],
    deps = [
        ":ldap_integration_proto_cc_proto",
        ":ldap_test_utils_lib",
        "//contrib/ldap_proxy/filters/network/source:config",
        "//contrib/ldap_proxy/filters/network/source:filter",
        "//source/common/tcp_proxy",
        "//source/extensions/filters/network/tcp_proxy:config",
        "//source/extensions/transport_sockets/starttls:config",
        "//test/integration:integration_lib",
        "//test/test_common:registry_lib",
        "@envoy_api//contrib/envoy/extensions/filters/network/ldap_proxy/v3alpha:pkg_cc_proto",
    ],
)
