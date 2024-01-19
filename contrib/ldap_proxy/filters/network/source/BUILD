load("@rules_foreign_cc//foreign_cc:configure.bzl", "configure_make")
load("//bazel:envoy_build_system.bzl", "envoy_contrib_package")
load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_contrib_extension",
    "envoy_cc_library",
    "envoy_contrib_package")
load(
    "//contrib:all_contrib_extensions.bzl",
    "envoy_contrib_linux_x86_64_constraints",
)

licenses(["notice"])  # Apache 2

envoy_contrib_package()

#package(default_visibility = ["//visibility:public"])

# LdapSQL proxy L7 network filter.
# Public docs: https://envoyproxy.io/docs/envoy/latest/configuration/listeners/network_filters/ldap_proxy_filter

envoy_cc_library(
    name = "filter",
    srcs = [
        "ldap_decoder.cc",
        "ldap_filter.cc",
        "ldap_message.cc",
    ],
    hdrs = [
        "ldap_decoder.h",
        "ldap_filter.h",
        "ldap_message.h",
        "ldap_session.h",
    ],
    repository = "@envoy",
    deps = [
        "//contrib/common/sqlutils/source:sqlutils_lib",
        "//envoy/network:filter_interface",
        "//envoy/server:filter_config_interface",
        "//envoy/stats:stats_interface",
        "//envoy/stats:stats_macros",
        "//source/common/buffer:buffer_lib",
        "//source/common/network:filter_lib",
        "//source/extensions/filters/network:well_known_names",
        "@envoy_api//contrib/envoy/extensions/filters/network/ldap_proxy/v3alpha:pkg_cc_proto",
	":liblber",
    ],
)

envoy_cc_contrib_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    repository = "@envoy",
    deps = [
        ":filter",
        "//source/extensions/filters/network:well_known_names",
        "//source/extensions/filters/network/common:factory_base_lib",
        "@envoy_api//contrib/envoy/extensions/filters/network/ldap_proxy/v3alpha:pkg_cc_proto",
    ],
)

configure_make(
    name = "liblber",
    autogen = False,
    configure_in_place = True,
    configure_options = [
    	"--disable-slapd",
    	"--disable-shared",
	"--disable-backends",
	"--disable-overlays",
	"--disable-versioning",
    	"--enable-static",
    ],
    #args = ["-C", "libraries/liblber", "liblber.la"],
    lib_source = "@org_openldap//:all",
    out_static_libs = [
        "liblber.a",
    #    "libusdm.a",
    ],
    target_compatible_with = envoy_contrib_linux_x86_64_constraints(),
    visibility = ["//visibility:public"],
    alwayslink = True,
)
