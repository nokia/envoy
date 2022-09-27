#pragma once

#include <functional>
#include <memory>
#include <string>

#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"
#include "contrib/sip_proxy/filters/network/source/sip.h"
#include "filters/filter.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace SipProxy {

enum SipMethodStatsSuffix {
	RequestReceived,
	RequestProxied,
	ResponseReceived,
	ResponseProxied,
	NullSuffix
};

#define SIP_METHOD_COUNTER_CONSTRUCT(method, postfix)                                              \
  POOL_COUNTER_PREFIX(scope, prefix)(method_##postfix)

#define SIP_METHOD_COUNTER(method, postfix)                                                        \
  sip_method_counter_vector_[method * SipMethodStatsPostfix::NullPosfix + postfix]

/**
 * All sip filter stats. @see stats_macros.h
 */
#define ALL_SIP_FILTER_STATS(COUNTER, GAUGE, HISTOGRAM)                                            \
  COUNTER(cx_destroy_local_with_active_rq)                                                         \
  COUNTER(cx_destroy_remote_with_active_rq)                                                        \
  COUNTER(request)                                                                                 \
  COUNTER(response)                                                                                \
  COUNTER(response_error)                                                                          \
  COUNTER(response_exception)                                                                      \
  COUNTER(response_reply)                                                                          \
  COUNTER(response_success)                                                                        \
  COUNTER(response_local_generated)                                                                        \
  GAUGE(request_active, Accumulate)                                                                \
  HISTOGRAM(request_time_ms, Milliseconds)

/**
 * Struct definition for all sip proxy stats. @see stats_macros.h
 */
struct SipFilterStats {
  ALL_SIP_FILTER_STATS(GENERATE_COUNTER_STRUCT, GENERATE_GAUGE_STRUCT, GENERATE_HISTOGRAM_STRUCT)

  static SipFilterStats generateStats(const std::string& prefix, Stats::Scope& scope) {
    std::vector<std::reference_wrapper<Envoy::Stats::Counter>> sip_method_counter_vector;
    for (int i = MethodType::Invite; i != MethodType::NullMethod; ++i) {
	auto method_str = methodStr[i];
	sip_method_counter_vector[i * SipMethodStatsSuffix::NullSuffix + SipMethodStatsSuffix::RequestReceived] = scope.counterFromString(Envoy::statPrefixJoin(prefix, method_str + "_request_received"));
	sip_method_counter_vector[i * SipMethodStatsSuffix::NullSuffix + SipMethodStatsSuffix::RequestProxied] = scope.counterFromString(Envoy::statPrefixJoin(prefix, method_str + "_request_proxied"));
	sip_method_counter_vector[i * SipMethodStatsSuffix::NullSuffix + SipMethodStatsSuffix::ResponseReceived] = scope.counterFromString(Envoy::statPrefixJoin(prefix, method_str + "_response_received"));
	sip_method_counter_vector[i * SipMethodStatsSuffix::NullSuffix + SipMethodStatsSuffix::ResponseProxied] = scope.counterFromString(Envoy::statPrefixJoin(prefix, method_str + "_response_proxied"));
    }

    return SipFilterStats{ALL_SIP_FILTER_STATS(POOL_COUNTER_PREFIX(scope, prefix),
                                               POOL_GAUGE_PREFIX(scope, prefix),
                                               POOL_HISTOGRAM_PREFIX(scope, prefix)) sip_method_counter_vector, scope};
  }

  Envoy::Stats::Counter & sipMethodCounter(MethodType method, SipMethodStatsSuffix suffix) {
  	return sip_method_counter_vector_[static_cast<int>(method) * SipMethodStatsSuffix::NullSuffix + suffix];
  }

  std::vector<std::reference_wrapper<Envoy::Stats::Counter>> sip_method_counter_vector_;
  Stats::Scope& scope_;
};

} // namespace SipProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
