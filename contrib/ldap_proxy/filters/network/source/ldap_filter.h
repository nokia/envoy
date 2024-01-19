#pragma once

#include "envoy/network/filter.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"

#include "contrib/envoy/extensions/filters/network/ldap_proxy/v3alpha/ldap_proxy.pb.h"
#include "contrib/ldap_proxy/filters/network/source/ldap_decoder.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace LdapProxy {

/**
 * All Ldap proxy stats. @see stats_macros.h
 */
#define ALL_POSTGRES_PROXY_STATS(COUNTER)                                                          \
  COUNTER(errors)                                                                                  \
  COUNTER(errors_error)                                                                            \
  COUNTER(errors_fatal)                                                                            \
  COUNTER(errors_panic)                                                                            \
  COUNTER(errors_unknown)                                                                          \
  COUNTER(messages)                                                                                \
  COUNTER(messages_backend)                                                                        \
  COUNTER(messages_frontend)                                                                       \
  COUNTER(messages_unknown)                                                                        \
  COUNTER(sessions)                                                                                \
  COUNTER(sessions_encrypted)                                                                      \
  COUNTER(sessions_terminated_ssl)                                                                 \
  COUNTER(sessions_unencrypted)                                                                    \
  COUNTER(sessions_upstream_ssl_success)                                                           \
  COUNTER(sessions_upstream_ssl_failed)                                                            \
  COUNTER(statements)                                                                              \
  COUNTER(statements_insert)                                                                       \
  COUNTER(statements_delete)                                                                       \
  COUNTER(statements_update)                                                                       \
  COUNTER(statements_select)                                                                       \
  COUNTER(statements_other)                                                                        \
  COUNTER(transactions)                                                                            \
  COUNTER(transactions_commit)                                                                     \
  COUNTER(transactions_rollback)                                                                   \
  COUNTER(statements_parsed)                                                                       \
  COUNTER(statements_parse_error)                                                                  \
  COUNTER(notices)                                                                                 \
  COUNTER(notices_notice)                                                                          \
  COUNTER(notices_warning)                                                                         \
  COUNTER(notices_debug)                                                                           \
  COUNTER(notices_info)                                                                            \
  COUNTER(notices_log)                                                                             \
  COUNTER(notices_unknown)

/**
 * Struct definition for all Ldap proxy stats. @see stats_macros.h
 */
struct LdapProxyStats {
  ALL_POSTGRES_PROXY_STATS(GENERATE_COUNTER_STRUCT)
};

/**
 * Configuration for the Ldap proxy filter.
 */
class LdapFilterConfig {
public:
  struct LdapFilterConfigOptions {
    std::string stats_prefix_;
    bool enable_sql_parsing_;
    bool terminate_ssl_;
    envoy::extensions::filters::network::ldap_proxy::v3alpha::LdapProxy::SSLMode
        upstream_ssl_;
  };
  LdapFilterConfig(const LdapFilterConfigOptions& config_options, Stats::Scope& scope);

  bool enable_sql_parsing_{true};
  bool terminate_ssl_{false};
  envoy::extensions::filters::network::ldap_proxy::v3alpha::LdapProxy::SSLMode
      upstream_ssl_{
          envoy::extensions::filters::network::ldap_proxy::v3alpha::LdapProxy::DISABLE};
  Stats::Scope& scope_;
  LdapProxyStats stats_;

private:
  LdapProxyStats generateStats(const std::string& prefix, Stats::Scope& scope) {
    return LdapProxyStats{ALL_POSTGRES_PROXY_STATS(POOL_COUNTER_PREFIX(scope, prefix))};
  }
};

using LdapFilterConfigSharedPtr = std::shared_ptr<LdapFilterConfig>;

class LdapFilter : public Network::Filter,
                       DecoderCallbacks,
                       Logger::Loggable<Logger::Id::filter> {
public:
  LdapFilter(LdapFilterConfigSharedPtr config);
  ~LdapFilter() override = default;

  // Network::ReadFilter
  Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
  Network::FilterStatus onNewConnection() override;
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override;
  void initializeWriteFilterCallbacks(Network::WriteFilterCallbacks& callbacks) override;

  // Network::WriteFilter
  Network::FilterStatus onWrite(Buffer::Instance& data, bool end_stream) override;

  // LdapProxy::DecoderCallback
  void incErrors(ErrorType) override;
  void incMessagesBackend() override;
  void incMessagesFrontend() override;
  void incMessagesUnknown() override;
  void incNotices(NoticeType) override;
  void incSessionsEncrypted() override;
  void incSessionsUnencrypted() override;
  void incStatements(StatementType) override;
  void incTransactions() override;
  void incTransactionsCommit() override;
  void incTransactionsRollback() override;
  void processQuery(const std::string&) override;
  bool onSSLRequest() override;
  bool shouldEncryptUpstream() const override;
  void sendUpstream(Buffer::Instance&) override;
  bool encryptUpstream(bool, Buffer::Instance&) override;

  Network::FilterStatus doDecode(Buffer::Instance& data, bool);
  DecoderPtr createDecoder(DecoderCallbacks* callbacks);
  void setDecoder(std::unique_ptr<Decoder> decoder) { decoder_ = std::move(decoder); }
  Decoder* getDecoder() const { return decoder_.get(); }

  // Routines used during integration and unit tests
  uint32_t getFrontendBufLength() const { return frontend_buffer_.length(); }
  uint32_t getBackendBufLength() const { return backend_buffer_.length(); }
  const LdapProxyStats& getStats() const { return config_->stats_; }
  Network::Connection& connection() const { return read_callbacks_->connection(); }
  const LdapFilterConfigSharedPtr& getConfig() const { return config_; }

private:
  Network::ReadFilterCallbacks* read_callbacks_{};
  Network::WriteFilterCallbacks* write_callbacks_{};
  LdapFilterConfigSharedPtr config_;
  Buffer::OwnedImpl frontend_buffer_;
  Buffer::OwnedImpl backend_buffer_;
  std::unique_ptr<Decoder> decoder_;
};

} // namespace LdapProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
