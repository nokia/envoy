#include "contrib/ldap_proxy/filters/network/source/config.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace LdapProxy {

/**
 * Config registration for the Ldap proxy filter. @see NamedNetworkFilterConfigFactory.
 */
Network::FilterFactoryCb
NetworkFilters::LdapProxy::LdapConfigFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::network::ldap_proxy::v3alpha::LdapProxy& proto_config,
    Server::Configuration::FactoryContext& context) {
  ASSERT(!proto_config.stat_prefix().empty());

  LdapFilterConfig::LdapFilterConfigOptions config_options;
  config_options.stats_prefix_ = fmt::format("ldap.{}", proto_config.stat_prefix());
  config_options.enable_sql_parsing_ =
      PROTOBUF_GET_WRAPPED_OR_DEFAULT(proto_config, enable_sql_parsing, true);
  config_options.terminate_ssl_ = proto_config.terminate_ssl();
  config_options.upstream_ssl_ = proto_config.upstream_ssl();

  LdapFilterConfigSharedPtr filter_config(
      std::make_shared<LdapFilterConfig>(config_options, context.scope()));
  return [filter_config](Network::FilterManager& filter_manager) -> void {
    filter_manager.addFilter(std::make_shared<LdapFilter>(filter_config));
  };
}

/**
 * Static registration for the Ldap proxy filter. @see RegisterFactory.
 */
REGISTER_FACTORY(LdapConfigFactory, Server::Configuration::NamedNetworkFilterConfigFactory);

} // namespace LdapProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
