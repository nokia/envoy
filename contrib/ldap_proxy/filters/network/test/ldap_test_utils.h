#pragma once

#include "source/common/buffer/buffer_impl.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace LdapProxy {

void createLdapMsg(Buffer::Instance& data, std::string type, std::string payload = "");
void createInitialLdapRequest(Buffer::Instance& data);

} // namespace LdapProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
