// Member sessions: bearer tokens signed with the instance key.
#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "store.hpp"

namespace toolshed::auth {

inline constexpr std::string_view kAlgorithm = "HS256";

std::optional<std::string> issue(const Member &member);
std::optional<Member>      authenticate(const Store &store, const std::string &email,
                                        const std::string &password);
std::optional<Member>      from_header(const Store &store, std::string_view authorization);

}  // namespace toolshed::auth
