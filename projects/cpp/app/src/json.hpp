// Small helpers to build JSON and HTML payloads.
#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace toolshed::json {

std::string quote(std::string_view text);
std::string escape_html(std::string_view text);

// Reads a top-level field of a flat JSON object.
std::optional<std::string> field(std::string_view body, std::string_view name);
long long field_number(std::string_view body, std::string_view name, long long fallback);

}  // namespace toolshed::json
