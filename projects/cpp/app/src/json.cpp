#include "json.hpp"

#include <cctype>
#include <charconv>
#include <sstream>

namespace toolshed::json {

std::string quote(std::string_view text)
{
    std::string out;
    out.reserve(text.size() + 2);
    out.push_back('"');
    for (unsigned char c : text) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (c < 0x20) {
                char escape[7];
                std::snprintf(escape, sizeof escape, "\\u%04x", c);
                out += escape;
            } else {
                out.push_back(static_cast<char>(c));
            }
        }
    }
    out.push_back('"');
    return out;
}

std::string escape_html(std::string_view text)
{
    std::string out;
    out.reserve(text.size());
    for (char c : text) {
        switch (c) {
        case '&':  out += "&amp;";  break;
        case '<':  out += "&lt;";   break;
        case '>':  out += "&gt;";   break;
        case '"':  out += "&quot;"; break;
        case '\'': out += "&#39;";  break;
        default:   out.push_back(c);
        }
    }
    return out;
}

namespace {

std::size_t find_value(std::string_view body, std::string_view name)
{
    const std::string needle = "\"" + std::string(name) + "\"";
    std::size_t at = body.find(needle);
    if (at == std::string_view::npos) {
        return std::string_view::npos;
    }
    at += needle.size();
    while (at < body.size() && std::isspace(static_cast<unsigned char>(body[at]))) {
        at++;
    }
    if (at >= body.size() || body[at] != ':') {
        return std::string_view::npos;
    }
    at++;
    while (at < body.size() && std::isspace(static_cast<unsigned char>(body[at]))) {
        at++;
    }
    return at;
}

}  // namespace

std::optional<std::string> field(std::string_view body, std::string_view name)
{
    std::size_t at = find_value(body, name);
    if (at == std::string_view::npos || body[at] != '"') {
        return std::nullopt;
    }
    at++;
    std::string out;
    while (at < body.size() && body[at] != '"') {
        if (body[at] == '\\' && at + 1 < body.size()) {
            at++;
            switch (body[at]) {
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            default:  out.push_back(body[at]);
            }
        } else {
            out.push_back(body[at]);
        }
        at++;
    }
    return out;
}

long long field_number(std::string_view body, std::string_view name, long long fallback)
{
    std::size_t at = find_value(body, name);
    if (at == std::string_view::npos) {
        return fallback;
    }
    long long value = 0;
    const char *begin = body.data() + at;
    const char *end = body.data() + body.size();
    auto [ptr, ec] = std::from_chars(begin, end, value);
    return ec == std::errc{} && ptr != begin ? value : fallback;
}

}  // namespace toolshed::json
