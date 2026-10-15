#include "auth.hpp"

#include <array>
#include <chrono>
#include <cstdlib>
#include <string>

#include <openssl/hmac.h>

#include "json.hpp"

namespace toolshed::auth {
namespace {

constexpr std::string_view kAlphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string b64url(std::string_view input)
{
    std::string out;
    out.reserve((input.size() + 2) / 3 * 4);
    for (std::size_t i = 0; i < input.size(); i += 3) {
        unsigned int block = static_cast<unsigned char>(input[i]) << 16;
        std::size_t have = 1;
        if (i + 1 < input.size()) {
            block |= static_cast<unsigned char>(input[i + 1]) << 8;
            have = 2;
        }
        if (i + 2 < input.size()) {
            block |= static_cast<unsigned char>(input[i + 2]);
            have = 3;
        }
        for (std::size_t j = 0; j <= have; j++) {
            out.push_back(kAlphabet[(block >> (18 - 6 * j)) & 0x3f]);
        }
    }
    return out;
}

std::optional<std::string> unb64url(std::string_view input)
{
    std::string out;
    unsigned int block = 0;
    int bits = 0;
    for (char c : input) {
        const std::size_t value = kAlphabet.find(c);
        if (value == std::string_view::npos) {
            return std::nullopt;
        }
        block = (block << 6) | static_cast<unsigned int>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((block >> bits) & 0xff));
        }
    }
    return out;
}

std::optional<std::string> signing_key()
{
    const char *key = std::getenv("TOOLSHED_TOKEN_KEY");
    if (key == nullptr || *key == '\0') {
        return std::nullopt;
    }
    return std::string{key};
}

long long ttl()
{
    const char *raw = std::getenv("TOOLSHED_TOKEN_TTL");
    if (raw == nullptr) {
        return 3600;
    }
    const long long value = std::strtoll(raw, nullptr, 10);
    return value > 0 ? value : 3600;
}

std::optional<std::string> sign(const std::string &key, const std::string &payload)
{
    std::array<unsigned char, EVP_MAX_MD_SIZE> mac{};
    unsigned int mac_len = 0;
    if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
             reinterpret_cast<const unsigned char *>(payload.data()), payload.size(),
             mac.data(), &mac_len) == nullptr) {
        return std::nullopt;
    }
    return b64url(std::string_view{reinterpret_cast<const char *>(mac.data()), mac_len});
}

bool equal_in_constant_time(std::string_view a, std::string_view b)
{
    if (a.size() != b.size()) {
        return false;
    }
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); i++) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

long long now_seconds()
{
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

}  // namespace

std::optional<std::string> issue(const Member &member)
{
    const auto key = signing_key();
    if (!key) {
        return std::nullopt;
    }
    const long long now = now_seconds();
    const std::string header = R"({"alg":"HS256","typ":"JWT"})";
    const std::string claims =
        "{\"sub\":\"" + std::to_string(member.id) + "\"" +
        ",\"email\":" + json::quote(member.email) +
        ",\"role\":" + json::quote(member.role) +
        ",\"iat\":" + std::to_string(now) +
        ",\"exp\":" + std::to_string(now + ttl()) + "}";
    const std::string body = b64url(header) + "." + b64url(claims);
    const auto mac = sign(*key, body);
    if (!mac) {
        return std::nullopt;
    }
    return body + "." + *mac;
}

std::optional<Member> authenticate(const Store &store, const std::string &email,
                                   const std::string &password)
{
    auto member = store.member_by_email(email);
    if (!member || !check_password(password, member->password)) {
        return std::nullopt;
    }
    return member;
}

std::optional<Member> from_header(const Store &store, std::string_view authorization)
{
    constexpr std::string_view prefix = "Bearer ";
    if (authorization.substr(0, prefix.size()) != prefix) {
        return std::nullopt;
    }
    const std::string_view token = authorization.substr(prefix.size());
    const std::size_t last_dot = token.rfind('.');
    const std::size_t first_dot = token.find('.');
    if (last_dot == std::string_view::npos || first_dot == last_dot) {
        return std::nullopt;
    }
    const auto key = signing_key();
    if (!key) {
        return std::nullopt;
    }
    const auto expected = sign(*key, std::string{token.substr(0, last_dot)});
    if (!expected || !equal_in_constant_time(token.substr(last_dot + 1), *expected)) {
        return std::nullopt;
    }
    const auto claims =
        unb64url(token.substr(first_dot + 1, last_dot - first_dot - 1));
    if (!claims) {
        return std::nullopt;
    }
    if (json::field_number(*claims, "exp", 0) <= now_seconds()) {
        return std::nullopt;
    }
    const auto subject = json::field(*claims, "sub");
    if (!subject) {
        return std::nullopt;
    }
    return store.member(std::strtoll(subject->c_str(), nullptr, 10));
}

}  // namespace toolshed::auth
