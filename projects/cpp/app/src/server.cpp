#include "server.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <sstream>
#include <string_view>

#include <microhttpd.h>
#include <openssl/rand.h>

#include "auth.hpp"
#include "json.hpp"

namespace toolshed {
namespace {

constexpr int         kDefaultDays = 7;
constexpr std::size_t kMaxBodyBytes = 1024 * 1024;
constexpr std::size_t kMaxPhotoBytes = 8 * 1024 * 1024;

const std::array<std::string_view, 3> kSortable{"name", "category", "daily_rate"};

const std::map<std::string, std::string> kPhotoTypes{
    {"jpg", "image/jpeg"}, {"jpeg", "image/jpeg"},
    {"png", "image/png"},  {"webp", "image/webp"},
};

/// What libmicrohttpd hands back to us on each call of the same request.
struct Request {
    std::string               body;
    MHD_PostProcessor        *post{nullptr};
    std::string               photo;
    std::string               filename;
    bool                      too_large{false};
};

std::string lower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

MHD_Result respond(MHD_Connection *connection, unsigned int status, const std::string &type,
                   const std::string &body, const char *extra_header = nullptr,
                   const char *extra_value = nullptr)
{
    MHD_Response *response = MHD_create_response_from_buffer(
        body.size(), const_cast<char *>(body.data()), MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, type.c_str());
    if (extra_header != nullptr) {
        MHD_add_response_header(response, extra_header, extra_value);
    }
    const MHD_Result rc = MHD_queue_response(connection, status, response);
    MHD_destroy_response(response);
    return rc;
}

MHD_Result send_json(MHD_Connection *connection, unsigned int status, const std::string &body)
{
    return respond(connection, status, "application/json", body);
}

MHD_Result send_error(MHD_Connection *connection, unsigned int status, const std::string &message)
{
    return send_json(connection, status, "{\"error\":" + json::quote(message) + "}");
}

std::string join_json(const std::vector<std::string> &items)
{
    std::string out = "[";
    for (std::size_t i = 0; i < items.size(); i++) {
        if (i != 0) {
            out += ",";
        }
        out += items[i];
    }
    out += "]";
    return out;
}

std::string iso_date(std::chrono::system_clock::time_point when)
{
    const std::time_t stamp = std::chrono::system_clock::to_time_t(when);
    std::tm parts{};
    gmtime_r(&stamp, &parts);
    std::array<char, 16> text{};
    std::strftime(text.data(), text.size(), "%Y-%m-%d", &parts);
    return text.data();
}

std::string query_value(MHD_Connection *connection, const char *key, const char *fallback)
{
    const char *value = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, key);
    return value != nullptr ? value : fallback;
}

std::optional<Member> signed_in(const Store &store, MHD_Connection *connection)
{
    const char *header = MHD_lookup_connection_value(connection, MHD_HEADER_KIND,
                                                     MHD_HTTP_HEADER_AUTHORIZATION);
    return header != nullptr ? auth::from_header(store, header) : std::nullopt;
}

std::optional<long long> tail_id(std::string_view url, std::string_view prefix)
{
    if (url.substr(0, prefix.size()) != prefix) {
        return std::nullopt;
    }
    const std::string_view tail = url.substr(prefix.size());
    long long value = 0;
    const auto [ptr, ec] = std::from_chars(tail.data(), tail.data() + tail.size(), value);
    if (ec != std::errc{} || ptr != tail.data() + tail.size()) {
        return std::nullopt;
    }
    return value;
}

std::string read_file(const std::filesystem::path &path)
{
    std::ifstream stream(path, std::ios::binary);
    return std::string{std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}

MHD_Result collect_photo(void *cls, MHD_ValueKind, const char *key, const char *filename,
                         const char *, const char *, const char *data, uint64_t, size_t size)
{
    auto *state = static_cast<Request *>(cls);
    if (std::strcmp(key, "photo") != 0) {
        return MHD_YES;
    }
    if (filename != nullptr && state->filename.empty()) {
        state->filename = filename;
    }
    if (state->photo.size() + size > kMaxPhotoBytes) {
        state->too_large = true;
        return MHD_YES;
    }
    state->photo.append(data, size);
    return MHD_YES;
}

// --------------------------------------------------------------------- routes

MHD_Result route_home(const Store &store, MHD_Connection *connection)
{
    std::ostringstream page;
    page << "<!doctype html>\n<html lang=\"en\">\n"
         << "<head><meta charset=\"utf-8\"><title>Toolshed</title>\n"
         << "<style>body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:48rem}\n"
         << "table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #ddd;"
            "padding:.5rem;text-align:left}\n.out{color:#999}</style></head>\n"
         << "<body><h1>Toolshed</h1><p>Tools the workshop lends to its members.</p>\n"
         << "<table><tr><th>Tool</th><th>Category</th><th>Per day</th><th>Status</th></tr>\n";
    for (const Tool &tool : store.top_tools(20)) {
        std::array<char, 32> rate{};
        std::snprintf(rate.data(), rate.size(), "%.2f", tool.daily_rate);
        page << "<tr><td>" << json::escape_html(tool.name)
             << "</td><td>" << json::escape_html(tool.category)
             << "</td><td>" << rate.data() << " &euro;</td><td>"
             << (tool.available ? "on the rack" : "<span class=\"out\">out</span>")
             << "</td></tr>\n";
    }
    page << "</table><p><a href=\"/openapi.yml\">API description</a></p></body></html>\n";
    return respond(connection, MHD_HTTP_OK, "text/html", page.str());
}

MHD_Result route_list_tools(const Store &store, MHD_Connection *connection)
{
    const std::string sort = query_value(connection, "sort", "name");
    if (std::find(kSortable.begin(), kSortable.end(), sort) == kSortable.end()) {
        return send_error(connection, MHD_HTTP_BAD_REQUEST, "cannot sort on '" + sort + "'");
    }
    std::vector<std::string> items;
    for (const Tool &tool : store.tools_ordered_by(sort)) {
        items.push_back(tool.to_json());
    }
    return send_json(connection, MHD_HTTP_OK, "{\"tools\":" + join_json(items) + "}");
}

MHD_Result route_search_tools(const Store &store, MHD_Connection *connection)
{
    const std::string term = query_value(connection, "q", "");
    std::vector<std::string> items;
    for (const Tool &tool : store.search_tools(term)) {
        items.push_back(tool.to_json());
    }
    return send_json(connection, MHD_HTTP_OK,
                     "{\"query\":" + json::quote(term) + ",\"tools\":" + join_json(items) + "}");
}

MHD_Result route_get_tool(const Store &store, MHD_Connection *connection, long long id)
{
    const auto tool = store.tool(id);
    if (!tool) {
        return send_error(connection, MHD_HTTP_NOT_FOUND, "no such tool");
    }
    return send_json(connection, MHD_HTTP_OK, tool->to_json());
}

MHD_Result route_sign_in(const Store &store, MHD_Connection *connection, const std::string &body)
{
    const auto email = json::field(body, "email").value_or("");
    const auto password = json::field(body, "password").value_or("");
    const auto member = auth::authenticate(store, email, password);
    if (!member) {
        return send_error(connection, MHD_HTTP_UNAUTHORIZED, "bad credentials");
    }
    const auto token = auth::issue(*member);
    if (!token) {
        return send_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "cannot issue a token");
    }
    return send_json(connection, MHD_HTTP_OK,
                     "{\"token\":" + json::quote(*token) +
                     ",\"role\":" + json::quote(member->role) + "}");
}

MHD_Result route_whoami(const Store &store, MHD_Connection *connection)
{
    const auto member = signed_in(store, connection);
    if (!member) {
        return send_error(connection, MHD_HTTP_UNAUTHORIZED, "authentication required");
    }
    return send_json(connection, MHD_HTTP_OK, member->to_json());
}

MHD_Result route_get_member(const Store &store, MHD_Connection *connection, long long id)
{
    const auto caller = signed_in(store, connection);
    if (!caller) {
        return send_error(connection, MHD_HTTP_UNAUTHORIZED, "authentication required");
    }
    if (caller->role != "staff") {
        return send_error(connection, MHD_HTTP_FORBIDDEN, "staff only");
    }
    const auto member = store.member(id);
    if (!member) {
        return send_error(connection, MHD_HTTP_NOT_FOUND, "no such member");
    }
    return send_json(connection, MHD_HTTP_OK, member->to_json());
}

MHD_Result route_my_rentals(const Store &store, MHD_Connection *connection)
{
    const auto member = signed_in(store, connection);
    if (!member) {
        return send_error(connection, MHD_HTTP_UNAUTHORIZED, "authentication required");
    }
    std::vector<std::string> items;
    for (const Rental &rental : store.rentals_of(member->id)) {
        items.push_back(rental.to_json());
    }
    return send_json(connection, MHD_HTTP_OK, "{\"rentals\":" + join_json(items) + "}");
}

MHD_Result route_take_out(const Store &store, MHD_Connection *connection, const std::string &body)
{
    const auto member = signed_in(store, connection);
    if (!member) {
        return send_error(connection, MHD_HTTP_UNAUTHORIZED, "authentication required");
    }
    const auto tool = store.tool(json::field_number(body, "tool_id", -1));
    if (!tool) {
        return send_error(connection, MHD_HTTP_NOT_FOUND, "no such tool");
    }
    if (!tool->available) {
        return send_error(connection, MHD_HTTP_CONFLICT, "already out");
    }
    long long days = json::field_number(body, "days", kDefaultDays);
    if (days <= 0) {
        days = kDefaultDays;
    }
    const auto today = std::chrono::system_clock::now();
    const auto due = today + std::chrono::hours(24 * days);
    const std::string taken_on = iso_date(today);
    const std::string due_on = iso_date(due);
    const long long id = store.create_rental(member->id, tool->id, taken_on, due_on,
                                             json::field(body, "notes").value_or(""));
    if (id < 0) {
        return send_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "cannot record the rental");
    }
    store.set_tool_available(tool->id, false);
    return send_json(connection, MHD_HTTP_CREATED,
                     "{\"id\":" + std::to_string(id) + ",\"due_on\":" + json::quote(due_on) + "}");
}

MHD_Result route_bring_back(const Store &store, MHD_Connection *connection, long long rental_id)
{
    const auto member = signed_in(store, connection);
    if (!member) {
        return send_error(connection, MHD_HTTP_UNAUTHORIZED, "authentication required");
    }
    const auto rental = store.rental_of(rental_id, member->id);
    if (!rental) {
        return send_error(connection, MHD_HTTP_NOT_FOUND, "no such rental");
    }
    store.close_rental(rental->id);
    store.set_tool_available(rental->tool_id, true);
    return send_json(connection, MHD_HTTP_OK, "{\"status\":\"returned\"}");
}

MHD_Result route_upload_photo(const Server &server, MHD_Connection *connection, Request &state)
{
    const auto member = signed_in(server.store(), connection);
    if (!member) {
        return send_error(connection, MHD_HTTP_UNAUTHORIZED, "authentication required");
    }
    if (state.too_large) {
        return send_error(connection, MHD_HTTP_BAD_REQUEST, "photo too large");
    }
    if (state.photo.empty() || state.filename.empty()) {
        return send_error(connection, MHD_HTTP_BAD_REQUEST, "no photo");
    }
    const std::string ext = lower(std::filesystem::path(state.filename).extension().string());
    const auto type = kPhotoTypes.find(ext.empty() ? ext : ext.substr(1));
    if (type == kPhotoTypes.end()) {
        return send_error(connection, MHD_HTTP_BAD_REQUEST,
                          (ext.empty() ? "file" : ext) + " not accepted");
    }
    std::array<unsigned char, 16> token{};
    if (RAND_bytes(token.data(), static_cast<int>(token.size())) != 1) {
        return send_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "cannot name the photo");
    }
    std::ostringstream name;
    for (unsigned char byte : token) {
        name << std::hex << (byte >> 4) << (byte & 0x0f);
    }
    name << ext;

    const std::filesystem::path path = std::filesystem::path(server.upload_dir()) / name.str();
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        return send_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "cannot store the photo");
    }
    out.write(state.photo.data(), static_cast<std::streamsize>(state.photo.size()));
    return send_json(connection, MHD_HTTP_CREATED,
                     "{\"name\":" + json::quote(name.str()) +
                     ",\"owner\":" + json::quote(member->email) + "}");
}

MHD_Result route_fetch_photo(const Server &server, MHD_Connection *connection,
                             std::string_view raw_name)
{
    const std::string name = std::filesystem::path(raw_name).filename().string();
    const std::string ext = lower(std::filesystem::path(name).extension().string());
    const auto type = kPhotoTypes.find(ext.empty() ? ext : ext.substr(1));
    if (type == kPhotoTypes.end() || name.find("..") != std::string::npos) {
        return send_error(connection, MHD_HTTP_NOT_FOUND, "no such photo");
    }
    const std::filesystem::path path = std::filesystem::path(server.upload_dir()) / name;
    if (!std::filesystem::is_regular_file(path)) {
        return send_error(connection, MHD_HTTP_NOT_FOUND, "no such photo");
    }
    return respond(connection, MHD_HTTP_OK, type->second, read_file(path),
                   "X-Content-Type-Options", "nosniff");
}

MHD_Result dispatch(void *cls, MHD_Connection *connection, const char *url, const char *method,
                    const char *, const char *upload_data, size_t *upload_data_size,
                    void **con_cls)
{
    auto *server = static_cast<Server *>(cls);

    if (*con_cls == nullptr) {
        auto *state = new Request();
        if (std::strcmp(method, MHD_HTTP_METHOD_POST) == 0) {
            state->post = MHD_create_post_processor(connection, 64 * 1024, collect_photo, state);
        }
        *con_cls = state;
        return MHD_YES;
    }

    auto *state = static_cast<Request *>(*con_cls);
    if (*upload_data_size != 0) {
        if (state->post != nullptr) {
            MHD_post_process(state->post, upload_data, *upload_data_size);
        }
        if (state->body.size() + *upload_data_size <= kMaxBodyBytes) {
            state->body.append(upload_data, *upload_data_size);
        }
        *upload_data_size = 0;
        return MHD_YES;
    }

    const std::string_view path{url};
    const bool is_get = std::strcmp(method, MHD_HTTP_METHOD_GET) == 0;
    const bool is_post = std::strcmp(method, MHD_HTTP_METHOD_POST) == 0;
    Store &store = server->store();

    try {
        if (is_get && path == "/healthz") {
            return send_json(connection, MHD_HTTP_OK,
                             std::string{"{\"status\":\"ok\",\"version\":\""} + kVersion + "\"}");
        }
        if (is_get && path == "/openapi.yml") {
            const std::string body = read_file("openapi.yml");
            if (body.empty()) {
                return send_error(connection, MHD_HTTP_NOT_FOUND, "no API description here");
            }
            return respond(connection, MHD_HTTP_OK, "application/yaml", body);
        }
        if (is_get && path == "/") {
            return route_home(store, connection);
        }
        if (is_get && path == "/api/tools") {
            return route_list_tools(store, connection);
        }
        if (is_get && path == "/api/tools/search") {
            return route_search_tools(store, connection);
        }
        if (is_get) {
            if (const auto id = tail_id(path, "/api/tools/")) {
                return route_get_tool(store, connection, *id);
            }
        }
        if (is_post && path == "/api/session") {
            return route_sign_in(store, connection, state->body);
        }
        if (is_get && path == "/api/members/me") {
            return route_whoami(store, connection);
        }
        if (is_get) {
            if (const auto id = tail_id(path, "/api/members/")) {
                return route_get_member(store, connection, *id);
            }
        }
        if (is_get && path == "/api/rentals") {
            return route_my_rentals(store, connection);
        }
        if (is_post && path == "/api/rentals") {
            return route_take_out(store, connection, state->body);
        }
        if (is_post && path.starts_with("/api/rentals/") && path.ends_with("/return")) {
            const std::string_view middle =
                path.substr(13, path.size() - 13 - std::string_view{"/return"}.size());
            long long id = 0;
            const auto [ptr, ec] =
                std::from_chars(middle.data(), middle.data() + middle.size(), id);
            if (ec == std::errc{} && ptr == middle.data() + middle.size()) {
                return route_bring_back(store, connection, id);
            }
        }
        if (is_post && path == "/api/photos") {
            return route_upload_photo(*server, connection, *state);
        }
        if (is_get && path.starts_with("/api/photos/")) {
            return route_fetch_photo(*server, connection, path.substr(12));
        }
    } catch (const std::exception &) {
        return send_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                          "the workshop records are unavailable");
    }
    return send_error(connection, MHD_HTTP_NOT_FOUND, "no such route");
}

void request_completed(void *, MHD_Connection *, void **con_cls, MHD_RequestTerminationCode)
{
    auto *state = static_cast<Request *>(*con_cls);
    if (state == nullptr) {
        return;
    }
    if (state->post != nullptr) {
        MHD_destroy_post_processor(state->post);
    }
    delete state;
    *con_cls = nullptr;
}

}  // namespace

Server::Server(Store &store, std::string upload_dir)
    : store_(store), upload_dir_(std::move(upload_dir))
{
    std::filesystem::create_directories(upload_dir_);
}

Server::~Server()
{
    if (daemon_ != nullptr) {
        MHD_stop_daemon(daemon_);
    }
}

bool Server::listen(unsigned short port)
{
    daemon_ = MHD_start_daemon(
        MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG, port, nullptr, nullptr,
        &dispatch, this,
        MHD_OPTION_NOTIFY_COMPLETED, &request_completed, nullptr,
        MHD_OPTION_CONNECTION_TIMEOUT, static_cast<unsigned int>(30),
        MHD_OPTION_END);
    return daemon_ != nullptr;
}

}  // namespace toolshed
