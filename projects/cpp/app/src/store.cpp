#include "store.hpp"

#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <stdexcept>

#include <crypt.h>
#include <sqlite3.h>

#include "json.hpp"

namespace toolshed {
namespace {

constexpr const char *kDdl = R"SQL(
CREATE TABLE IF NOT EXISTS members (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    email     TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    password  TEXT NOT NULL,
    role      TEXT NOT NULL DEFAULT 'member'
);
CREATE TABLE IF NOT EXISTS tools (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    category    TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    daily_rate  REAL NOT NULL DEFAULT 0,
    available   INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS rentals (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER NOT NULL REFERENCES members(id),
    tool_id   INTEGER NOT NULL REFERENCES tools(id),
    taken_on  TEXT NOT NULL,
    due_on    TEXT NOT NULL,
    notes     TEXT NOT NULL DEFAULT '',
    returned  INTEGER NOT NULL DEFAULT 0
);
)SQL";

struct SeedTool {
    const char *name;
    const char *category;
    const char *description;
    double      rate;
};

constexpr std::array<SeedTool, 5> kSeedTools{{
    {"Circular saw", "cutting", "190 mm blade, 1400 W", 12.5},
    {"Impact driver", "drilling", "18 V, two batteries", 8.0},
    {"Mitre saw", "cutting", "Sliding, 255 mm", 18.0},
    {"Heat gun", "finishing", "2000 W, variable", 5.5},
    {"Mortar mixer", "masonry", "1600 W, 140 mm paddle", 15.0},
}};

struct SeedMember {
    const char *email;
    const char *name;
    const char *password;
    const char *role;
};

constexpr std::array<SeedMember, 3> kSeedMembers{{
    {"ada@toolshed.example", "Ada Mallory", "workshop-keeper", "staff"},
    {"jun@toolshed.example", "Jun Watanabe", "sawdust-season", "member"},
    {"pierre@toolshed.example", "Pierre Lefranc", "bench-grinder", "member"},
}};

std::string column_text(sqlite3_stmt *statement, int index)
{
    const unsigned char *text = sqlite3_column_text(statement, index);
    return text ? reinterpret_cast<const char *>(text) : std::string{};
}

Tool read_tool(sqlite3_stmt *statement)
{
    return Tool{
        sqlite3_column_int64(statement, 0),
        column_text(statement, 1),
        column_text(statement, 2),
        column_text(statement, 3),
        sqlite3_column_double(statement, 4),
        sqlite3_column_int(statement, 5) != 0,
    };
}

Member read_member(sqlite3_stmt *statement)
{
    return Member{
        sqlite3_column_int64(statement, 0),
        column_text(statement, 1),
        column_text(statement, 2),
        column_text(statement, 3),
        column_text(statement, 4),
    };
}

/// Frees a prepared statement whatever path leaves the scope.
class Statement {
public:
    Statement(sqlite3 *db, const std::string &sql)
    {
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &handle_, nullptr) != SQLITE_OK) {
            throw std::runtime_error(sqlite3_errmsg(db));
        }
    }
    ~Statement() { sqlite3_finalize(handle_); }
    Statement(const Statement &) = delete;
    Statement &operator=(const Statement &) = delete;

    [[nodiscard]] sqlite3_stmt *get() const { return handle_; }

private:
    sqlite3_stmt *handle_{nullptr};
};

}  // namespace

std::string Tool::to_json() const
{
    std::array<char, 32> rate{};
    std::snprintf(rate.data(), rate.size(), "%.2f", daily_rate);
    return "{\"id\":" + std::to_string(id) +
           ",\"name\":" + json::quote(name) +
           ",\"category\":" + json::quote(category) +
           ",\"description\":" + json::quote(description) +
           ",\"daily_rate\":" + rate.data() +
           ",\"available\":" + (available ? "true" : "false") + "}";
}

std::string Member::to_json() const
{
    return "{\"id\":" + std::to_string(id) +
           ",\"email\":" + json::quote(email) +
           ",\"full_name\":" + json::quote(full_name) +
           ",\"role\":" + json::quote(role) + "}";
}

std::string Rental::to_json() const
{
    std::string out = "{\"id\":" + std::to_string(id) +
                      ",\"member_id\":" + std::to_string(member_id) +
                      ",\"tool_id\":" + std::to_string(tool_id);
    if (!tool_name.empty()) {
        out += ",\"tool_name\":" + json::quote(tool_name);
    }
    out += ",\"taken_on\":" + json::quote(taken_on) +
           ",\"due_on\":" + json::quote(due_on) +
           ",\"notes\":" + json::quote(notes) +
           ",\"returned\":" + (returned ? "true" : "false") + "}";
    return out;
}

std::string hash_password(const std::string &password)
{
    std::array<char, CRYPT_GENSALT_OUTPUT_SIZE> salt{};
    if (crypt_gensalt_rn("$2b$", 12, nullptr, 0, salt.data(), salt.size()) == nullptr) {
        throw std::runtime_error("cannot generate a salt");
    }
    crypt_data data{};
    const char *hash = crypt_r(password.c_str(), salt.data(), &data);
    if (hash == nullptr) {
        throw std::runtime_error("cannot hash the password");
    }
    return hash;
}

bool check_password(const std::string &password, const std::string &expected)
{
    crypt_data data{};
    const char *hash = crypt_r(password.c_str(), expected.c_str(), &data);
    if (hash == nullptr || std::strlen(hash) != expected.size()) {
        return false;
    }
    unsigned char diff = 0;
    for (std::size_t i = 0; i < expected.size(); i++) {
        diff |= static_cast<unsigned char>(hash[i] ^ expected[i]);
    }
    return diff == 0;
}

Store::Store(const std::string &file)
{
    std::filesystem::path path{file};
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path());
    }
    if (sqlite3_open(file.c_str(), &db_) != SQLITE_OK) {
        throw std::runtime_error("cannot open the database");
    }
    sqlite3_busy_timeout(db_, 5000);
    char *message = nullptr;
    if (sqlite3_exec(db_, kDdl, nullptr, nullptr, &message) != SQLITE_OK) {
        const std::string detail = message ? message : "unknown";
        sqlite3_free(message);
        throw std::runtime_error("schema: " + detail);
    }
    seed();
}

Store::~Store()
{
    sqlite3_close(db_);
}

void Store::seed() const
{
    {
        Statement count(db_, "SELECT COUNT(*) FROM tools");
        if (sqlite3_step(count.get()) == SQLITE_ROW && sqlite3_column_int64(count.get(), 0) > 0) {
            return;
        }
    }
    for (const auto &tool : kSeedTools) {
        Statement insert(db_,
            "INSERT INTO tools (name, category, description, daily_rate) VALUES (?1, ?2, ?3, ?4)");
        sqlite3_bind_text(insert.get(), 1, tool.name, -1, SQLITE_STATIC);
        sqlite3_bind_text(insert.get(), 2, tool.category, -1, SQLITE_STATIC);
        sqlite3_bind_text(insert.get(), 3, tool.description, -1, SQLITE_STATIC);
        sqlite3_bind_double(insert.get(), 4, tool.rate);
        sqlite3_step(insert.get());
    }
    for (const auto &member : kSeedMembers) {
        const std::string hash = hash_password(member.password);
        Statement insert(db_,
            "INSERT INTO members (email, full_name, password, role) VALUES (?1, ?2, ?3, ?4)");
        sqlite3_bind_text(insert.get(), 1, member.email, -1, SQLITE_STATIC);
        sqlite3_bind_text(insert.get(), 2, member.name, -1, SQLITE_STATIC);
        sqlite3_bind_text(insert.get(), 3, hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert.get(), 4, member.role, -1, SQLITE_STATIC);
        sqlite3_step(insert.get());
    }
}

std::vector<Tool> Store::tools_ordered_by(const std::string &column) const
{
    Statement statement(db_, "SELECT * FROM tools ORDER BY " + column);
    std::vector<Tool> tools;
    while (sqlite3_step(statement.get()) == SQLITE_ROW) {
        tools.push_back(read_tool(statement.get()));
    }
    return tools;
}

std::vector<Tool> Store::top_tools(int limit) const
{
    Statement statement(db_, "SELECT * FROM tools ORDER BY name LIMIT ?1");
    sqlite3_bind_int(statement.get(), 1, limit);
    std::vector<Tool> tools;
    while (sqlite3_step(statement.get()) == SQLITE_ROW) {
        tools.push_back(read_tool(statement.get()));
    }
    return tools;
}

std::vector<Tool> Store::search_tools(const std::string &term) const
{
    Statement statement(db_, "SELECT * FROM tools WHERE name LIKE ?1 OR description LIKE ?1");
    const std::string like = "%" + term + "%";
    sqlite3_bind_text(statement.get(), 1, like.c_str(), -1, SQLITE_TRANSIENT);
    std::vector<Tool> tools;
    while (sqlite3_step(statement.get()) == SQLITE_ROW) {
        tools.push_back(read_tool(statement.get()));
    }
    return tools;
}

std::optional<Tool> Store::tool(long long id) const
{
    Statement statement(db_, "SELECT * FROM tools WHERE id = ?1");
    sqlite3_bind_int64(statement.get(), 1, id);
    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        return std::nullopt;
    }
    return read_tool(statement.get());
}

std::optional<Member> Store::member_by_email(const std::string &email) const
{
    Statement statement(db_, "SELECT * FROM members WHERE email = ?1");
    sqlite3_bind_text(statement.get(), 1, email.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        return std::nullopt;
    }
    return read_member(statement.get());
}

std::optional<Member> Store::member(long long id) const
{
    Statement statement(db_, "SELECT * FROM members WHERE id = ?1");
    sqlite3_bind_int64(statement.get(), 1, id);
    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        return std::nullopt;
    }
    return read_member(statement.get());
}

std::vector<Rental> Store::rentals_of(long long member_id) const
{
    Statement statement(db_,
        "SELECT r.id, r.member_id, r.tool_id, r.taken_on, r.due_on, r.notes, r.returned, t.name "
        "FROM rentals r JOIN tools t ON t.id = r.tool_id "
        "WHERE r.member_id = ?1 ORDER BY r.taken_on DESC");
    sqlite3_bind_int64(statement.get(), 1, member_id);
    std::vector<Rental> rentals;
    while (sqlite3_step(statement.get()) == SQLITE_ROW) {
        sqlite3_stmt *row = statement.get();
        rentals.push_back(Rental{
            sqlite3_column_int64(row, 0), sqlite3_column_int64(row, 1),
            sqlite3_column_int64(row, 2), column_text(row, 7),
            column_text(row, 3), column_text(row, 4), column_text(row, 5),
            sqlite3_column_int(row, 6) != 0,
        });
    }
    return rentals;
}

std::optional<Rental> Store::rental_of(long long rental_id, long long member_id) const
{
    Statement statement(db_, "SELECT * FROM rentals WHERE id = ?1 AND member_id = ?2");
    sqlite3_bind_int64(statement.get(), 1, rental_id);
    sqlite3_bind_int64(statement.get(), 2, member_id);
    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        return std::nullopt;
    }
    sqlite3_stmt *row = statement.get();
    return Rental{
        sqlite3_column_int64(row, 0), sqlite3_column_int64(row, 1), sqlite3_column_int64(row, 2),
        {}, column_text(row, 3), column_text(row, 4), column_text(row, 5),
        sqlite3_column_int(row, 6) != 0,
    };
}

long long Store::create_rental(long long member_id, long long tool_id, const std::string &taken_on,
                               const std::string &due_on, const std::string &notes) const
{
    Statement statement(db_,
        "INSERT INTO rentals (member_id, tool_id, taken_on, due_on, notes) "
        "VALUES (?1, ?2, ?3, ?4, ?5)");
    sqlite3_bind_int64(statement.get(), 1, member_id);
    sqlite3_bind_int64(statement.get(), 2, tool_id);
    sqlite3_bind_text(statement.get(), 3, taken_on.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement.get(), 4, due_on.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement.get(), 5, notes.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement.get()) != SQLITE_DONE) {
        return -1;
    }
    return sqlite3_last_insert_rowid(db_);
}

void Store::set_tool_available(long long tool_id, bool available) const
{
    Statement statement(db_, "UPDATE tools SET available = ?1 WHERE id = ?2");
    sqlite3_bind_int(statement.get(), 1, available ? 1 : 0);
    sqlite3_bind_int64(statement.get(), 2, tool_id);
    sqlite3_step(statement.get());
}

void Store::close_rental(long long rental_id) const
{
    Statement statement(db_, "UPDATE rentals SET returned = 1 WHERE id = ?1");
    sqlite3_bind_int64(statement.get(), 1, rental_id);
    sqlite3_step(statement.get());
}

}  // namespace toolshed
