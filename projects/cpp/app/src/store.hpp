// SQLite access layer and the initial dataset of the workshop.
#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace toolshed {

struct Tool {
    long long   id{};
    std::string name;
    std::string category;
    std::string description;
    double      daily_rate{};
    bool        available{};

    [[nodiscard]] std::string to_json() const;
};

struct Member {
    long long   id{};
    std::string email;
    std::string full_name;
    std::string password;
    std::string role;

    [[nodiscard]] std::string to_json() const;
};

struct Rental {
    long long   id{};
    long long   member_id{};
    long long   tool_id{};
    std::string tool_name;
    std::string taken_on;
    std::string due_on;
    std::string notes;
    bool        returned{};

    [[nodiscard]] std::string to_json() const;
};

std::string hash_password(const std::string &password);
bool        check_password(const std::string &password, const std::string &expected);

class Store {
public:
    explicit Store(const std::string &file);
    ~Store();
    Store(const Store &) = delete;
    Store &operator=(const Store &) = delete;

    [[nodiscard]] std::vector<Tool> tools_ordered_by(const std::string &column) const;
    [[nodiscard]] std::vector<Tool> top_tools(int limit) const;
    [[nodiscard]] std::vector<Tool> search_tools(const std::string &term) const;
    [[nodiscard]] std::optional<Tool> tool(long long id) const;

    [[nodiscard]] std::optional<Member> member_by_email(const std::string &email) const;
    [[nodiscard]] std::optional<Member> member(long long id) const;

    [[nodiscard]] std::vector<Rental> rentals_of(long long member_id) const;
    [[nodiscard]] std::optional<Rental> rental_of(long long rental_id, long long member_id) const;

    long long create_rental(long long member_id, long long tool_id, const std::string &taken_on,
                            const std::string &due_on, const std::string &notes) const;
    void set_tool_available(long long tool_id, bool available) const;
    void close_rental(long long rental_id) const;

private:
    void seed() const;

    sqlite3 *db_{nullptr};
};

}  // namespace toolshed
