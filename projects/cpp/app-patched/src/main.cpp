// Toolshed — the lending service of a neighbourhood workshop.
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <string>
#include <unistd.h>

#include "server.hpp"
#include "store.hpp"

namespace {

std::string env_or(const char *key, const std::string &fallback)
{
    const char *value = std::getenv(key);
    return (value != nullptr && *value != '\0') ? std::string{value} : fallback;
}

}  // namespace

int main()
{
    std::signal(SIGPIPE, SIG_IGN);

    const std::string db_file = env_or("TOOLSHED_DB", "var/toolshed.db");
    const std::string uploads = env_or("TOOLSHED_UPLOADS", "var/uploads");

    try {
        toolshed::Store store{db_file};
        toolshed::Server server{store, uploads};

        const auto port = static_cast<unsigned short>(
            std::strtol(env_or("PORT", "8000").c_str(), nullptr, 10));
        if (!server.listen(port)) {
            std::cerr << "cannot listen on port " << port << '\n';
            return 1;
        }
        std::cout << "toolshed " << toolshed::kVersion << " listening on :" << port << std::endl;
        for (;;) {
            pause();
        }
    } catch (const std::exception &error) {
        std::cerr << "cannot start: " << error.what() << '\n';
        return 1;
    }
}
