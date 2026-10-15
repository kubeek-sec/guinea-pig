// The HTTP surface of the workshop.
#pragma once

#include <string>

#include "store.hpp"

struct MHD_Daemon;

namespace toolshed {

inline constexpr const char *kVersion = "1.4.2";

class Server {
public:
    Server(Store &store, std::string upload_dir);
    ~Server();
    Server(const Server &) = delete;
    Server &operator=(const Server &) = delete;

    bool listen(unsigned short port);

    [[nodiscard]] Store &store() const { return store_; }
    [[nodiscard]] const std::string &upload_dir() const { return upload_dir_; }

private:
    Store       &store_;
    std::string  upload_dir_;
    MHD_Daemon  *daemon_{nullptr};
};

}  // namespace toolshed
