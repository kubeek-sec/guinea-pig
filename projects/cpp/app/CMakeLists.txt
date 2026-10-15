cmake_minimum_required(VERSION 3.22)
project(toolshed VERSION 1.4.2 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(MHD REQUIRED libmicrohttpd)
pkg_check_modules(SQLITE REQUIRED sqlite3)
find_package(OpenSSL REQUIRED)

add_executable(toolshed
  src/main.cpp
  src/json.cpp
  src/store.cpp
  src/auth.cpp
  src/server.cpp
)

target_include_directories(toolshed PRIVATE ${MHD_INCLUDE_DIRS} ${SQLITE_INCLUDE_DIRS})
target_link_libraries(toolshed PRIVATE ${MHD_LIBRARIES} ${SQLITE_LIBRARIES} OpenSSL::Crypto crypt)
target_compile_options(toolshed PRIVATE -Wall -Wextra -Wpedantic)
