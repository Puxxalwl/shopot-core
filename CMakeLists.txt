cmake_minimum_required(VERSION 3.24)
project(shopot-core VERSION 0.1.0 LANGUAGES CXX)

option(SHOPOT_WITH_RTC "Build WebRTC transport (libdatachannel)" ON)
# Release builds: link every third-party library statically so the binary runs
# on machines without dev packages. glibc stays dynamic (fully-static glibc
# breaks name resolution). On macOS only BUILD_SHARED_LIBS applies — ld64 has
# no selective -Bstatic, so system libs stay dynamic there.
option(SHOPOT_STATIC_DEPS "Link third-party dependencies statically (for releases)" OFF)
if(SHOPOT_STATIC_DEPS)
  set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
endif()
option(SHOPOT_BUILD_CLI "Build demo CLI application" ON)
option(SHOPOT_BUILD_TESTS "Build tests" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
pkg_check_modules(SQLITE3 REQUIRED IMPORTED_TARGET sqlite3)

# Static linking for releases: point the imported targets at the static
# archives shipped by the -dev packages. Targeted overrides avoid the global
# -Wl,-Bstatic approach, which also captures libgcc_s (no static archive
# exists for it) and breaks the link.
if(SHOPOT_STATIC_DEPS AND UNIX AND NOT APPLE)
  # some distros (e.g. Fedora) do not ship static archives: fall back to
  # dynamic linking there — the release CI (Ubuntu) gets the static binary
  find_library(A_LIBSODIUM NAMES libsodium.a)
  find_library(A_SQLITE3 NAMES libsqlite3.a)
  if(A_LIBSODIUM)
    set_target_properties(PkgConfig::SODIUM PROPERTIES IMPORTED_LOCATION "${A_LIBSODIUM}")
  endif()
  if(A_SQLITE3)
    set_target_properties(PkgConfig::SQLITE3 PROPERTIES IMPORTED_LOCATION "${A_SQLITE3}")
  endif()
endif()

include(FetchContent)
FetchContent_Declare(nlohmann_json
  URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
  URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d)
FetchContent_MakeAvailable(nlohmann_json)

add_library(shopot-core STATIC
  src/crypto.cpp
  src/db.cpp
  src/session.cpp
  src/engine.cpp)
target_include_directories(shopot-core
  PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(shopot-core
  PUBLIC  PkgConfig::SODIUM PkgConfig::SQLITE3
  PRIVATE nlohmann_json::nlohmann_json)
target_compile_options(shopot-core PRIVATE -Wall -Wextra -Wno-unused-parameter)

if(SHOPOT_WITH_RTC)
  set(NO_EXAMPLES ON CACHE BOOL "" FORCE)
  set(NO_TESTS ON CACHE BOOL "" FORCE)
  set(NO_WEBSOCKET OFF CACHE BOOL "" FORCE)  # WebSocket: the rendezvous relay client
  set(NO_MEDIA ON CACHE BOOL "" FORCE)
  FetchContent_Declare(libdatachannel
    GIT_REPOSITORY https://github.com/paullouisageneau/libdatachannel.git
    GIT_TAG v0.23.2
    GIT_SHALLOW TRUE)
  FetchContent_MakeAvailable(libdatachannel)
  target_sources(shopot-core PRIVATE src/transport/rtc.cpp src/transport/mqtt.cpp)
  target_link_libraries(shopot-core PRIVATE datachannel)
  target_compile_definitions(shopot-core PRIVATE SHOPOT_WITH_RTC=1 RTC_ENABLE_WEBSOCKET=1)
  if(SHOPOT_STATIC_DEPS AND UNIX AND NOT APPLE)
    find_library(A_SSL NAMES libssl.a)
    find_library(A_CRYPTO NAMES libcrypto.a)
    if(A_SSL)
      set_target_properties(OpenSSL::SSL PROPERTIES IMPORTED_LOCATION "${A_SSL}")
    endif()
    if(A_CRYPTO)
      set_target_properties(OpenSSL::Crypto PROPERTIES IMPORTED_LOCATION "${A_CRYPTO}")
    endif()
    # a static libssl.a no longer carries its zlib dependency (a .so would
    # have it as DT_NEEDED), so append libz after the OpenSSL archives
    find_library(A_Z NAMES libz.a libz.so)
    if(A_Z)
      set_property(TARGET datachannel APPEND PROPERTY INTERFACE_LINK_LIBRARIES "${A_Z}")
    endif()
  endif()
endif()

if(SHOPOT_BUILD_CLI AND SHOPOT_WITH_RTC)
  FetchContent_Declare(ftxui
    GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI.git
    GIT_TAG v5.0.0
    GIT_SHALLOW TRUE)
  FetchContent_MakeAvailable(ftxui)  # honors BUILD_SHARED_LIBS=OFF above
  add_executable(shopot-cli cli/main.cpp cli/plain.cpp cli/tui.cpp)
  target_link_libraries(shopot-cli PRIVATE shopot-core
    ftxui::component ftxui::dom ftxui::screen)
  target_compile_options(shopot-cli PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

if(SHOPOT_BUILD_TESTS)
  enable_testing()
  add_executable(shopot-tests tests/test_main.cpp)
  target_include_directories(shopot-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(shopot-tests PRIVATE shopot-core nlohmann_json::nlohmann_json)
  if(SHOPOT_WITH_RTC)  # live-mqtt test includes rtc headers via mqtt.hpp
    target_compile_definitions(shopot-tests PRIVATE SHOPOT_WITH_RTC=1 RTC_ENABLE_WEBSOCKET=1)
    target_include_directories(shopot-tests PRIVATE ${CMAKE_BINARY_DIR}/_deps/libdatachannel-src/include)
  endif()
  add_test(NAME shopot-tests COMMAND shopot-tests)
endif()
