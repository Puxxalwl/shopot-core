cmake_minimum_required(VERSION 3.24)
project(shopot-core VERSION 0.1.0 LANGUAGES CXX)

option(SHOPOT_WITH_RTC "Build WebRTC transport (libdatachannel)" ON)
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
endif()

if(SHOPOT_BUILD_CLI AND SHOPOT_WITH_RTC)
  add_executable(shopot-cli cli/main.cpp)
  target_link_libraries(shopot-cli PRIVATE shopot-core)
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
