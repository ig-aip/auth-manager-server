cmake_minimum_required(VERSION 3.16)

project(auth-manager-server LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost REQUIRED)
find_package(GTest REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED CONFIG)
find_package(libpqxx REQUIRED)
find_package(jwt-cpp REQUIRED CONFIG)

add_library(auth-manager-server-lib
  connection_pool.h connection_pool.cpp
  database.h database.cpp
  server_auth.h server_auth.cpp
  net_auth.h
  session_auth.h session_auth.cpp
  settings_auth.h
)

target_link_libraries(auth-manager-server-lib PUBLIC
  Boost::boost
  OpenSSL::SSL
  nlohmann_json::nlohmann_json
  libpqxx::pqxx
  jwt-cpp::jwt-cpp
)
add_executable(auth-manager-server
  main_auth.cpp
)
target_link_libraries(auth-manager-server auth-manager-server-lib)

include(GNUInstallDirs)
install(TARGETS auth-manager-server
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
