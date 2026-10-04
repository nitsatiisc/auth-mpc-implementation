cmake_minimum_required(VERSION 3.22)
project(auth_mpc)

set(CMAKE_CXX_STANDARD 14)


set(LIBFF_PREFIX "${CMAKE_SOURCE_DIR}/../deps/libff-install" CACHE PATH "libff install prefix")

include_directories(. ${LIBFF_PREFIX}/include /usr/include/nlohmann)
link_directories(${LIBFF_PREFIX}/lib)

add_executable(setup setup.cpp)
target_link_libraries(setup ff gmp gmpxx crypto)

add_executable(pokprover pokprover.cpp)
target_link_libraries(pokprover ff gmp gmpxx crypto zmq)

add_executable(nipk nipk.cpp)
target_link_libraries(nipk ff gmp gmpxx crypto)

add_executable(dpok-dlog dpok-dlog.cpp)
target_link_libraries(dpok-dlog ff gmp gmpxx crypto pthread zmq)

add_executable(hub_server hub_server.cpp)
target_link_libraries(hub_server zmq)

add_executable(dpok-bbs dpok-bbs.cpp)
target_link_libraries(dpok-bbs ff gmp gmpxx crypto pthread zmq)
