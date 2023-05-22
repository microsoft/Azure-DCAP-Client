cmake_minimum_required(VERSION 3.13.1)
 
# Locate GTest
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})
 
option(__SERVICE_VM__ "Compile Service VM Tests." OFF)
if(__SERVICE_VM__)
	add_definitions(-D__LINUX__ -D__SERVICE_VM__)
else()
	add_definitions(-D__LINUX__)
endif(__SERVICE_VM__)

find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")

# Link runTests with what we want to test and the GTest and pthread library
add_executable(dcap_provider_utests ../UnitTest/test_local_cache.cpp ../UnitTest/test_quote_prov.cpp ../UnitTest/main.cpp ../Linux/local_cache.cpp)
target_link_libraries(dcap_provider_utests ${GTEST_LIBRARIES} pthread ${CMAKE_DL_LIBS} 
${CMAKE_THREAD_LIBS_INIT} OpenSSL::SSL OpenSSL::Crypto )
