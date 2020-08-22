cmake_minimum_required(VERSION 3.13.1)
 
# Locate GTest
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})
 
add_definitions(-D__LINUX__)

file(GLOB Dir1_Sources RELATIVE "../UnitTest" "*.cpp")
file(GLOB Dir2_Sources RELATIVE "../Linux" "*.cpp")

find_package(OpenSSL REQUIRED)

# Link runTests with what we want to test and the GTest and pthread library
add_executable(dcap_provider_utests ../UnitTest/test_local_cache.cpp ../UnitTest/test_quote_prov.cpp ../UnitTest/main.cpp ../Linux/local_cache.cpp)
target_link_libraries(dcap_provider_utests ${GTEST_LIBRARIES} pthread ${CMAKE_DL_LIBS} 
${CMAKE_THREAD_LIBS_INIT} OpenSSL::SSL OpenSSL::Crypto )
