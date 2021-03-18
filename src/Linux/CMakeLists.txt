cmake_minimum_required(VERSION 3.13.1)
 
# Locate GTest
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS} ${CMAKE_CURRENT_LIST_DIR} ${CMAKE_CURRENT_LIST_DIR}/.. ${CMAKE_CURRENT_LIST_DIR}/../UnitTest)
 
add_definitions(-D__LINUX__)

find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")

# Link runTests with what we want to test and the GTest and pthread library
add_executable(dcap_provider_utests local_cache.cpp curl_easy.cpp  ../dcap_provider.cpp ../dcap_provider.h ../logging.cpp ../UnitTest/main.cpp ../UnitTest/test_local_cache.cpp ../UnitTest/test_quote_prov.cpp )
target_include_directories(dcap_provider_utests PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}  ${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_CURRENT_LIST_DIR}/../UnitTest )

target_link_libraries(dcap_provider_utests curl ${GTEST_LIBRARIES} pthread ${CMAKE_DL_LIBS}
${CMAKE_THREAD_LIBS_INIT} OpenSSL::SSL OpenSSL::Crypto)
