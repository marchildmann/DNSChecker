cmake_minimum_required(VERSION 3.14)
project(dns_checker VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# CUI from a local checkout when there is one, otherwise from its public
# repository at a commit this app is known to build with.
set(CUI_DIR "$ENV{HOME}/Code/CUI" CACHE PATH "Checkout of the CUI library")
if(EXISTS "${CUI_DIR}/CMakeLists.txt")
    add_subdirectory(${CUI_DIR} ${CMAKE_BINARY_DIR}/cui EXCLUDE_FROM_ALL)
else()
    include(FetchContent)
    FetchContent_Declare(cui
        GIT_REPOSITORY https://github.com/yappologistic/CUI.git
        GIT_TAG a5c9ef5efc39b3fc783758362f6b8f9f130f5883)
    FetchContent_MakeAvailable(cui)
endif()

find_package(Threads REQUIRED)
find_package(LibXml2 REQUIRED)
find_package(ZLIB REQUIRED)

# Everything that does not draw: DNS queries, the worker thread, DMARC
# records, DMARC aggregate reports and the texts in each language.
add_library(dns_checker_core STATIC
    src/dns_lookup.c
    src/dns_wire.c
    src/dmarc.c
    src/dmarc_report.c
    src/domain_scan.c
    src/lookup_task.c
    src/portable.c
    src/report_file.c
    src/ui_text.c
)
target_include_directories(dns_checker_core PUBLIC src)
target_link_libraries(dns_checker_core PUBLIC Threads::Threads LibXml2::LibXml2 ZLIB::ZLIB)
target_compile_options(dns_checker_core PRIVATE -Wall -Wextra)
if(WIN32)
    target_sources(dns_checker_core PRIVATE src/dns_query_windows.c)
    target_compile_definitions(dns_checker_core PUBLIC _WIN32_WINNT=0x0A00)
    target_link_libraries(dns_checker_core PUBLIC dnsapi ws2_32)
else()
    target_sources(dns_checker_core PRIVATE src/dns_query_resolv.c)
    target_link_libraries(dns_checker_core PUBLIC resolv)
endif()
if(APPLE)
    # ui_text.c reads the preferred language from System Settings
    target_link_libraries(dns_checker_core PUBLIC "-framework CoreFoundation")
endif()

add_executable(dns_checker
    src/main.c
    src/page_records.c
    src/page_dmarc.c
    src/page_reports.c
)
target_link_libraries(dns_checker PRIVATE dns_checker_core cui::cui)
target_compile_options(dns_checker PRIVATE -Wall -Wextra)
cui_app_target(dns_checker)

# macOS: a "DNS Checker.app" bundle; Windows: DNSChecker.exe. The release
# workflow passes the version of its tag in DNS_CHECKER_VERSION.
set(DNS_CHECKER_VERSION "${PROJECT_VERSION}" CACHE STRING "Version shown in the app bundle")
if(APPLE)
    set_target_properties(dns_checker PROPERTIES
        MACOSX_BUNDLE ON
        OUTPUT_NAME "DNS Checker"
        MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/packaging/macos/Info.plist.in"
        MACOSX_BUNDLE_GUI_IDENTIFIER "com.marchildmann.dnschecker"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${DNS_CHECKER_VERSION}"
        MACOSX_BUNDLE_BUNDLE_VERSION "${DNS_CHECKER_VERSION}")
elseif(WIN32)
    set_target_properties(dns_checker PROPERTIES OUTPUT_NAME "DNSChecker")
endif()

enable_testing()
add_executable(test_core tests/test_core.c)
target_link_libraries(test_core PRIVATE dns_checker_core)
target_compile_definitions(test_core PRIVATE FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures")
add_test(NAME core COMMAND test_core)

# Needs the network, so it is built but not run by ctest; CI runs it.
add_executable(test_network tests/test_network.c)
target_link_libraries(test_network PRIVATE dns_checker_core)
