cmake_minimum_required(VERSION 3.20)

project(efficient_log_forwarder VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# The one place the agent version is defined (--version, User-Agent). Not
# ELF_VERSION: wingdi.h defines that as 0.
set(ELF_AGENT_VERSION_DEFINE "ELF_AGENT_VERSION=\"${PROJECT_VERSION}\"")

if(WIN32)
  # Statically link the Visual C++ runtime so the exe has no DLL
  # dependencies. Must be set before FetchContent so yaml-cpp uses the
  # same runtime (mixing /MD and /MT fails to link).
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

include(FetchContent)

# --- yaml-cpp (rule parsing) ---
FetchContent_Declare(
    yaml-cpp
    GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
    GIT_TAG        0.8.0
)
set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
set(YAML_CPP_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(yaml-cpp)
if(WIN32)
  set_target_properties(yaml-cpp PROPERTIES
      MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
  # yaml-cpp 0.8.0 uses uint16_t without including <cstdint>, which GCC 15
  # rejects; force the include for that target.
  target_compile_options(yaml-cpp PRIVATE -include cstdint)
endif()

# --- nlohmann/json (JSON parsing for server responses + payloads) ---
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
)
FetchContent_MakeAvailable(nlohmann_json)

# --- Sources ---------------------------------------------------------------
# Portable core: rule engine, buffer, forwarder, output formats, server
# client, spool, configuration, logging, and the agent runtime that wires
# them together behind the platform interfaces (Platform.h, EventSource.h).
set(ELF_CORE_SOURCES
    src/AgentClient.cpp
    src/AgentRuntime.cpp
    src/Config.cpp
    src/Console.cpp
    src/EventBuffer.cpp
    src/FieldResolver.cpp
    src/Forwarder.cpp
    src/OutputFormat.cpp
    src/Rule.cpp
    src/RuleEngine.cpp
    src/SpoolQueue.cpp
    src/XmlPretty.cpp
    src/YamlRuleLoader.cpp
)

if(WIN32)
  # Windows Event Log collection (wevtapi), WinHTTP transport, the service
  # wrapper and the SCM install helpers.
  set(ELF_PLATFORM_DIR src/platform/win)
  set(ELF_PLATFORM_SOURCES
      ${ELF_PLATFORM_DIR}/BookmarkStore.cpp
      ${ELF_PLATFORM_DIR}/EventCollector.cpp
      ${ELF_PLATFORM_DIR}/EventQueryCollector.cpp
      ${ELF_PLATFORM_DIR}/EventRender.cpp
      ${ELF_PLATFORM_DIR}/EventSourceWin.cpp
      ${ELF_PLATFORM_DIR}/HttpClientWin.cpp
      ${ELF_PLATFORM_DIR}/LogGrowthMonitor.cpp
      ${ELF_PLATFORM_DIR}/PlatformWin.cpp
  )
  set(ELF_MAIN_SOURCE ${ELF_PLATFORM_DIR}/main_win.cpp)
  set(ELF_PLATFORM_LIBS wevtapi winhttp ws2_32 advapi32)
else()
  # Linux: systemd journal collection, libcurl transport, a plain daemon.
  set(ELF_PLATFORM_DIR src/platform/linux)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
  find_package(CURL REQUIRED)
  set(ELF_PLATFORM_SOURCES
      ${ELF_PLATFORM_DIR}/EventSourceLinux.cpp
      ${ELF_PLATFORM_DIR}/HttpClientCurl.cpp
      ${ELF_PLATFORM_DIR}/JournalEvent.cpp
      ${ELF_PLATFORM_DIR}/PlatformLinux.cpp
  )
  set(ELF_MAIN_SOURCE ${ELF_PLATFORM_DIR}/main_linux.cpp)
  set(ELF_PLATFORM_LIBS PkgConfig::SYSTEMD CURL::libcurl pthread)
endif()

# --- Agent executable --------------------------------------------------------
add_executable(efficient_log_forwarder ${ELF_MAIN_SOURCE} ${ELF_CORE_SOURCES} ${ELF_PLATFORM_SOURCES})
target_include_directories(efficient_log_forwarder PRIVATE src ${ELF_PLATFORM_DIR})
target_compile_definitions(efficient_log_forwarder PRIVATE ${ELF_AGENT_VERSION_DEFINE})
target_link_libraries(efficient_log_forwarder PRIVATE
    yaml-cpp
    nlohmann_json::nlohmann_json
    ${ELF_PLATFORM_LIBS}
)

# config.ini, rules/ and lists/ next to the binary so --debug runs from the
# build tree find them.
add_custom_command(TARGET efficient_log_forwarder POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/config.ini"
        "$<TARGET_FILE_DIR:efficient_log_forwarder>/config.ini"
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_SOURCE_DIR}/rules"
        "$<TARGET_FILE_DIR:efficient_log_forwarder>/rules"
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_SOURCE_DIR}/lists"
        "$<TARGET_FILE_DIR:efficient_log_forwarder>/lists"
)

# --- Test harness -----------------------------------------------------------
# A console app with its own CHECK macro: the portable engine, format and
# forwarder tests on both platforms, the live Event Log subscription tests
# on Windows, the journal renderer and audit joiner tests on Linux.
add_executable(test_rule_engine tests/test_rule_engine.cpp ${ELF_CORE_SOURCES} ${ELF_PLATFORM_SOURCES})
target_include_directories(test_rule_engine PRIVATE src ${ELF_PLATFORM_DIR})
target_compile_definitions(test_rule_engine PRIVATE ${ELF_AGENT_VERSION_DEFINE})
target_link_libraries(test_rule_engine PRIVATE
    yaml-cpp
    nlohmann_json::nlohmann_json
    ${ELF_PLATFORM_LIBS}
)
# `ctest -C Release` runs the harness from the directory it writes to.
enable_testing()
add_test(NAME rule_engine_tests COMMAND test_rule_engine
    WORKING_DIRECTORY $<TARGET_FILE_DIR:test_rule_engine>)
