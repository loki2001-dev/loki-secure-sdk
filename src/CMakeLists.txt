FILE(GLOB_RECURSE LOKI_CORE_SOURCES
        "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/core/*.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/crypto/*.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/asym/*.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/x509/*.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/tls/*.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/io/*.cpp"
)

FILE(GLOB_RECURSE LOKI_CORE_HEADERS
        "${CMAKE_CURRENT_SOURCE_DIR}/*.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/core/*.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/crypto/*.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/asym/*.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/x509/*.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/tls/*.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/io/*.h"
)

IF(BUILD_SHARED_LIBS)
    ADD_LIBRARY(loki-secure-sdk SHARED ${LOKI_CORE_SOURCES})
ELSE()
    ADD_LIBRARY(loki-secure-sdk STATIC ${LOKI_CORE_SOURCES})
ENDIF()

TARGET_LINK_LIBRARIES(loki-secure-sdk
        PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)

SET_TARGET_PROPERTIES(loki-secure-sdk PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        PUBLIC_HEADER "${LOKI_CORE_HEADERS}"
)

TARGET_INCLUDE_DIRECTORIES(loki-secure-sdk
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)