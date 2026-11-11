cmake_minimum_required(VERSION 3.15)
project(libcerts VERSION 4.2 LANGUAGES C CXX)
 
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
 
if(NOT MSVC)
    message(FATAL_ERROR "libcerts requiere arquitectura Win y compilador MSVC.")
endif()
 
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(PLATFORM_DIR "x32")
else()
    set(PLATFORM_DIR "x64")
endif()

set(ARQUITECTURE_DIR ${CMAKE_SYSTEM_PROCESSOR})
if(NOT ARQUITECTURE_DIR)
    set(ARQUITECTURE_DIR ${CMAKE_HOST_SYSTEM_NAME})
endif()

set(DIR_BUILD "${PLATFORM_DIR}-${ARQUITECTURE_DIR}")


set(CORESDK_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../external/core-c-sdk)
set(LIBSTRING_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../external/libstring)
set(LIBIO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../external/libio)
set(LIBCRYPTO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../external/libcrypto)

include(FetchContent)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON CACHE BOOL "No buscar actualizaciones en GitHub si ya existe")

FetchContent_Declare(
  coresdk
  GIT_REPOSITORY https://github.com/christian-gutman/core-c-sdk
  GIT_TAG        v2.6.0.0
  SOURCE_DIR     ${CORESDK_DIR}
)
FetchContent_MakeAvailable(coresdk)

FetchContent_Declare(
  libstring
  GIT_REPOSITORY https://github.com/christian-gutman/libstring.git
  GIT_TAG        v2.6.0.0
  SOURCE_DIR     ${LIBSTRING_DIR}
)
FetchContent_MakeAvailable(libstring)
 
FetchContent_Declare(
  libcrypto
  GIT_REPOSITORY https://github.com/christian-gutman/libcrypto.git
  GIT_TAG        v2.6.0.0
  SOURCE_DIR     ${LIBCRYPTO_DIR}
)
FetchContent_MakeAvailable(libcrypto)

FetchContent_Declare(
  libio
  GIT_REPOSITORY https://github.com/christian-gutman/libio.git
  GIT_TAG        v2.6.0.0
  SOURCE_DIR     ${LIBIO_DIR}
)
FetchContent_MakeAvailable(libio)

set(SRC_libcerts
    "${CORESDK_DIR}/src/core/core.h"   
    "${CORESDK_DIR}/src/core/core.c"  
    #

    "${LIBSTRING_DIR}/src/strings/core/core_encoding.h"    
    "${LIBSTRING_DIR}/src/strings/core/core_encoding.c"    
    #

    "${LIBSTRING_DIR}/src/strings/core/core_string.h"    
    "${LIBSTRING_DIR}/src/strings/core/core_string.c" 
    #

    "${LIBIO_DIR}/src/io/core/core_io.h"    
    "${LIBIO_DIR}/src/io/core/core_io.c" 
    #
    "${LIBCRYPTO_DIR}/src/crypto/core/core_crypto.h"    
    "${LIBCRYPTO_DIR}/src/crypto/core/core_crypto.c" 
    #
    "${CMAKE_CURRENT_SOURCE_DIR}/core/core_certs.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/core/core_certs.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/core/certs.rc"
)
 
add_library(libcerts SHARED ${SRC_libcerts})

target_include_directories(libcerts PRIVATE
    "${CORESDK_DIR}/src/core"                         
    "${LIBSTRING_DIR}/src/strings/core"  
    "${LIBIO_DIR}/src/io/core"  
    "${LIBCRYPTO_DIR}/src/crypto/core"  
) 

set_target_properties(libcerts PROPERTIES LINK_FLAGS "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/core/certs.def")
 
set_target_properties(libcerts PROPERTIES
    PREFIX ""
    OUTPUT_NAME "libcerts"
    SUFFIX ".dll"
    WINDOWS_EXPORT_ALL_SYMBOLS FALSE 
) 

target_compile_definitions(libcerts PRIVATE
    WIN32 _WINDOWS _USRDLL UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS TARGET_OS_WIN32 WIN32_LEAN_AND_MEAN
) 
 
set(DIR_BIN "${CMAKE_CURRENT_SOURCE_DIR}/../../bin/${DIR_BUILD}")

set_target_properties(libcerts PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${DIR_BIN}/$<CONFIG>"
    LIBRARY_OUTPUT_DIRECTORY "${DIR_BIN}/$<CONFIG>"
    ARCHIVE_OUTPUT_DIRECTORY "${DIR_BIN}/$<CONFIG>"
)
 
add_custom_command(TARGET libcerts POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_CURRENT_SOURCE_DIR}/examples"
        "$<TARGET_FILE_DIR:libcerts>/"
)
