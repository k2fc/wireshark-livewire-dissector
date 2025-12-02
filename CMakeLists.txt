# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

cmake_minimum_required(VERSION 3.16)

project(AXIA_LW VERSION 0.0.1 DESCRIPTION "Wireshark Livewire Plugins" LANGUAGES C)
# Find the Git executable
find_program(GIT_EXECUTABLE NAMES git)

if (GIT_EXECUTABLE)
    # Execute git rev-parse --short HEAD to get the short hash
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_SHORT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE GIT_COMMAND_RESULT
    )

    if (GIT_COMMAND_RESULT EQUAL 0)
        # Set the project version to the obtained Git short hash
        set(PROJECT_VERSION "${GIT_SHORT_HASH}")
        message(STATUS "Project version set to Git short hash: ${PROJECT_VERSION}")
    else()
        message(WARNING "Failed to get Git short hash. Using default version.")
        set(PROJECT_VERSION "unknown")
    endif()
else()
    message(WARNING "Git executable not found. Using default version.")
    set(PROJECT_VERSION "unknown")
endif()

find_package(Wireshark CONFIG REQUIRED)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX "${Wireshark_INSTALL_PREFIX}"
		CACHE PATH "Installation prefix" FORCE
	)
endif()

if(NOT Wireshark_PLUGINS_ENABLED)
	message(WARNING "Wireshark was compiled without support for plugins")
endif()

# External plugins must define HAVE_SSIZE_T for the plugin toolchain.
include(CheckTypeSize)
check_type_size("ssize_t" SSIZE_T)

set(CMAKE_C_VISIBILITY_PRESET hidden)
if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS  "-Wall -Wextra ${CMAKE_C_FLAGS}")
endif()

add_compile_definitions(
	VERSION=\"${PROJECT_VERSION}\"
	$<$<BOOL:${HAVE_SSIZE_T}>:HAVE_SSIZE_T>
)

add_library(livewire MODULE packet-livewire.c)
set_target_properties(livewire PROPERTIES PREFIX "" DEFINE_SYMBOL "")
target_link_libraries(livewire epan)

# This is the normal installation target to CMAKE_INSTALL_PREFIX. It is relocatable
# using DESTDIR or cmake --install. By default CMAKE_INSTALL_PREFIX should be configured
# correctly for Wireshark's system installation prefix.
install(TARGETS livewire
	LIBRARY DESTINATION "${Wireshark_PLUGIN_LIBDIR}/epan" NAMELINK_SKIP
)

# This custom target installs the plugin to the plugin dir in WiresharkConfig.cmake.
# It does not use CMAKE_INSTALL_PREFIX.
add_custom_target(copy_plugin
	COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:livewire> "${Wireshark_PLUGIN_INSTALL_DIR}/epan"
	COMMENT "Installing plugin to: ${Wireshark_PLUGIN_INSTALL_DIR}/epan"
)

string(TOLOWER "${PROJECT_NAME}-${PROJECT_VERSION}" _pkgname)

add_custom_target(package_prep
	COMMAND ${CMAKE_COMMAND} -E make_directory  ${CMAKE_BINARY_DIR}/${_pkgname}
	COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/README $<TARGET_FILE:livewire> ${CMAKE_BINARY_DIR}/${_pkgname}
)

add_custom_target(package
	COMMAND ${CMAKE_COMMAND} -E tar czf ${CMAKE_BINARY_DIR}/${_pkgname}.tar.gz --format=gnutar -- ${CMAKE_BINARY_DIR}/${_pkgname}
)
add_dependencies(package package_prep)

add_custom_target(package_zip
	COMMAND ${CMAKE_COMMAND} -E tar cf ${CMAKE_BINARY_DIR}/${_pkgname}.zip --format=zip -- ${CMAKE_BINARY_DIR}/${_pkgname}
)
add_dependencies(package_zip package_prep)
