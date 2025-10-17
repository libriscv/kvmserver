cmake_minimum_required(VERSION 3.16)
project(kvmserver CXX)

option(STATIC_BUILD "Build static executable" OFF)

add_subdirectory(ext/tinykvm tinykvm EXCLUDE_FROM_ALL)
add_subdirectory(ext/CLI11)
add_subdirectory(src/api)

add_executable(kvmserver
	src/main.cpp
	src/config.cpp
	src/file.cpp
	src/warmup.cpp
	src/vm.cpp
	src/vm_state.cpp
)
target_compile_features(kvmserver PUBLIC cxx_std_20)
target_link_libraries(kvmserver
	tinykvm
	CLI11::CLI11
	_binary_libkvmserverguest_so
)

if (SANITIZE)
	target_compile_options(kvmserver PRIVATE -fsanitize=address,undefined)
	target_link_options(kvmserver PRIVATE
		-fsanitize=address,undefined
		-fno-omit-frame-pointer
	)
endif()

if (STATIC_BUILD)
	set_target_properties(kvmserver PROPERTIES
		BUILD_RPATH_USE_ORIGIN ON
		CXX_VISIBILITY_PRESET hidden
		LINK_SEARCH_START_STATIC ON
		LINK_SEARCH_END_STATIC ON
	)
	if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
		target_link_options(kvmserver PRIVATE -static-libgcc -static-libstdc++)
	elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
		target_link_options(kvmserver PRIVATE -static-libgcc -static-libstdc++)
	endif()
	if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
		target_link_options(kvmserver PRIVATE -static -pthread -ldl)
	elseif (CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
		target_link_options(kvmserver PRIVATE -static -pthread)
	endif()
endif()
