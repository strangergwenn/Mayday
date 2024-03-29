cmake_minimum_required (VERSION 3.5)
project (Mayday)

# Dependencies
set(ZLIB_SOURCE_PATH "external/zlib-1.2.11")
add_subdirectory(${ZLIB_SOURCE_PATH})
set(OPENSSL_USE_STATIC_LIBS TRUE)
set(OPENSSL_MSVC_STATIC_RT TRUE)
find_package(OpenSSL REQUIRED)

# Setup a target
macro(setup_executable TARGET FILES)

	# Create executable
	add_executable(${TARGET} ${FILES})
	set_property(TARGET ${TARGET} PROPERTY CXX_STANDARD 17)
	set_property(TARGET ${TARGET} PROPERTY CXX_STANDARD_REQUIRED ON)
	
	# C++11 trick for older CMake
	if (NOT WIN32)
		set(CMAKE_CXX_FLAGS "-std=c++17")
	endif()

	# Add includes
	target_include_directories(${TARGET} PUBLIC sources)
	target_include_directories(${TARGET} PUBLIC ${OPENSSL_INCLUDE_DIR})
	target_include_directories(${TARGET} PUBLIC ${CMAKE_SOURCE_DIR}/${ZLIB_SOURCE_PATH})
	target_include_directories(${TARGET} PUBLIC ${CMAKE_BINARY_DIR}/${ZLIB_SOURCE_PATH})
	target_compile_definitions(${TARGET} PUBLIC USE_SSL=1 _CRT_SECURE_NO_WARNINGS=1)
	
	# Link with sockets, threads, OpenSSL...
	if(WIN32)
  		target_link_libraries(${TARGET} wsock32 ws2_32 crypt32.lib)
	else()
  		target_link_libraries(${TARGET} pthread)
	endif()
	add_dependencies(${TARGET} zlibstatic)
  	target_link_libraries(${TARGET} ${OPENSSL_LIBRARIES} zlibstatic)
	
	# Link statically
	if(WIN32)
		set(CMAKE_FIND_LIBRARY_SUFFIXES ".lib")
		target_compile_options(${TARGET} PUBLIC /MT)
		target_link_options(${TARGET} PUBLIC /INCREMENTAL:NO /NODEFAULTLIB:MSVCRT /NODEFAULTLIB:MSVCRTD)
	else()
		target_link_libraries(${TARGET} -static)
	endif()
	
	# Make it a console application for easier debugging
	if(WIN32)
		set_target_properties(${TARGET} PROPERTIES LINK_FLAGS_DEBUG "/SUBSYSTEM:CONSOLE")
		set_target_properties(${TARGET} PROPERTIES COMPILE_DEFINITIONS_DEBUG "_CONSOLE")
		set_target_properties(${TARGET} PROPERTIES LINK_FLAGS_RELWITHDEBINFO "/SUBSYSTEM:CONSOLE")
		set_target_properties(${TARGET} PROPERTIES COMPILE_DEFINITIONS_RELWITHDEBINFO "_CONSOLE")
		set_target_properties(${TARGET} PROPERTIES LINK_FLAGS_RELEASE "/SUBSYSTEM:CONSOLE")
		set_target_properties(${TARGET} PROPERTIES LINK_FLAGS_MINSIZEREL "/SUBSYSTEM:CONSOLE")
	endif(WIN32)

endmacro()

# Project files
set (PROJECT_FILES
	sources/tcpsocket.h
	sources/tcpsocket.cpp
	sources/main.cpp
	sources/certs.h
	sources/config.h
)
source_group("Sources" FILES ${PROJECT_FILES})

# Executable
set (SERVER_PROJECT_FILES
	${SERVER_FILES}
	${NETWORK_FILES}
	${DATA_FILES}
	${JSON_FILES}
)
setup_executable(Mayday "${PROJECT_FILES}")
set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT Mayday)
