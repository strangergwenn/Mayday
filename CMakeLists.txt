cmake_minimum_required (VERSION 3.0)
project (Mayday)

# Dependencies
find_package(OpenSSL REQUIRED)

# Setup a target
macro(setup_executable TARGET FILES)

	# Create executable
	add_executable(${TARGET} ${FILES})
	set_property(TARGET ${TARGET} PROPERTY CXX_STANDARD 11)
	set_property(TARGET ${TARGET} PROPERTY CXX_STANDARD_REQUIRED ON)
	
	# C++11 trick for older CMake
	if (NOT WIN32)
		set(CMAKE_CXX_FLAGS "-std=c++11")
	endif()

	# Add includes
	target_include_directories(${TARGET} PUBLIC sources)
	target_include_directories(${TARGET} PUBLIC ${OPENSSL_INCLUDE_DIR})
	target_compile_definitions(${TARGET} PUBLIC USE_SSL=1)
	
	# Link with sockets, threads, OpenSSL...
	if(WIN32)
  		target_link_libraries(${TARGET} wsock32 ws2_32)
	else()
  		target_link_libraries(${TARGET} pthread)
	endif()
  	target_link_libraries(${TARGET} ${OPENSSL_LIBRARIES})
	
	# Link statically
	if(WIN32)
		set(CMAKE_FIND_LIBRARY_SUFFIXES ".lib")
		target_compile_options(${TARGET} PUBLIC /MT)
		target_link_options(${TARGET} PUBLIC /INCREMENTAL:NO /NODEFAULTLIB:MSVCRT)
	else()
		target_link_libraries(${TARGET} -static)
	endif()
	
	# Make it a console application for easier debugging
	if(WIN32)
		set_target_properties(${TARGET} PROPERTIES LINK_FLAGS_DEBUG "/SUBSYSTEM:CONSOLE")
		set_target_properties(${TARGET} PROPERTIES COMPILE_DEFINITIONS_DEBUG "_CONSOLE")
		set_target_properties(${TARGET} PROPERTIES LINK_FLAGS_RELWITHDEBINFO "/SUBSYSTEM:CONSOLE")
		set_target_properties(${TARGET} PROPERTIES COMPILE_DEFINITIONS_RELWITHDEBINFO "_CONSOLE")
		set_target_properties(${TARGET} PROPERTIES LINK_FLAGS_RELEASE "/SUBSYSTEM:WINDOWS")
		set_target_properties(${TARGET} PROPERTIES LINK_FLAGS_MINSIZEREL "/SUBSYSTEM:WINDOWS")
	endif(WIN32)

endmacro()

# Project files
set (PROJECT_FILES
	sources/tcpsocket.h
	sources/tcpsocket.cpp
	sources/main.cpp
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
