
cmake_minimum_required( VERSION 2.6 )
project( simple-proxy-utils )

set( CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake )

find_package( Voms REQUIRED )
find_package( PythonInterp REQUIRED )

if( CMAKE_COMPILER_IS_GNUCXX )
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror" )
endif()

if( CMAKE_COMPILER_IS_GNUCC )
  set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror" )
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -D_GLIBCXX_USE_CXX11_ABI=0")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")

include (FindPkgConfig)
pkg_check_modules(GLOBUS REQUIRED globus-gsi-credential globus-gsi-cert-utils globus-common globus-gsi-sysconfig globus-gsi-callback)
set (INCLUDE_DIRECTORIES ${INCLUDE_DIRECTORIES} ${GLOBUS_INCLUDE_DIRS})

include_directories( "${PROJECT_SOURCE_DIR}" "${VOMS_INCLUDES}")

add_library(SimpleProxyUtils MODULE src/SimpleProxyUtils.cc src/GlobusSupport.cc src/GlobusError.cc)
target_link_libraries(SimpleProxyUtils ${VOMS_LIB} ${GLOBUS_LIBRARIES})
set_target_properties(SimpleProxyUtils PROPERTIES LINK_FLAGS "-Wl,--version-script=${PROJECT_SOURCE_DIR}/configs/export-symbols")

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/chain_verify_test
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${PROJECT_SOURCE_DIR}/src/simple_proxy_utils.py ${CMAKE_CURRENT_BINARY_DIR}/chain_verify_test
    MAIN_DEPENDENCY ${PROJECT_SOURCE_DIR}/src/simple_proxy_utils.py)
add_custom_target(python ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/chain_verify_test)

if (NOT DEFINED LIB_INSTALL_DIR)
  SET(LIB_INSTALL_DIR "lib")
endif()

install(
  TARGETS SimpleProxyUtils
  LIBRARY DESTINATION ${LIB_INSTALL_DIR} )

install(
  FILES ${CMAKE_SOURCE_DIR}/src/simple_proxy_utils.py
  DESTINATION ${LIB_INSTALL_DIR}/python${PYTHON_VERSION_MAJOR}.${PYTHON_VERSION_MINOR}/site-packages/ )

set_target_properties(
  SimpleProxyUtils
  PROPERTIES
  VERSION   "0.0.2"
  SOVERSION "0"
  LINK_INTERFACE_LIBRARIES "" )

