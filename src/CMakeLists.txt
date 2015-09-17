find_package(PkgConfig REQUIRED)
pkg_check_modules(Eventd REQUIRED libeventd>=0.4)
pkg_check_modules(EventdPlugin REQUIRED libeventd-plugin>=0.3)
pkg_check_modules(SystemdJournal REQUIRED libsystemd-journal)

macro (pkg_get_variable pkg var out)
    execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} --variable=${var} ${pkg}
        OUTPUT_VARIABLE ${out}
        OUTPUT_STRIP_TRAILING_WHITESPACE)
endmacro ()

pkg_get_variable(libeventd pkglibdir eventd_pkglibdir)
find_library(EventdHelpers_LIBRARY eventd-helpers
    PATHS ${eventd_pkglibdir}
    NO_DEFAULT_PATH)

include_directories(SYSTEM
    ${Eventd_INCLUDE_DIRS}
    ${EventdPlugin_INCLUDE_DIRS}
    ${SystemdJournal_INCLUDE_DIRS})

add_library(journald MODULE
    journald.c)
target_compile_definitions(journald
    PRIVATE
        -DG_LOG_DOMAIN="eventd-journald")
target_link_libraries(journald
    PRIVATE
        ${Eventd_LIBRARIES}
        ${EventdPlugin_LIBRARIES}
        ${EventdHelpers_LIBRARY}
        ${SystemdJournal_LIBRARIES})
set_target_properties(journald
    PROPERTIES
        PREFIX    ""
        NO_SONAME 1)

pkg_get_variable(libeventd-plugin exec_prefix eventdplugin_execprefix)
if (NOT CMAKE_INSTALL_PREFIX STREQUAL eventdplugin_execprefix)
  message(FATAL_ERROR "CMAKE_INSTALL_PREFIX does not match libeventd-plugin's exec-prefix (${eventdplugin_execprefix}); this is not supported")
endif ()

pkg_get_variable(libeventd-plugin pluginsdir eventdplugin_pluginsdir)
set(EVENTD_PLUGINS_DIR ${eventdplugin_pluginsdir}
    CACHE
    PATH
    "eventd plugins directory (defaults to ${eventdplugin_pluginsdir}")

install(
    TARGETS     journald
    DESTINATION ${EVENTD_PLUGINS_DIR}
    COMPONENT   runtime)
