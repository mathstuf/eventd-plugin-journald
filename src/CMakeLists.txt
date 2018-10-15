find_package(PkgConfig REQUIRED)
pkg_check_modules(Eventd REQUIRED libeventd>=0.19 IMPORTED_TARGET)
pkg_check_modules(EventdPlugin REQUIRED libeventd-plugin>=0.19 IMPORTED_TARGET)
pkg_check_modules(Systemd REQUIRED libsystemd IMPORTED_TARGET)

if (NOT COMMAND pkg_get_variable)
    function (pkg_get_variable out pkg var)
        execute_process(
            COMMAND "${PKG_CONFIG_EXECUTABLE}"
                    "--variable=${var}"
                    "${pkg}"
            OUTPUT_VARIABLE output
            RESULT_VARIABLE res
            OUTPUT_STRIP_TRAILING_WHITESPACE)
        if (NOT res)
            set("${out}"
                "${output}"
                PARENT_SCOPE)
        endif ()
    endfunction ()
endif ()

add_library(journald MODULE
    journald.c)
target_compile_definitions(journald
    PRIVATE
        -DG_LOG_DOMAIN="journald")
target_link_libraries(journald
    PRIVATE
        PkgConfig::Eventd
        PkgConfig::EventdPlugin
        PkgConfig::Systemd)
set_target_properties(journald
    PROPERTIES
        PREFIX    ""
        NO_SONAME 1)

pkg_get_variable(eventdplugin_prefix libeventd-plugin prefix)
if (NOT CMAKE_INSTALL_PREFIX STREQUAL eventdplugin_prefix)
  message(FATAL_ERROR "CMAKE_INSTALL_PREFIX does not match libeventd-plugin's prefix (${eventdplugin_prefix}); this is not supported")
endif ()

pkg_get_variable(eventdplugin_pluginsdir libeventd-plugin pluginsdir)
set(EVENTD_PLUGINS_DIR "${eventdplugin_pluginsdir}"
    CACHE PATH "eventd plugins directory")

install(
    TARGETS     journald
    DESTINATION "${EVENTD_PLUGINS_DIR}"
    COMPONENT   runtime)
