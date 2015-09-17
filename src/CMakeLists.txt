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

install(
    TARGETS     journald
    DESTINATION lib${LIB_SUFFIX}/eventd/plugins
    COMPONENT   runtime)
