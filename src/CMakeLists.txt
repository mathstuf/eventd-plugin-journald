find_package(PkgConfig REQUIRED)
pkg_check_modules(EventdEvent REQUIRED libeventd-event>=0.3)
pkg_check_modules(EventdPlugin REQUIRED libeventd-plugin>=0.3)
pkg_check_modules(SystemdJournal REQUIRED libsystemd-journal)

include_directories(SYSTEM
    ${EventdEvent_INCLUDE_DIRS}
    ${EventdPlugin_INCLUDE_DIRS}
    ${SystemdJournal_INCLUDE_DIRS})

add_library(journald MODULE
    journald.c)

install(
    TARGETS     journald
    DESTINATION lib${LIB_SUFFIX}/eventd
    COMPONENT   runtime)
