find_package(PkgConfig REQUIRED)
pkg_check_modules(EventdPlugin REQUIRED libeventd-plugin)
pkg_check_modules(SystemdJournal REQUIRED libsystemd-journal)

include_directories(SYSTEM
    ${EventdPlugin_INCLUDE_DIRS}
    ${SystemdJournal_INCLUDE_DIRS})

add_library(journald MODULE
    journald.c)