find_program(XSLT_EXECUTABLE
    NAMES   xsltproc
    DOC     "xsltproc for handling documentation")

if (NOT XSLT_EXECUTABLE)
    message(FATAL_ERROR "xsltproc is required for documentation")
endif ()

add_custom_target(man ALL)

function (generate_manpage name section)
    add_custom_command(
        OUTPUT  "${CMAKE_CURRENT_BINARY_DIR}/${name}.${section}"
        COMMAND "${XSLT_EXECUTABLE}"
                -o "${CMAKE_CURRENT_BINARY_DIR}/"
                ${xsltproc_args}
                ${ARGN}
                "http://docbook.sourceforge.net/release/xsl/current/manpages/profile-docbook.xsl"
                "${CMAKE_CURRENT_SOURCE_DIR}/${name}.xml"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/${name}.xml"
                ${xsltproc_deps}
        COMMENT "Generating manpage for ${name}.${section}"
        WORKING_DIRECTORY
                "${CMAKE_CURRENT_BINARY_DIR}")
    add_custom_target("man-${name}.${section}"
        DEPENDS
            "${CMAKE_CURRENT_BINARY_DIR}/${name}.${section}")
    add_dependencies(man
        "man-${name}.${section}")
    install(
        FILES       "${CMAKE_CURRENT_BINARY_DIR}/${name}.${section}"
        DESTINATION "share/man/man${section}"
        COMPONENT   "documentation")
endfunction ()

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/config.ent.in"
    "${CMAKE_CURRENT_BINARY_DIR}/config.ent"
    @ONLY)

set(xsltproc_args
    --xinclude
    --stringparam funcsynopsis.style ansi
    --stringparam man.output.quietly 1
    --path "${CMAKE_CURRENT_SOURCE_DIR}"
    --path "${CMAKE_CURRENT_BINARY_DIR}")
set(xsltproc_deps
    "${CMAKE_CURRENT_SOURCE_DIR}/common-man.xml"
    "${CMAKE_CURRENT_BINARY_DIR}/config.ent")

option(JOURNALD_XSLT_VERIFY "Verify the manpages using the DTD" ON)
mark_as_advanced(JOURNALD_XSLT_VERIFY)

if (NOT JOURNALD_XSLT_VERIFY)
    list(APPEND xsltproc_args
        --nonet
        --novalid)
endif ()

generate_manpage(eventd-journald.conf 5)
