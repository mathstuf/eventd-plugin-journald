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
                -o "${CMAKE_CURRENT_BINARY_DIR}"
                ${xsltproc_args}
                ${ARGN}
                "http://docbook.sourceforge.net/release/xsl/current/manpages/profile-docbook.xsl"
                "${CMAKE_CURRENT_SOURCE_DIR}/${name}.xml"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/${name}.xml"
                ${xsltproc_deps}
        COMMENT "Generating manpage for ${name}.${section}")
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
    --nonet
    --xinclude
    --stringparam funcsynopsis.style ansi
    --stringparam man.output.quietly 1
    --path "${CMAKE_CURRENT_SOURCE_DIR}"
    --path "${CMAKE_CURRENT_BINARY_DIR}")
set(xsltproc_deps
    "${CMAKE_CURRENT_SOURCE_DIR}/common-man.xml"
    "${CMAKE_CURRENT_BINARY_DIR}/config.ent")

generate_manpage(eventd-journald.conf 5)
generate_manpage(eventd-journald.event 5)
