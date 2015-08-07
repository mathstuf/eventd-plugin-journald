cmake_minimum_required(VERSION 3.1)

set(project "eventd-plugin-journald")
project("${project}" NONE)

set("${project}_version_major" 0)
set("${project}_version_minor" 1)
set("${project}_version_patch" 0)
set("${project}_version" "${${project}_version_major}.${${project}_version_minor}.${${project}_version_patch}")

set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} -fvisibility=hidden")

add_subdirectory(man)
