cmake_minimum_required(VERSION 3.7.0)

set(project "eventd-plugin-journald")
project("${project}" C)

set("${project}_version_major" 0)
set("${project}_version_minor" 13)
set("${project}_version_patch" 1)
set("${project}_version" "${${project}_version_major}.${${project}_version_minor}.${${project}_version_patch}")

set(CMAKE_C_VISIBILITY_PRESET "hidden")
string(APPEND CMAKE_C_FLAGS " -Wall")

add_subdirectory(man)
add_subdirectory(src)
