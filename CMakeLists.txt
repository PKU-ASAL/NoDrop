cmake_minimum_required(VERSION 3.20)
project(ImGuiDemo)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

## Find dependencies
find_package(glfw3 REQUIRED)
find_package(imgui REQUIRED)
find_package(Freetype REQUIRED)

add_subdirectory(glad)
add_subdirectory(imgui)

add_executable(${PROJECT_NAME} src/main.cpp)

target_link_libraries(
  ${PROJECT_NAME}
  PRIVATE
    glfw
    imgui::imgui
    ${FREETYPE_LIBRARIES}
    glad
    imgui
    GL
)