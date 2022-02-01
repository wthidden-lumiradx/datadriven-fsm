cmake_minimum_required(VERSION 3.21)
project(datadriven_fsm C)

set(CMAKE_C_STANDARD 23)

add_executable(datadriven_fsm main.c fsm.c fsm.h)
