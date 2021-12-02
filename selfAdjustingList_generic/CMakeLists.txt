cmake_minimum_required(VERSION 3.20)
project(selfAdjustingList_generic C)

set(CMAKE_C_STANDARD 99)

#change this path to your own kernel header includes
include_directories(/usr/src/linux-headers-5.4.0-86-generic/include)
add_executable(selfAdjustingList_generic main.c self_adjusting_list.h)
