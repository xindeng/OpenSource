# 指定cmake版本
cmake_minimum_required(VERSION 2.8.9)

# 指定项目名
project(hunter_crypto)

# 指定安装目录前缀，为根目录
set(CMAKE_INSTALL_PREFIX /)

# 添加编译参数，编译位置无关代码
set(CMAKE_CXX_FLAGS "-fPIC")

# 添加子目录
add_subdirectory(src) 