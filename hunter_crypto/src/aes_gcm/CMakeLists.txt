# 添加当前目录所有文件
AUX_SOURCE_DIRECTORY(. DIR_SRCS)

# 指定头文件目录
include_directories(${PROJECT_SOURCE_DIR}/include)

# 指定静态/动态库的输出目录
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)

# 查找需要链接的动态库，REQUIRED表示找不到，则会报错并退出，无REQUIRED会忽略找不到的库，执行时再报错
find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()

# hunter_aes_gcm 为编译输出的库名
# SHARED 指定编译为动态库，STATIC指定编译为静态库
add_library(hunter_aes_gcm STATIC ${DIR_SRCS})

# 指定编译需要链接的动态库
target_link_libraries(hunter_aes_gcm crypto)