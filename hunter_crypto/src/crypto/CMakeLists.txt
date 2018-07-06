# 添加指定的代码文件
set(SRC_LIST hunter_crypto.cpp)

# 指定头文件目录
include_directories(${PROJECT_SOURCE_DIR}/include)

# 指定动态/静态库的输出目录
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)
find_package( PythonLibs 2.7 REQUIRED )
include_directories( ${PYTHON_INCLUDE_DIRS})

# 注意boost python版本, 
# 查看/lib64 /usr/lib64中 libboost_python*对应的版本
find_package(Boost COMPONENTS python27)
include_directories( ${Boost_INCLUDE_DIR} )

# 添加动态库搜索目录
link_directories(${PROJECT_SOURCE_DIR}/lib)
add_library(hunter_crypto SHARED ${SRC_LIST})
target_link_libraries(hunter_crypto hunter_aes_gcm ${Boost_LIBRARIES})

# 去掉动态库的前缀，动态库为hunter_crypto.so,此处动态库名需要与BOOST_PYTHON_MODULE(lib_name)对应上
set_target_properties(hunter_crypto PROPERTIES PREFIX "")

# 指定最终的安装目录 
install(TARGETS hunter_crypto
            RUNTIME DESTINATION bin
            LIBRARY DESTINATION lib64
)
