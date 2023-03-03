project(
    'kiss-ng',
    'c',
    default_options: [
        'buildtype=debugoptimized',
        'warning_level=3',
        'b_lto=true',
        'c_std=c11',
    ],
)

cc = meson.get_compiler('c')

c_args = []

warning_c_args = [
    '-Wshadow',
    '-Wnull-dereference',
    '-Wformat=2',
    '-Wcast-qual',
    '-Wconversion',
    '-Wpointer-arith',
    '-Wunused-macros',
    '-Wredundant-decls',
    '-Wwrite-strings',
    '-Werror=int-conversion',
    '-Werror=implicit-function-declaration',
    '-Werror=incompatible-pointer-types',
]

add_project_arguments(c_args, language: 'c')
add_project_arguments(cc.get_supported_arguments(warning_c_args), language: 'c')

incdirs = include_directories('include')

libkiss_ng = static_library(
    'kiss-ng',
    'lib/log.c',
    include_directories: incdirs,
    install: true,
)

executable(
    'kiss-ng',
    'src/kiss-ng.c',
    link_with: libkiss_ng,
    include_directories: incdirs,
    install: true,
)

install_headers('include/kiss-ng.h')
