project('samplecore', 'c',
  version: '0.0.1',
  license: 'LGPL3',
  meson_version: '>=0.55.0',
  default_options: [
    'buildtype=debugoptimized',
    'b_vscrt=from_buildtype',
  ])

rz_core = dependency('rz_core')
core_plugdir = rz_core.get_variable(pkgconfig: 'plugindir', cmake: 'rz_core_PLUGINDIR')

plugin_incs = ['.']
plugin_src = ['core_plugin.c']
plugin_deps = [rz_core]

shared_library('samplecore', plugin_src,
  dependencies: plugin_deps,
  include_directories: include_directories(plugin_incs),
  implicit_include_directories: false,
  install: true,
  install_dir: core_plugdir
)
