project('samplehash', 'c',
  version: '0.0.1',
  license: 'LGPL3',
  meson_version: '>=0.55.0',
  default_options: [
    'buildtype=debugoptimized',
    'b_vscrt=from_buildtype',
  ])

rz_hash = dependency('rz_hash')
hash_plugdir = rz_hash.get_variable(pkgconfig: 'plugindir', cmake: 'rz_hash_PLUGINDIR')

plugin_incs = ['.']
plugin_src = ['hash_plugin.c']
plugin_deps = [rz_hash]

shared_library('samplehash', plugin_src,
  dependencies: plugin_deps,
  include_directories: include_directories(plugin_incs),
  implicit_include_directories: false,
  install: true,
  install_dir: hash_plugdir
)
