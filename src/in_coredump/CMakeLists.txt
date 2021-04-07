# FIXME: there is something wrong when linking objects and this
# static plugin, I should not require to link to a specific symbol
# if the object was already linked from fluent-bit core on src/, also
# jsmn should not be required.

webos_distro_variant_dep()
webos_configure_source_files(cfg ${CMAKE_CURRENT_SOURCE_DIR}/Environment.h) 

set(src
  in_coredump.c
  )

FLB_PLUGIN(in_coredump "${src}" "")
