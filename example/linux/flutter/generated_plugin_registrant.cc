//
//  Generated file. Do not edit.
//

// clang-format off

#include "generated_plugin_registrant.h"

#include <joy_biometric_storage/biometric_storage_plugin.h>

void fl_register_plugins(FlPluginRegistry* registry) {
  g_autoptr(FlPluginRegistrar) joy_biometric_storage_registrar =
      fl_plugin_registry_get_registrar_for_plugin(registry, "BiometricStoragePlugin");
  biometric_storage_plugin_register_with_registrar(joy_biometric_storage_registrar);
}
