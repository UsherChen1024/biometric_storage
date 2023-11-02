#import "BiometricStoragePlugin.h"
#import <joy_biometric_storage/joy_biometric_storage-Swift.h>

@implementation BiometricStoragePlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftBiometricStoragePlugin registerWithRegistrar:registrar];
}
@end
