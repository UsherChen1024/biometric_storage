#import "BiometricStoragePlugin.h"
#import <joy_biometric_storage/joy_biometric_storage-Swift.h>
#import "BiometricStorageImp.h"

@implementation BiometricStoragePlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
//  [SwiftBiometricStoragePlugin registerWithRegistrar:registrar];
    FlutterMethodChannel *channel = [FlutterMethodChannel methodChannelWithName:@"biometric_storage" binaryMessenger:[registrar messenger]];
    BiometricStoragePlugin *instance = [[BiometricStoragePlugin alloc] init];
    [registrar addMethodCallDelegate:instance channel:channel];
}

- (void)handleMethodCall:(FlutterMethodCall *)call result:(FlutterResult)result {
    NSDictionary *argDic = (NSDictionary *)call.arguments;
    if (argDic == nil || argDic.allKeys.count == 0) {
        argDic = @{};
    }
    
    if ([call.method isEqualToString:@"canAuthenticate"]) {
        [BiometricStorageImp canAuthenticateCompleted:result];
    } else if ([call.method isEqualToString:@"getAvailableBiometrics"]) {
        [BiometricStorageImp getAvailableBiometricsCompleted:result];
    } else if ([call.method isEqualToString:@"write"]) {
        [BiometricStorageImp write:argDic completed:result];
    } else if ([call.method isEqualToString:@"read"]) {
        [BiometricStorageImp read:argDic completed:result];
    } else if ([call.method isEqualToString:@"delete"]) {
        [BiometricStorageImp delete:argDic completed:result];
    }
}

@end
