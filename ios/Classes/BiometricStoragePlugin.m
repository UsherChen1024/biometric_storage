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
    NSString *token = argDic[@"token"];
    
    if ([call.method isEqualToString:@"testWrite"]) {
      [BiometricStorageImp write:token completed:result];
    } else if ([call.method isEqualToString:@"testRead"]) {
      [BiometricStorageImp readCompleted:result];
    } else if ([call.method isEqualToString:@"testDelete"]) {
      [BiometricStorageImp deleteCompleted:result];
    }
}

@end
