//
//  BiometricStorageTest.m
//  joy_biometric_storage
//
//  Created by fugui on 2023/11/6.
//

#import "BiometricStorageImp.h"
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

static NSString * const JDTBiometricsDataKey   = @"com.jd.app.biometricsData";
static NSString * const JDTBiometricsKeyChainServiceKey   = @"com.jd.app.biometricsKeyChainService";
static NSString * const JDTBiometricsKeyChainAccountKey   = @"com.jd.app.biometricsKeyChainAccount";
static NSString * const JDTSucceedKey   = @"succeed";
static NSString * const JDTErrorCodeKey   = @"errorCode";
static NSString * const JDTBiometricsTokenKey   = @"token";
static NSInteger SucceedCode = 10000;

static NSString * const JDTPinToken   = @"token";
static NSString * const JDTFallbackTitle   = @"fallbackTitle";
static NSString * const JDTReasonTitle   = @"reasonTitle";

/// 设备生物特征识别支持状态
typedef NS_ENUM(NSInteger, JDTBiometricsSupportedStatus) {
    /// 生物特征识别不支持
    JDTBiometricsUnsupported = 0,
    /// 支持touchID
    JDTBiometricsTouchIDSupported = 1 << 0,
    /// 支持faceID
    JDTBiometricsFaceIDSupported = 1 << 1,
    /// 未录入
    JDTBiometricsNotEnrolled = 1 << 2,
    /// 用户在设置里关闭了面容、指纹
    JDTBiometricsRefused = 1 << 3,
};

/// 设备生物特征识别错误码
typedef NS_ENUM(NSInteger, JDTBiometricsErrorCode) {
    /// 未录入指纹
    JDTBiometricsError_TouchIDNotEnrolled = 0,
    /// 未录入面容
    JDTBiometricsError_FaceIDNotEnrolled = 1,
    /// 未设置密码
    JDTBiometricsError_PasscodeNotSet = 2,
    /// 验证设备密码以解锁指纹
    JDTBiometricsError_TouchIDLockout = 3,
    /// 验证设备密码以解锁面容
    JDTBiometricsError_FaceIDLockout = 4,
    /// 指纹发生变更
    JDTBiometricsError_TouchIDChange = 5,
    /// 面容发生变更
    JDTBiometricsError_FaceIDChange = 6,
    /// 面容发生变更
    JDTBiometricsError_UserCancel = 7,
    /// 未知错误
    JDTBiometricsError_UnKnow = 8,
    /// KeyChain错误
    JDTBiometricsError_KeyChain = 100
};

@implementation BiometricStorageImp

/// 生物特征验证支持状态
+ (JDTBiometricsSupportedStatus)biometricsSupportedStatus {
    NSError *error = nil;
    LAContext *context = [[LAContext alloc] init];
    BOOL gBiometricsAvailable = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
    if (gBiometricsAvailable) {
        if (context.biometryType == LABiometryTypeTouchID) {
            return JDTBiometricsTouchIDSupported;
        } else if (context.biometryType == LABiometryTypeFaceID) {
            return JDTBiometricsFaceIDSupported;
        }
    } else {
        if (error.code == LAErrorBiometryNotEnrolled) {
            return JDTBiometricsNotEnrolled;
        } else if (error.code == LAErrorBiometryNotAvailable) {
            return JDTBiometricsRefused;
        }
    }
    
    return JDTBiometricsUnsupported;
}

+ (void)startBiometricsWrite:(BOOL)isWrite params:(NSDictionary *)params completed:(void (^)(BOOL bSucceed, JDTBiometricsErrorCode code))completionHandler {
    NSError *error = nil;
    LAContext *context = [[LAContext alloc] init];
    context.localizedFallbackTitle = params[JDTFallbackTitle] ?: @" "; //弹窗按钮文字
    NSString *reasonTitle = params[JDTReasonTitle] ?: @" "; // 弹窗描述文字
    BOOL biometricsAvailable = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
    if (!biometricsAvailable) {
        //无法使用验证
        if (error.code == LAErrorPasscodeNotSet) {
            //手机未设置密码
            if (completionHandler) {
                completionHandler(false, JDTBiometricsError_PasscodeNotSet);
            }
        } else if (error.code == LAErrorBiometryNotEnrolled) {
            if (isWrite) {
                //打开生物开关，未设置生物特征
                if (context.biometryType == LABiometryTypeTouchID) {
                    if (completionHandler) {
                        completionHandler(false, JDTBiometricsError_TouchIDNotEnrolled);
                    }
                } else if (context.biometryType == LABiometryTypeFaceID) {
                    if (completionHandler) {
                        completionHandler(false, JDTBiometricsError_FaceIDNotEnrolled);
                    }
                }
            } else {
                //使用生物识别，说明之前打开过生物开关，检测没有生物特征，说明发生了改变
                //清空本地保存生物信息
                [self deleteLocalBiometricsData];
                [self deleteKeyChainToken];
                if (context.biometryType == LABiometryTypeTouchID) {
                    if (completionHandler) {
                        completionHandler(false, JDTBiometricsError_TouchIDChange);
                    }
                } else if (context.biometryType == LABiometryTypeFaceID) {
                    if (completionHandler) {
                        completionHandler(false, JDTBiometricsError_FaceIDChange);
                    }
                }
            }
        } else if (error.code == LAErrorBiometryLockout) {
            //重新拉起验证
            [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication localizedReason:reasonTitle reply:^(BOOL success, NSError * _Nullable error) {
                if (success) {
                    [self startBiometricsWrite:isWrite params:params completed:completionHandler];
                } else {
                    if (context.biometryType == LABiometryTypeTouchID) {
                        if (completionHandler) {
                            completionHandler(false, JDTBiometricsError_TouchIDLockout);
                        }
                    } else if (context.biometryType == LABiometryTypeFaceID) {
                        if (completionHandler) {
                            completionHandler(false, JDTBiometricsError_FaceIDLockout);
                        }
                    }
                }
            }];
        } else {
            if (completionHandler) {
                completionHandler(false, JDTBiometricsError_UnKnow);
            }
        }
        return;
    }
    
    //拉取验证
    [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:reasonTitle reply:^(BOOL success, NSError * _Nullable error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (success) {
                if (!isWrite) {
                    //验证读取token
                    NSData *localData = [self readLocalBiometricsData];
                    if (![localData isEqualToData:context.evaluatedPolicyDomainState]) {
                        // 读取生物信息与保存的不一致，说明生物信息发生了改变
                        [self deleteLocalBiometricsData];
                        [self deleteKeyChainToken];
                        if (context.biometryType == LABiometryTypeTouchID) {
                            if (completionHandler) {
                                completionHandler(false, JDTBiometricsError_TouchIDChange);
                            }
                        } else if (context.biometryType == LABiometryTypeFaceID) {
                            if (completionHandler) {
                                completionHandler(false, JDTBiometricsError_FaceIDChange);
                            }
                        }
                        return;
                    }
                } else {
                    // 验证通过
                    [self saveLocalBiometricsData:context.evaluatedPolicyDomainState];
                }
                
                if (completionHandler) {
                    completionHandler(YES, SucceedCode);
                }
                return;
            }
            //失败
            if (error.code == LAErrorUserCancel) {
                if (completionHandler) {
                    completionHandler(NO, JDTBiometricsError_UserCancel);
                }
            } else {
                if (completionHandler) {
                    completionHandler(NO, JDTBiometricsError_UnKnow);
                }
            }
        });
    }];
}

+ (void)saveLocalBiometricsData:(NSData *)data {
    if (data) {
        [[NSUserDefaults standardUserDefaults] setObject:data forKey:JDTBiometricsDataKey];
        [[NSUserDefaults standardUserDefaults] synchronize];
    }
}

+ (NSData *)readLocalBiometricsData {
    return [[NSUserDefaults standardUserDefaults] objectForKey:JDTBiometricsDataKey];
}

+ (void)deleteLocalBiometricsData {
    [[NSUserDefaults standardUserDefaults] removeObjectForKey:JDTBiometricsDataKey];
}

+ (BOOL)saveKeyChainToken:(NSString *)token {
    NSLog(@"saveKeyChainToken: %@", token);
    if (token == nil) {
        return NO;
    }
    NSData *data = [token dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *saveItems = @{
        (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService : JDTBiometricsKeyChainServiceKey,
        (__bridge id)kSecAttrAccount : JDTBiometricsKeyChainAccountKey,
        (__bridge id)kSecValueData : data
    };
    CFTypeRef dataRef = nil;
    OSStatus errorCode = SecItemAdd((CFDictionaryRef)saveItems, (CFTypeRef *)&dataRef);
    if (errorCode == errSecSuccess) {
        return YES;
    } else if (errorCode == errSecDuplicateItem) {
        //覆盖
        return [self updateKeyChainToken:data];
    }
    NSLog(@"saveErrorCode: %d", errorCode);
    return NO;
}

+ (BOOL)updateKeyChainToken:(NSData *)data {
    NSDictionary *queryItems = @{
        (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService : JDTBiometricsKeyChainServiceKey,
        (__bridge id)kSecAttrAccount : JDTBiometricsKeyChainAccountKey,
    };
    NSDictionary *updateItems = @{
        (__bridge id)kSecValueData : data
    };
    OSStatus errorCode = SecItemUpdate((CFDictionaryRef)queryItems, (CFDictionaryRef)updateItems);
    NSLog(@"updateErrorCode: %d", errorCode);
    if(errorCode == errSecSuccess) {
        return YES;
    }
    return NO;
}

+ (NSString *)readKeyChainToken {
    NSDictionary *matchItems = @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrService : JDTBiometricsKeyChainServiceKey,
        (id)kSecAttrAccount : JDTBiometricsKeyChainAccountKey,
        (id)kSecMatchLimit : (id)kSecMatchLimitOne,
        (id)kSecReturnData : @(YES)
    };
    CFTypeRef dataRef = nil;
    OSStatus errorCode = SecItemCopyMatching((CFDictionaryRef)matchItems, (CFTypeRef *)&dataRef);
    if (errorCode == errSecSuccess) {
        NSString *token = [[NSString alloc] initWithData:CFBridgingRelease(dataRef) encoding:NSUTF8StringEncoding];
        NSLog(@"readKeyChainToken: %@", token);
        return  token;
    }
    NSLog(@"readErrorCode: %d", errorCode);
    return @"";
}

+ (void)deleteKeyChainToken {
    NSDictionary *secItems = @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrService : JDTBiometricsKeyChainServiceKey,
        (id)kSecAttrAccount : JDTBiometricsKeyChainAccountKey,
    };
    OSStatus errorCode = SecItemDelete((CFDictionaryRef)secItems);
    NSLog(@"deleteErrorCode: %d", errorCode);
}

+ (void)write:(NSDictionary *)params completed:(void (^)(NSDictionary * _Nonnull))completionHandler{
    NSMutableDictionary *resultDic = [NSMutableDictionary dictionary];
    [self startBiometricsWrite:YES params:params completed:^(BOOL bSucceed, JDTBiometricsErrorCode code) {
        if (bSucceed) {
            //验证成功，写入keychain
            BOOL result = [self saveKeyChainToken:params[@"token"]];
            if (result) {
                [resultDic setObject:@(YES) forKey:JDTSucceedKey];
            } else {
                code = JDTBiometricsError_KeyChain;
                [resultDic setObject:@(NO) forKey:JDTSucceedKey];
            }
        } else {
            [resultDic setObject:@(NO) forKey:JDTSucceedKey];
        }
        [resultDic setObject:@(code) forKey:JDTErrorCodeKey];
        [resultDic setObject:@"" forKey:JDTBiometricsTokenKey];
        if (completionHandler) {
            completionHandler(resultDic);
        }
    }];
}

+ (void)read:(NSDictionary *)params completed:(void (^)(NSDictionary * _Nonnull))completionHandler {
    NSMutableDictionary *resultDic = [NSMutableDictionary dictionary];
    [self startBiometricsWrite:NO params:params completed:^(BOOL bSucceed, JDTBiometricsErrorCode code) {
        [resultDic setObject:@(code) forKey:JDTErrorCodeKey];
        if (bSucceed) {
            //验证成功，读取token
            NSString *token = [self readKeyChainToken];
            if ([token isEqualToString:@""]) {
                code = JDTBiometricsError_KeyChain;
                [resultDic setObject:@(code) forKey:JDTErrorCodeKey];
                [resultDic setObject:@"" forKey:JDTBiometricsTokenKey];
                [resultDic setObject:@(NO) forKey:JDTSucceedKey];
            } else {
                [resultDic setObject:token forKey:JDTBiometricsTokenKey];
                [resultDic setObject:@(YES) forKey:JDTSucceedKey];
            }
        } else {
            [resultDic setObject:@"" forKey:JDTBiometricsTokenKey];
            [resultDic setObject:@(NO) forKey:JDTSucceedKey];
        }
        if (completionHandler) {
            completionHandler(resultDic);
        }
    }];
}

+(void)deleteCompleted:(void (^)(NSDictionary * _Nonnull))completionHandler {
    [self deleteKeyChainToken];
    if (completionHandler) {
        completionHandler(@{
            JDTSucceedKey : @(YES),
            JDTBiometricsTokenKey : @"",
            JDTErrorCodeKey : @(SucceedCode)
        });
    }
}


@end
