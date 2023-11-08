//
//  BiometricStorageTest.h
//  joy_biometric_storage
//
//  Created by fugui on 2023/11/6.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface BiometricStorageImp : NSObject

+ (void)write:(NSDictionary *)params completed:(void (^)(NSDictionary *dic))completionHandler;

+ (void)read:(NSDictionary *)params completed:(void (^)(NSDictionary *dic))completionHandler;

+ (void)deleteCompleted:(void (^)(NSDictionary *dic))completionHandler;

@end

NS_ASSUME_NONNULL_END
