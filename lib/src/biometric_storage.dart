import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:joy_biometric_storage/src/biometric_error_code.dart';
import 'package:logging/logging.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'biometric_type.dart';

final _logger = Logger('biometric_storage');

/// Reason for not supporting authentication.
/// **As long as this is NOT [unsupported] you can still use the secure
/// storage without biometric storage** (By setting
/// [StorageFileInitOptions.authenticationRequired] to `false`).
enum CanAuthenticateResponse {
  success,
  errorHwUnavailable,
  errorNoBiometricEnrolled,
  errorNoHardware,

  /// Passcode is not set (iOS/MacOS) or no user credentials (on macos).
  errorPasscodeNotSet,

  /// 用户在设置中关闭了生物识别(iOS)
  errorBiometricClosed,

  /// Used on android if the status is unknown.
  /// https://developer.android.com/reference/androidx/biometric/BiometricManager#BIOMETRIC_STATUS_UNKNOWN
  statusUnknown,

  /// Plugin does not support platform. This should no longer be the case.
  unsupported,
}

const _canAuthenticateMapping = {
  'Success': CanAuthenticateResponse.success,
  'ErrorHwUnavailable': CanAuthenticateResponse.errorHwUnavailable,
  'ErrorNoBiometricEnrolled': CanAuthenticateResponse.errorNoBiometricEnrolled,
  'ErrorNoHardware': CanAuthenticateResponse.errorNoHardware,
  'ErrorPasscodeNotSet': CanAuthenticateResponse.errorPasscodeNotSet,
  'ErrorUnknown': CanAuthenticateResponse.unsupported,
  'ErrorStatusUnknown': CanAuthenticateResponse.statusUnknown,
};

enum AuthExceptionCode {
  /// User taps the cancel/negative button or presses `back`.
  userCanceled,

  /// Authentication prompt is canceled due to another reason
  /// (like when biometric sensor becamse unavailable like when
  /// user switches between apps, logsout, etc).
  canceled,
  unknown,
  timeout,
  linuxAppArmorDenied,
}

const _authErrorCodeMapping = {
  'AuthError:UserCanceled': AuthExceptionCode.userCanceled,
  'AuthError:Canceled': AuthExceptionCode.canceled,
  'AuthError:Timeout': AuthExceptionCode.timeout,
};

class BiometricStorageException implements Exception {
  BiometricStorageException(this.message);
  final String message;

  @override
  String toString() {
    return 'BiometricStorageException{message: $message}';
  }
}

/// Exceptions during authentication operations.
/// See [AuthExceptionCode] for details.
class AuthException implements Exception {
  AuthException(this.code, this.message);

  final AuthExceptionCode code;
  final String message;

  @override
  String toString() {
    return 'AuthException{code: $code, message: $message}';
  }
}

class StorageFileInitOptions {
  StorageFileInitOptions({
    this.authenticationValidityDurationSeconds = -1,
    this.authenticationRequired = true,
    this.androidBiometricOnly = true,
    this.darwinBiometricOnly = true,
  });

  final int authenticationValidityDurationSeconds;

  /// Whether an authentication is required. if this is
  /// false NO BIOMETRIC CHECK WILL BE PERFORMED! and the value
  /// will simply be save encrypted. (default: true)
  final bool authenticationRequired;

  /// Only makes difference on Android, where if set true, you can't use
  /// PIN/pattern/password to get the file.
  /// On Android < 30 this will always be ignored. (always `true`)
  /// https://github.com/authpass/biometric_storage/issues/12#issuecomment-900358154
  ///
  /// Also: this **must** be `true` if [authenticationValidityDurationSeconds]
  /// is `-1`.
  /// https://github.com/authpass/biometric_storage/issues/12#issuecomment-902508609
  final bool androidBiometricOnly;

  /// Only for iOS and macOS:
  /// Uses `.biometryCurrentSet` if true, `.userPresence` otherwise.
  /// https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/1392879-userpresence
  final bool darwinBiometricOnly;

  Map<String, dynamic> toJson() => <String, dynamic>{
        'authenticationValidityDurationSeconds':
            authenticationValidityDurationSeconds,
        'authenticationRequired': authenticationRequired,
        'androidBiometricOnly': androidBiometricOnly,
        'darwinBiometricOnly': darwinBiometricOnly,
      };
}

/// Android specific configuration of the prompt displayed for biometry.
class AndroidPromptInfo {
  const AndroidPromptInfo({
    this.title = 'Authenticate to unlock data',
    this.subtitle,
    this.description,
    this.negativeButton = 'Cancel',
    this.confirmationRequired = true,
  });

  final String title;
  final String? subtitle;
  final String? description;
  final String negativeButton;
  final bool confirmationRequired;

  static const defaultValues = AndroidPromptInfo();

  Map<String, dynamic> _toJson() => <String, dynamic>{
        'title': title,
        'subtitle': subtitle,
        'description': description,
        'negativeButton': negativeButton,
        'confirmationRequired': confirmationRequired,
      };
}

/// iOS **and MacOS** specific configuration of the prompt displayed for biometry.
class IosPromptInfo {
  const IosPromptInfo({
    this.reasonTitle = 'Unlock to save data',
    this.fallbackTitle = 'Unlock to access data',
  });

  final String reasonTitle;
  final String fallbackTitle;

  static const defaultValues = IosPromptInfo();

  Map<String, dynamic> _toJson() => <String, dynamic>{
        'reasonTitle': reasonTitle,
        'fallbackTitle': fallbackTitle,
      };
}

/// Wrapper for platform specific prompt infos.
class PromptInfo {
  const PromptInfo({
    this.androidPromptInfo = AndroidPromptInfo.defaultValues,
    this.iosPromptInfo = IosPromptInfo.defaultValues,
    this.macOsPromptInfo = IosPromptInfo.defaultValues,
  });
  static const defaultValues = PromptInfo();

  final AndroidPromptInfo androidPromptInfo;
  final IosPromptInfo iosPromptInfo;
  final IosPromptInfo macOsPromptInfo;
}

class BiometricResponse {
  final bool success;
  final BiometricErrorCode errorCode;
  final String? data;

  const BiometricResponse(
      {this.success = false,
      this.errorCode = BiometricErrorCode.errorUnKnow,
      this.data});
}

/// Main plugin class to interact with. Is always a singleton right now,
/// factory constructor will always return the same instance.
///
/// * call [canAuthenticate] to check support on the platform/device.
/// * call [getStorage] to initialize a storage.
abstract class BiometricStorage extends PlatformInterface {
  // Returns singleton instance.
  factory BiometricStorage() => _instance;

  BiometricStorage.create() : super(token: _token);

  static BiometricStorage _instance = MethodChannelBiometricStorage();

  /// Platform-specific plugins should set this with their own platform-specific
  /// class that extends [UrlLauncherPlatform] when they register themselves.
  static set instance(BiometricStorage instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  static const Object _token = Object();

  /// Returns whether this device supports biometric/secure storage or
  /// the reason [CanAuthenticateResponse] why it is not supported.
  Future<CanAuthenticateResponse> canAuthenticate();

  Future<List<BiometricType>> getAvailableBiometrics();

  /// Returns true when there is an AppArmor error when trying to read a value.
  ///
  /// When used inside a snap, there might be app armor limitations
  /// which lead to an error like:
  /// org.freedesktop.DBus.Error.AccessDenied: An AppArmor policy prevents
  /// this sender from sending this message to this recipient;
  /// type="method_call", sender=":1.140" (uid=1000 pid=94358
  /// comm="/snap/biometric-storage-example/x1/biometric_stora"
  /// label="snap.biometric-storage-example.biometric (enforce)")
  /// interface="org.freedesktop.Secret.Service" member="OpenSession"
  /// error name="(unset)" requested_reply="0" destination=":1.30"
  /// (uid=1000 pid=1153 comm="/usr/bin/gnome-keyring-daemon
  /// --daemonize --login " label="unconfined")
  Future<bool> linuxCheckAppArmorError();

  /// Retrieves the given biometric storage file.
  /// Each store is completely separated, and has it's own encryption and
  /// biometric lock.
  /// if [forceInit] is true, will throw an exception if the store was already
  /// created in this runtime.
  Future<BiometricStorageFile> getStorage(
    String name, {
    StorageFileInitOptions? options,
    bool forceInit = false,
    PromptInfo promptInfo = PromptInfo.defaultValues,
  });

  // @protected
  // Future<String?> read(
  //   String name,
  //   PromptInfo promptInfo,
  // );

  // @protected
  // Future<bool?> delete(
  //   String name,
  //   PromptInfo promptInfo,
  // );

  // @protected
  // Future<void> write(
  //   String name,
  //   String content,
  //   PromptInfo promptInfo,
  // );

  Future<BiometricResponse> write(String name, String content, PromptInfo promptInfo);

  Future<BiometricResponse> read(String name, PromptInfo promptInfo);

  Future<BiometricResponse> delete(String name, PromptInfo promptInfo);
}

class MethodChannelBiometricStorage extends BiometricStorage {
  MethodChannelBiometricStorage() : super.create();

  static const MethodChannel _channel = MethodChannel('biometric_storage');

  @override
  Future<CanAuthenticateResponse> canAuthenticate() async {
    if (kIsWeb) {
      return CanAuthenticateResponse.unsupported;
    }
    if (Platform.isAndroid || Platform.isLinux) {
      final response = await _channel.invokeMethod<String>('canAuthenticate');
      final ret = _canAuthenticateMapping[response];
      if (ret == null) {
        throw StateError('Invalid response from native platform. {$response}');
      }
      return ret;
    } else if (Platform.isIOS || Platform.isMacOS) {
      final response = await _channel.invokeMethod('canAuthenticate');
      final Map<Object?, Object?> result = response as Map<Object?, Object?>;
      final bool success = result['succeed'] == 1 ? true : false;
      final int code = result['errorCode'] as int;
      if (success) {
        return CanAuthenticateResponse.success;
      }
      if (code == 3) {
        return CanAuthenticateResponse.errorNoBiometricEnrolled;
      }
      if (code == 11) {
        return CanAuthenticateResponse.errorBiometricClosed;
      }
      if (code == 10) {
        return CanAuthenticateResponse.errorPasscodeNotSet;
      }
    }
    return CanAuthenticateResponse.unsupported;
  }

  @override
  Future<List<BiometricType>> getAvailableBiometrics() async {
    final List<BiometricType> biometrics = <BiometricType>[];

    if (Platform.isIOS) {
      final response = await _channel.invokeMethod('getAvailableBiometrics');
      final Map<Object?, Object?> result = response as Map<Object?, Object?>;
      final int code = result['errorCode'] as int;
      if (code == 20) {
        biometrics.add(BiometricType.fingerprint);
      } else if (code == 21) {
        biometrics.add(BiometricType.face);
      }
      return biometrics;
    }

    final result = await _channel.invokeListMethod<String>(
          'getAvailableBiometrics',
        ) ??
        [];
    _logger.finer('availables = $result');

    for (final String value in result) {
      switch (value) {
        case 'face':
          biometrics.add(BiometricType.face);
          break;
        case 'fingerprint':
          biometrics.add(BiometricType.fingerprint);
          break;
        case 'iris':
          biometrics.add(BiometricType.iris);
          break;
        case 'weak':
          biometrics.add(BiometricType.weak);
          break;
        case 'strong':
          biometrics.add(BiometricType.strong);
          break;
        case 'undefined':
          // Sentinel value for the case when nothing is enrolled, but hardware
          // support for biometrics is available.
          break;
      }
    }
    return biometrics;
  }

  // @override
  // Future<void> testWrite({
  //     String? token, String? fallTitle, String? reasonTitle}) async {
  //   final result = await _channel.invokeMethod('testWrite', {
  //         'token': token ?? '111',
  //         'fallbackTitle': fallTitle ?? '密码支付',
  //         'reasonTitle': reasonTitle ?? '使用生物支付哈哈哈哈'
  //       }) ??
  //       {};
  //   _logger.finer('testWrite--result回调：$result');
  //   // return result;
  // }

  // @override
  // Future<void> testRead(
  //   {String? fallTitle, String? reasonTitle}
  // ) async {
  //   final result = await _channel.invokeMethod('testRead') ?? {};
  //   _logger.finer('testRead --result回调：$result');
  // }

  // @override
  // Future<void> testDelete() async {
  //   final result = await _channel.invokeMethod('testDelete') ?? {};
  //   _logger.finer('testDelete --result回调：$result');
  // }

  /// Returns true when there is an AppArmor error when trying to read a value.
  ///
  /// When used inside a snap, there might be app armor limitations
  /// which lead to an error like:
  /// org.freedesktop.DBus.Error.AccessDenied: An AppArmor policy prevents
  /// this sender from sending this message to this recipient;
  /// type="method_call", sender=":1.140" (uid=1000 pid=94358
  /// comm="/snap/biometric-storage-example/x1/biometric_stora"
  /// label="snap.biometric-storage-example.biometric (enforce)")
  /// interface="org.freedesktop.Secret.Service" member="OpenSession"
  /// error name="(unset)" requested_reply="0" destination=":1.30"
  /// (uid=1000 pid=1153 comm="/usr/bin/gnome-keyring-daemon
  /// --daemonize --login " label="unconfined")
  @override
  Future<bool> linuxCheckAppArmorError() async {
    if (!Platform.isLinux) {
      return false;
    }
    final tmpStorage = await getStorage('appArmorCheck',
        options: StorageFileInitOptions(authenticationRequired: false));
    _logger.finer('Checking app armor');
    try {
      // await tmpStorage.read();
      _logger.finer('Everything okay.');
      return false;
    } on AuthException catch (e, stackTrace) {
      if (e.code == AuthExceptionCode.linuxAppArmorDenied) {
        return true;
      }
      _logger.warning(
          'Unknown error while checking for app armor.', e, stackTrace);
      // some other weird error?
      rethrow;
    }
  }

  /// Retrieves the given biometric storage file.
  /// Each store is completely separated, and has it's own encryption and
  /// biometric lock.
  /// if [forceInit] is true, will throw an exception if the store was already
  /// created in this runtime.
  @override
  Future<BiometricStorageFile> getStorage(
    String name, {
    StorageFileInitOptions? options,
    bool forceInit = false,
    PromptInfo promptInfo = PromptInfo.defaultValues,
  }) async {
    try {
      final result = await _channel.invokeMethod<bool>(
        'init',
        {
          'name': name,
          'options': options?.toJson() ?? StorageFileInitOptions().toJson(),
          'forceInit': forceInit,
        },
      );
      _logger.finest('getting storage. was created: $result');
      return BiometricStorageFile(
        this,
        name,
        promptInfo,
      );
    } catch (e, stackTrace) {
      _logger.warning(
          'Error while initializing biometric storage.', e, stackTrace);
      rethrow;
    }
  }

  // @override
  // Future<String?> read(
  //   String name,
  //   PromptInfo promptInfo,
  // ) =>
  //     _transformErrors(_channel.invokeMethod<String>('read', <String, dynamic>{
  //       'name': name,
  //       ..._promptInfoForCurrentPlatform(promptInfo),
  //     }));

  // @override
  // Future<bool?> delete(
  //   String name,
  //   PromptInfo promptInfo,
  // ) =>
  //     _transformErrors(_channel.invokeMethod<bool>('delete', <String, dynamic>{
  //       'name': name,
  //       ..._promptInfoForCurrentPlatform(promptInfo),
  //     }));

  // @override
  // Future<void> write(
  //   String name,
  //   String content,
  //   PromptInfo promptInfo,
  // ) =>
  //     _transformErrors(_channel.invokeMethod('write', <String, dynamic>{
  //       'name': name,
  //       'content': content,
  //       ..._promptInfoForCurrentPlatform(promptInfo),
  //     }));

  @override
  Future<BiometricResponse> write(String name, String content, PromptInfo promptInfo) async {
    final result = await _channel.invokeMethod('write', <String, dynamic>{
      'name': name,
      'content': content,
      ..._promptInfoForCurrentPlatform(promptInfo),
    });
    _logger.finer('testWrite--result回调:$result');
    return _handleResult(result);
  }

  @override
  Future<BiometricResponse> read(String name, PromptInfo promptInfo) async {
    final result = await _channel.invokeMethod('read', <String, dynamic>{
      'name': name,
      ..._promptInfoForCurrentPlatform(promptInfo),
    });
    _logger.finer('testRead--result回调:$result');
    return _handleResult(result);
  }

  @override
  Future<BiometricResponse> delete(String name, PromptInfo promptInfo) async {
    final result = await _channel.invokeMethod('delete', <String, dynamic>{
      'name': name,
      ..._promptInfoForCurrentPlatform(promptInfo),
    });
    _logger.finer('testDelete--result回调:$result');
    return _handleResult(result);
  }

  BiometricResponse _handleResult(dynamic response) {
    if (Platform.isIOS) {
      final Map<Object?, Object?> result = response as Map<Object?, Object?>;
      final int code = result['errorCode'] as int;
      final bool success = result['succeed'] == 1 ? true : false;
      final String? dataStr = result['data'] as String;
      var errorCode = BiometricErrorCode.errorUnKnow;
      if (code == 1) {
        errorCode = BiometricErrorCode.touchIDNotEnrolled;
      } else if (code == 2) {
        errorCode = BiometricErrorCode.faceIDNotEnrolled;
      } else if (code == 3) {
        errorCode = BiometricErrorCode.biometricNotEnrolled;
      } else if (code == 4) {
        errorCode = BiometricErrorCode.touchIDLockout;
      } else if (code == 5) {
        errorCode = BiometricErrorCode.faceIDLockout;
      } else if (code == 6) {
        errorCode = BiometricErrorCode.biometricLockout;
      } else if (code == 7) {
        errorCode = BiometricErrorCode.touchIDChange;
      } else if (code == 8) {
        errorCode = BiometricErrorCode.faceIDChange;
      } else if (code == 9) {
        errorCode = BiometricErrorCode.userCancel;
      } else if (code == 10) {
        errorCode = BiometricErrorCode.passcodeNotSet;
      } else if (code == 11) {
        errorCode = BiometricErrorCode.biometricClosed;
      } else if (code == 12) {
        errorCode = BiometricErrorCode.fileNotExist;
      } else if (code == 13) {
        errorCode = BiometricErrorCode.timeOut;
      } else if (code == 100) {
        errorCode = BiometricErrorCode.errorKeyChain;
      }
      return BiometricResponse(
          success: success, errorCode: errorCode, data: dataStr);
    }
    ///TODO: 安卓处理返回转换
    return const BiometricResponse(
      success: false,
      errorCode: BiometricErrorCode.errorUnKnow,
    );
  }

  Map<String, dynamic> _promptInfoForCurrentPlatform(PromptInfo promptInfo) {
    // Don't expose Android configurations to other platforms
    if (Platform.isAndroid) {
      return <String, dynamic>{
        'androidPromptInfo': promptInfo.androidPromptInfo._toJson()
      };
    } else if (Platform.isIOS) {
      return <String, dynamic>{
        'iosPromptInfo': promptInfo.iosPromptInfo._toJson()
      };
    } else if (Platform.isMacOS) {
      return <String, dynamic>{
        // This is no typo, we use the same implementation on iOS and MacOS,
        // so we use the same parameter.
        'iosPromptInfo': promptInfo.macOsPromptInfo._toJson()
      };
    } else if (Platform.isLinux) {
      return <String, dynamic>{};
    } else {
      // Windows has no method channel implementation
      // Web has a Noop implementation.
      throw StateError('Unsupported Platform ${Platform.operatingSystem}');
    }
  }

  Future<T> _transformErrors<T>(Future<T> future) =>
      future.catchError((Object error, StackTrace stackTrace) {
        if (error is PlatformException) {
          _logger.finest(
              'Error during plugin operation (details: ${error.details})',
              error,
              stackTrace);
          if (error.code.startsWith('AuthError:')) {
            return Future<T>.error(
              AuthException(
                _authErrorCodeMapping[error.code] ?? AuthExceptionCode.unknown,
                error.message ?? 'Unknown error',
              ),
              stackTrace,
            );
          }
          if (error.details is Map) {
            final message = error.details['message'] as String;
            if (message.contains('org.freedesktop.DBus.Error.AccessDenied') ||
                message.contains('AppArmor')) {
              _logger.fine('Got app armor error.');
              return Future<T>.error(
                  AuthException(
                      AuthExceptionCode.linuxAppArmorDenied, error.message!),
                  stackTrace);
            }
          }
        }
        return Future<T>.error(error, stackTrace);
      });
}

class BiometricStorageFile {
  BiometricStorageFile(this._plugin, this.name, this.defaultPromptInfo);

  final BiometricStorage _plugin;
  final String name;
  final PromptInfo defaultPromptInfo;

  /// read from the secure file and returns the content.
  /// Will return `null` if file does not exist.
  // Future<String?> read({PromptInfo? promptInfo}) =>
  //     _plugin.read(name, promptInfo ?? defaultPromptInfo);

  // /// Write content of this file. Previous value will be overwritten.
  // Future<void> write(String content, {PromptInfo? promptInfo}) =>
  //     _plugin.write(name, content, promptInfo ?? defaultPromptInfo);

  // /// Delete the content of this storage.
  // Future<void> delete({PromptInfo? promptInfo}) =>
  //     _plugin.delete(name, promptInfo ?? defaultPromptInfo);

  // Future<void> testWrite(String content, {PromptInfo? promptInfo}) =>
  //     _plugin.testWrite(name, content, promptInfo ?? defaultPromptInfo);

  // Future<void> testRead({PromptInfo? promptInfo}) =>
  //     _plugin.testRead(name, promptInfo ?? defaultPromptInfo);

  // Future<void> testDelete({PromptInfo? promptInfo}) =>
  //     _plugin.testDelete(name, promptInfo ?? defaultPromptInfo);
}
