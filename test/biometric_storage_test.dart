import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:joy_biometric_storage/biometric_storage.dart';

void main() {
  const channel = MethodChannel('biometric_storage');

  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    channel.setMockMethodCallHandler((MethodCall methodCall) async {
      if (methodCall.method == 'canAuthenticate') {
        return 'ErrorUnknown';
      }
      throw PlatformException(code: 'NotImplemented');
    });
  });

  tearDown(() {
    channel.setMockMethodCallHandler(null);
  });

  test('canAuthenticate', () async {
    final result = await BiometricStorage().canAuthenticate();
    expect(result, CanAuthenticateResponse.unsupported);
  });
}
