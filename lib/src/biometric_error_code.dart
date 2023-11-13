enum BiometricErrorCode {
  /// 设置中关闭了生物识别
  biometricClosed,

  /// 未录入指纹
  touchIDNotEnrolled,

  /// 未录入面容
  faceIDNotEnrolled,

  /// 未录入生物信息
  biometricNotEnrolled,

  /// 未设置密码
  passcodeNotSet,

  /// 验证设备密码以解锁指纹
  touchIDLockout,

  /// 验证设备密码以解锁面容
  faceIDLockout,

  /// 验证设备密码以解锁
  biometricLockout,

  /// 指纹发生变更
  touchIDChange,

  /// 面容发生变更
  faceIDChange,

  /// 用户点击取消
  userCancel,

  /// 未知错误
  errorUnKnow,

  ///生物识别失效
  fileNotExist,

  ///超时
  timeOut,

  ///android生物识别信息变更
  biometricChange,

  /// KeyChain错误
  errorKeyChain
}