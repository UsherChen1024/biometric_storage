package design.codeux.biometric_storage

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.os.*
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import androidx.annotation.AnyThread
import androidx.annotation.UiThread
import androidx.annotation.WorkerThread
import androidx.biometric.*
import androidx.biometric.BiometricManager.Authenticators.*
import androidx.fragment.app.FragmentActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.*
import io.flutter.plugin.common.*
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.github.oshai.kotlinlogging.KotlinLogging
import java.io.File
import java.io.IOException
import java.io.PrintWriter
import java.io.StringWriter
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import javax.crypto.Cipher

private val logger = KotlinLogging.logger {}

/// 设备生物特征识别错误码
object JdtCode {
    /// 未录入指纹
    val TouchIDNotEnrolled = 1

    /// 未录入面容
    val FaceIDNotEnrolled = 2

    /// 未录入生物信息
    val NotEnrolled = 3

    /// 验证设备密码以解锁指纹
    val TouchIDLockout = 4

    /// 验证设备密码以解锁面容
    val FaceIDLockout = 5

    /// 验证设备密码以解锁
    val Lockout = 6

    /// 指纹发生变更
    val TouchIDChange = 7

    /// 面容发生变更
    val FaceIDChange = 8

    /// 用户点击取消
    val UserCancel = 9

    /// 未设置密码
    val PasscodeNotSet = 10

    /// 用户在设置里关闭了面容、指纹
    val Closed = 11

    //保存token的文件丢失, 生物识别失效
    val FileNotExist = 12

    val TimeOut = 13    //超时

    //生物识别信息发生变更
    val BiometricChange = 14

    /// 未知错误
    val UnKnow = 99

    /// KeyChain错误
    val KeyChain = 100

    val JDT_SUCCESS = 10000
}


enum class CipherMode {
    Encrypt,
    Decrypt,
}

typealias ErrorCallback = (errorInfo: AuthenticationErrorInfo) -> Unit

class MethodCallException(
    val errorCode: String,
    val errorMessage: String?,
    val errorDetails: Any? = null
) : Exception(errorMessage ?: errorCode)

@Suppress("unused")
enum class CanAuthenticateResponse(val code: Int) {
    Success(BiometricManager.BIOMETRIC_SUCCESS),
    ErrorHwUnavailable(BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE),
    ErrorNoBiometricEnrolled(BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED),
    ErrorNoHardware(BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE),
    ErrorStatusUnknown(BiometricManager.BIOMETRIC_STATUS_UNKNOWN),
    ErrorPasscodeNotSet(-99),
    ;

    override fun toString(): String {
        return "CanAuthenticateResponse.${name}: $code"
    }
}

@Suppress("unused")
enum class AuthenticationError(vararg val code: Int) {
    Canceled(BiometricPrompt.ERROR_CANCELED),
    Timeout(BiometricPrompt.ERROR_TIMEOUT),
    UserCanceled(BiometricPrompt.ERROR_USER_CANCELED, BiometricPrompt.ERROR_NEGATIVE_BUTTON),
    Unknown(-1),

    /** Authentication valid, but unknown */
    Failed(-2),
    ;

    companion object {
        fun forCode(code: Int) =
            values().firstOrNull { it.code.contains(code) } ?: Unknown
    }
}

data class AuthenticationErrorInfo(
    val error: Int,
    val message: CharSequence,
    val errorDetails: String? = null
) {
    constructor(
        error: Int,
        message: CharSequence,
        e: Throwable
    ) : this(error, message, e.toCompleteString())
}

private fun Throwable.toCompleteString(): String {
    val out = StringWriter().let { out ->
        printStackTrace(PrintWriter(out))
        out.toString()
    }
    return "$this\n$out"
}

class BiometricStoragePlugin : FlutterPlugin, ActivityAware, MethodCallHandler {

    companion object {
        const val PARAM_NAME = "name"
        const val PARAM_WRITE_CONTENT = "content"
        const val PARAM_ANDROID_PROMPT_INFO = "androidPromptInfo"

        private const val DIRECTORY_NAME = "biometric_storage"
        private const val FILE_SUFFIX_V2 = ".v2.txt"
    }

    private val cryptographyManager = CryptographyManager {
        setUserAuthenticationRequired(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val useStrongBox = applicationContext.packageManager.hasSystemFeature(
                PackageManager.FEATURE_STRONGBOX_KEYSTORE
            )
            setIsStrongBoxBacked(useStrongBox)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG
            )
        } else {
            @Suppress("DEPRECATION")
            setUserAuthenticationValidityDurationSeconds(-1)
        }
    }

    private val executor: ExecutorService by lazy { Executors.newSingleThreadExecutor() }
    private val handler: Handler by lazy { Handler(Looper.getMainLooper()) }


    private var attachedActivity: FragmentActivity? = null

    private val storageFiles = mutableMapOf<String, BiometricStorageFile>()

    private val biometricManager by lazy { BiometricManager.from(applicationContext) }

    private lateinit var applicationContext: Context

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        this.applicationContext = binding.applicationContext
        val channel = MethodChannel(binding.binaryMessenger, "biometric_storage")
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        executor.shutdown()
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        logger.trace { "onMethodCall(${call.method})" }
        try {
            fun <T> requiredArgument(name: String) =
                call.argument<T>(name) ?: throw MethodCallException(
                    "MissingArgument",
                    "Missing required argument '$name'"
                )

            // every method call requires the name of the stored file.
            val getName = { requiredArgument<String>(PARAM_NAME) }
            val getAndroidPromptInfo = {
                requiredArgument<Map<String, Any>>(PARAM_ANDROID_PROMPT_INFO).let {
                    AndroidPromptInfo(
                        title = it["title"] as String,
                        subtitle = it["subtitle"] as String?,
                        description = it["description"] as String?,
                        negativeButton = it["negativeButton"] as String,
                        confirmationRequired = it["confirmationRequired"] as Boolean,
                    )
                }
            }

            fun withStorage(cb: BiometricStorageFile.() -> Unit) {
                val name = getName()
                storageFiles[name]?.apply(cb) ?: run {
                    logger.warn { "User tried to access storage '$name', before initialization" }
                    result.error("Storage $name was not initialized.", null, null)
                    return
                }
            }

            val resultError: ErrorCallback = { errorInfo ->

                result.error(
                    "AuthError:${errorInfo.error}",
                    errorInfo.message.toString(),
                    errorInfo.errorDetails
                )
                logger.error("AuthError: $errorInfo")

            }

            @UiThread
            fun BiometricStorageFile.withAuth(
                mode: CipherMode,
                @WorkerThread cb: BiometricStorageFile.(cipher: Cipher?) -> Unit
            ) {
                if (!options.authenticationRequired) {
                    return cb(null)
                }

                fun cipherForMode() = when (mode) {
                    CipherMode.Encrypt -> cipherForEncrypt()
                    CipherMode.Decrypt -> cipherForDecrypt()
                }

                val cipher = if (options.authenticationValidityDurationSeconds > -1) {
                    null
                } else try {
                    cipherForMode()
                } catch (e: KeyPermanentlyInvalidatedException) {
                    // TODO should we communicate this to the caller?
                    logger.warn(e) { "Key was invalidated. removing previous storage and recreating." }
                    deleteFile()
                    // if deleting fails, simply throw the second time around.
                    cipherForMode()
                }

                if (cipher == null) {
                    // if we have no cipher, just try the callback and see if the
                    // user requires authentication.
                    try {
                        return cb(null)
                    } catch (e: UserNotAuthenticatedException) {
                        logger.debug(e) { "User requires (re)authentication. showing prompt ..." }
                    }
                }

                val promptInfo = getAndroidPromptInfo()
                authenticate(cipher, promptInfo, options, {
                    cb(cipher)
                }, onError = resultError)
            }

            when (call.method) {
                "canAuthenticate" -> result.success(canAuthenticate().name)
                "getAvailableBiometrics" -> {
                    result.success(getEnrolledBiometrics())
                }

                "dispose" -> storageFiles.remove(getName())?.apply {
                    dispose()
                    result.success(true)
                } ?: throw MethodCallException(
                    "NoSuchStorage",
                    "Tried to dispose non existing storage.",
                    null
                )

                "read" -> {
                    val fileName = getName()
                    val masterKeyName = getMasterKeyName(fileName)
                    val fileV2 = getFileV2(fileName)

                    if (fileV2.exists()) {
                        val cipher = try {
                            cipherForDecrypt(masterKeyName, fileV2)
                        } catch (e: KeyPermanentlyInvalidatedException) {
                            logger.warn(e) { "Key was invalidated. removing previous storage and recreating." }
                            deleteFile(masterKeyName, fileV2)
                            // if deleting fails, simply throw the second time around.
                            //key失效，证明生物识别信息变更。
                            result.success(wrapResult(
                                    JdtCode.BiometricChange,
                            ))
                            return;
                        }

                        val cb = {
                            val ret = readFile(cipher, masterKeyName, fileV2)
                            ui(resultError) {
                                result.success(
                                    wrapResult(
                                        JdtCode.JDT_SUCCESS,
                                        ret!!
                                    )
                                )
                            }
                        }

                        if (cipher == null) {
                            // if we have no cipher, just try the callback and see if the
                            // user requires authentication.
                            try {
                                cb()
                                return
                            } catch (e: UserNotAuthenticatedException) {
                                logger.debug(e) { "User requires (re)authentication. showing prompt ..." }
                            }
                        }

                        val promptInfo = getAndroidPromptInfo()
                        authenticate(cipher, promptInfo, InitOptions(), {
                            cb()
                        }, onError = resultError)

                    } else {
                        result.success(wrapResult(JdtCode.FileNotExist))
                    }

                }

                "delete" -> {
                    val fileName = getName()
                    val masterKeyName = getMasterKeyName(fileName)
                    val fileV2 = getFileV2(fileName)

                    if (fileV2.exists()) {
                        val isSuccess = deleteFile(masterKeyName, fileV2)
                    }
                    result.success(wrapResult(JdtCode.JDT_SUCCESS))
                }

                "write" -> {
                    val fileName = getName()
                    val masterKeyName = getMasterKeyName(fileName)
                    val fileV2 = getFileV2(fileName)

                    val cipher = try {
                        cipherForEncrypt(masterKeyName)
                    } catch (e: KeyPermanentlyInvalidatedException) {
                        logger.warn(e) { "Key was invalidated. removing previous storage and recreating." }
                        deleteFile(masterKeyName, fileV2)
                        // if deleting fails, simply throw the second time around.
                        cipherForEncrypt(masterKeyName)
                    }

                    val cb = {
                        writeFile(cipher, requiredArgument<String>(PARAM_WRITE_CONTENT), masterKeyName, fileV2)
                        ui(resultError) { result.success(wrapResult(
                            JdtCode.JDT_SUCCESS
                        )) }
                    }

                    if (cipher == null) {
                        // if we have no cipher, just try the callback and see if the
                        // user requires authentication.
                        try {
                            cb()
                            return
                        } catch (e: UserNotAuthenticatedException) {
                            logger.debug(e) { "User requires (re)authentication. showing prompt ..." }
                        }
                    }

                    val promptInfo = getAndroidPromptInfo()
                    authenticate(cipher, promptInfo, InitOptions(), {
                        cb()
                    }, onError = resultError)

                }

                else -> result.notImplemented()
            }
        } catch (e: MethodCallException) {
            logger.error(e) { "Error while processing method call ${call.method}" }
            result.error(e.errorCode, e.errorMessage, e.errorDetails)
        } catch (e: Exception) {
            logger.error(e) { "Error while processing method call '${call.method}'" }
            result.error("Unexpected Error", e.message, e.toCompleteString())
        }
    }

    private fun getFileV2(fileName: String): File {
        val fileNameV2 = "$fileName${FILE_SUFFIX_V2}"

        val baseDir = File(applicationContext.filesDir, DIRECTORY_NAME)
        if (!baseDir.exists()) {
            baseDir.mkdirs()
        }

        return File(baseDir, fileNameV2)
    }

    private fun getMasterKeyName(fileName: String): String {
        return "${fileName}_master_key"
    }

    fun cipherForEncrypt(masterKeyName: String) =
        cryptographyManager.getInitializedCipherForEncryption(masterKeyName)

    fun cipherForDecrypt(masterKeyName: String, fileV2: File): Cipher? {
        if (fileV2.exists()) {
            return cryptographyManager.getInitializedCipherForDecryption(masterKeyName, fileV2)
        }
        logger.debug { "No file exists, no IV found. null cipher." }
        return null
    }

    @Synchronized
    fun deleteFile(masterKeyName: String, fileV2: File): Boolean {
        cryptographyManager.deleteKey(masterKeyName)
        return fileV2.delete()
    }

    @Synchronized
    fun readFile(cipher: Cipher?, masterKeyName: String, fileV2: File): String? {
        val useCipher = cipher ?: cipherForDecrypt(masterKeyName, fileV2)
        // if the file exists, there should *always* be a decryption key.
        if (useCipher != null && fileV2.exists()) {
            return try {
                val bytes = fileV2.readBytes()
                logger.debug { "read ${bytes.size}" }
                cryptographyManager.decryptData(bytes, useCipher)
            } catch (ex: IOException) {
                logger.error(ex) { "Error while writing encrypted file $fileV2" }
                null
            }
        }

        logger.debug { "File $fileV2 does not exist. returning null." }
        return null

    }

    @Synchronized
    fun writeFile(cipher: Cipher?, content: String, masterKeyName: String, fileV2: File) {
        // cipher will be null if user does not need authentication or valid period is > -1
        val useCipher = cipher ?: cipherForEncrypt(masterKeyName)
        try {
            val encrypted = cryptographyManager.encryptData(content, useCipher)
            fileV2.writeBytes(encrypted.encryptedPayload)
            logger.debug { "Successfully written ${encrypted.encryptedPayload.size} bytes." }

            return
        } catch (ex: IOException) {
            // Error occurred opening file for writing.
            logger.error(ex) { "Error while writing encrypted file $fileV2" }
            throw ex
        }
    }

    @AnyThread
    private inline fun ui(
        @UiThread crossinline onError: ErrorCallback,
        @UiThread crossinline cb: () -> Unit
    ) = handler.post {
        try {
            cb()
        } catch (e: Throwable) {
            logger.error(e) { "Error while calling UI callback. This must not happen." }
            onError(
                AuthenticationErrorInfo(
                    JdtCode.UnKnow,
                    "Unexpected authentication error. ${e.localizedMessage}",
                )
            )
        }
    }

    private inline fun worker(
        @UiThread crossinline onError: ErrorCallback,
        @WorkerThread crossinline cb: () -> Unit
    ) = executor.submit {
        try {
            cb()
        } catch (e: Throwable) {
            logger.error(e) { "Error while calling worker callback. This must not happen." }
            handler.post {
                onError(
                    AuthenticationErrorInfo(
                        JdtCode.UnKnow,
                        "Unexpected authentication error. ${e.localizedMessage}",
                    )
                )
            }
        }
    }

    private fun canAuthenticate(): CanAuthenticateResponse {
        val credentialsResponse = biometricManager.canAuthenticate(DEVICE_CREDENTIAL);
        logger.debug { "canAuthenticate for DEVICE_CREDENTIAL: $credentialsResponse" }
        if (credentialsResponse == BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED) {
            return CanAuthenticateResponse.Success
        }

        val response = biometricManager.canAuthenticate(
            BIOMETRIC_STRONG or BIOMETRIC_WEAK
        )
        return CanAuthenticateResponse.values().firstOrNull { it.code == response }
            ?: throw Exception(
                "Unknown response code {$response} (available: ${
                    CanAuthenticateResponse
                        .values()
                        .contentToString()
                }"
            )
    }

    private fun getEnrolledBiometrics(): List<String> {
        val biometrics: ArrayList<String> = ArrayList()
        if (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK)
            === BiometricManager.BIOMETRIC_SUCCESS
        ) {
            biometrics.add("weak")
        }
        if (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            === BiometricManager.BIOMETRIC_SUCCESS
        ) {
            biometrics.add("strong")
        }
        return biometrics
    }

    @UiThread
    private fun authenticate(
        cipher: Cipher?,
        promptInfo: AndroidPromptInfo,
        options: InitOptions,
        @WorkerThread onSuccess: (cipher: Cipher?) -> Unit,
        onError: ErrorCallback
    ) {
        logger.trace("authenticate()")
        val activity = attachedActivity ?: return run {
            logger.error { "We are not attached to an activity." }
            onError(
                AuthenticationErrorInfo(
                    JdtCode.UnKnow,
                    "Plugin not attached to any activity."
                )
            )
        }
        val prompt =
            BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    logger.trace("onAuthenticationError($errorCode, $errString)")
                    val jdtErrorCode = when (errorCode) {
                        BiometricPrompt.ERROR_CANCELED, BiometricPrompt.ERROR_USER_CANCELED, BiometricPrompt.ERROR_NEGATIVE_BUTTON -> JdtCode.UserCancel
                        BiometricPrompt.ERROR_TIMEOUT -> JdtCode.TimeOut
                        BiometricPrompt.ERROR_NO_BIOMETRICS -> JdtCode.NotEnrolled
                        else -> JdtCode.UnKnow
                    }
                    ui(onError) {
                        onError(
                            AuthenticationErrorInfo(
                                jdtErrorCode, errString
                            )
                        )
                    }
                }

                @WorkerThread
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    logger.trace("onAuthenticationSucceeded($result)")
                    worker(onError) { onSuccess(result.cryptoObject?.cipher) }
                }

                override fun onAuthenticationFailed() {
                    logger.trace("onAuthenticationFailed()")
                    // this just means the user was not recognised, but the O/S will handle feedback so we don't have to
                }
            })

        val promptBuilder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(promptInfo.title)
            .setSubtitle(promptInfo.subtitle)
            .setDescription(promptInfo.description)
            .setConfirmationRequired(promptInfo.confirmationRequired)

        val biometricOnly =
            options.androidBiometricOnly || Build.VERSION.SDK_INT < Build.VERSION_CODES.R

        if (biometricOnly) {
            if (!options.androidBiometricOnly) {
                logger.debug {
                    "androidBiometricOnly was false, but prior " +
                            "to ${Build.VERSION_CODES.R} this was not supported. ignoring."
                }
            }
            promptBuilder
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .setNegativeButtonText(promptInfo.negativeButton)
        } else {
            promptBuilder.setAllowedAuthenticators(DEVICE_CREDENTIAL or BIOMETRIC_STRONG)
        }

        if (cipher == null || options.authenticationValidityDurationSeconds >= 0) {
            // if authenticationValidityDurationSeconds is not -1 we can't use a CryptoObject
            logger.debug { "Authenticating without cipher. ${options.authenticationValidityDurationSeconds}" }
            prompt.authenticate(promptBuilder.build())
        } else {
            prompt.authenticate(promptBuilder.build(), BiometricPrompt.CryptoObject(cipher))
        }
    }

    override fun onDetachedFromActivity() {
        logger.trace { "onDetachedFromActivity" }
        attachedActivity = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        logger.debug { "Attached to new activity." }
        updateAttachedActivity(binding.activity)
    }

    private fun updateAttachedActivity(activity: Activity) {
        if (activity !is FragmentActivity) {
            logger.error { "Got attached to activity which is not a FragmentActivity: $activity" }
            return
        }
        attachedActivity = activity
    }

    override fun onDetachedFromActivityForConfigChanges() {
    }
}

fun wrapResult(code: Int, data: String = ""): Map<String, Any> {
    return mapOf(
        Pair("errorCode", code),
        Pair("data", data),
        Pair("succeed", if (code == JdtCode.JDT_SUCCESS) 1 else 0)
    )
}

data class AndroidPromptInfo(
    val title: String,
    val subtitle: String?,
    val description: String?,
    val negativeButton: String,
    val confirmationRequired: Boolean
)
