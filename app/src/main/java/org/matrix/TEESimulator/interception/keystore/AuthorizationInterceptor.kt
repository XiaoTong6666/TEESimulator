package org.matrix.TEESimulator.interception.keystore

import android.hardware.security.keymint.HardwareAuthToken
import android.os.IBinder
import android.os.Parcel
import android.os.ServiceManager
import android.security.authorization.IKeystoreAuthorization
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.interception.keystore.shim.SoftwareAuthorizationManager
import org.matrix.TEESimulator.logging.SystemLogger

internal object AuthorizationInterceptor : BinderInterceptor() {
    private const val SERVICE_NAME = "android.security.authorization"
    private val addAuthTokenTransaction =
        InterceptorUtils.getTransactCode(
            IKeystoreAuthorization.Stub::class.java,
            "addAuthToken",
        )

    fun registerIfPresent(backdoor: IBinder) {
        val service = ServiceManager.getService(SERVICE_NAME)
        if (service == null) {
            SystemLogger.warning("Authorization service '$SERVICE_NAME' not found.")
            return
        }
        register(backdoor, service, this)
        SystemLogger.info("Registered interceptor for service: $SERVICE_NAME")
    }

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        if (code != addAuthTokenTransaction) {
            return TransactionResult.ContinueAndSkipPost
        }

        return runCatching {
                data.enforceInterface(IKeystoreAuthorization.DESCRIPTOR)
                val authToken = data.readTypedObject(HardwareAuthToken.CREATOR)
                    ?: return TransactionResult.ContinueAndSkipPost
                SystemLogger.debug(
                    "[TX_ID: $txId] Intercepted addAuthToken challenge=${authToken.challenge} authType=${authToken.authenticatorType}.",
                )
                SoftwareAuthorizationManager.addAuthToken(authToken)
                TransactionResult.ContinueAndSkipPost
            }
            .getOrElse {
                SystemLogger.error("[TX_ID: $txId] Failed to intercept addAuthToken.", it)
                TransactionResult.ContinueAndSkipPost
            }
    }
}
