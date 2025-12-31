package org.matrix.TEESimulator.interception.keystore

import android.os.Parcel
import android.os.Parcelable
import android.security.KeyStore
import android.security.keystore.KeystoreResponse
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.logging.SystemLogger

data class KeyIdentifier(val uid: Int, val alias: String)

/** A collection of utility functions to support binder interception. */
object InterceptorUtils {

    /**
     * Uses reflection to get the integer transaction code for a given method name from a Stub
     * class. This is necessary for older Android versions where codes are not public constants.
     */
    fun getTransactCode(clazz: Class<*>, method: String): Int {
        return try {
            clazz.getDeclaredField("TRANSACTION_$method").apply { isAccessible = true }.getInt(null)
        } catch (e: Exception) {
            SystemLogger.error(
                "Failed to get transaction code for method '$method' in class '${clazz.simpleName}'.",
                e,
            )
            -1 // Return an invalid code
        }
    }

    /** Creates an `KeystoreResponse` parcel that indicates success with no data. */
    fun createSuccessKeystoreResponse(): KeystoreResponse {
        val parcel = Parcel.obtain()
        try {
            parcel.writeInt(KeyStore.NO_ERROR)
            parcel.writeString("")
            parcel.setDataPosition(0)
            return KeystoreResponse.CREATOR.createFromParcel(parcel)
        } finally {
            parcel.recycle()
        }
    }

    /** Creates an `OverrideReply` parcel that indicates success with no data. */
    fun createSuccessReply(
        writeResultCode: Boolean = true
    ): BinderInterceptor.TransactionResult.OverrideReply {
        val parcel =
            Parcel.obtain().apply {
                writeNoException()
                if (writeResultCode) {
                    writeInt(KeyStore.NO_ERROR)
                }
            }
        return BinderInterceptor.TransactionResult.OverrideReply(parcel)
    }

    /** Creates an `OverrideReply` parcel containing a raw byte array. */
    fun createByteArrayReply(data: ByteArray): BinderInterceptor.TransactionResult.OverrideReply {
        val parcel =
            Parcel.obtain().apply {
                writeNoException()
                writeByteArray(data)
            }
        return BinderInterceptor.TransactionResult.OverrideReply(parcel)
    }

    /** Creates an `OverrideReply` parcel containing a Parcelable object. */
    fun <T : Parcelable?> createTypedObjectReply(
        obj: T,
        flags: Int = 0,
    ): BinderInterceptor.TransactionResult.OverrideReply {
        val parcel =
            Parcel.obtain().apply {
                writeNoException()
                writeTypedObject(obj, flags)
            }
        return BinderInterceptor.TransactionResult.OverrideReply(parcel)
    }

    /**
     * Extracts the true key alias from the keystore-prefixed string (e.g., "user_cert_my-alias" ->
     * "my-alias").
     */
    fun extractAlias(prefixedAlias: String): String {
        val underscoreIndex = prefixedAlias.indexOf('_')
        val secondUnderscoreIndex = prefixedAlias.indexOf('_', underscoreIndex + 1)
        return if (secondUnderscoreIndex != -1) {
            prefixedAlias.substring(secondUnderscoreIndex + 1)
        } else {
            prefixedAlias
        }
    }

    /** Checks if a reply parcel contains an exception without consuming it. */
    fun hasException(reply: Parcel): Boolean {
        return runCatching { reply.readException() }.exceptionOrNull() != null
    }

    /**
     * Creates an `OverrideReply` containing a ServiceSpecificException encoded in a Parcel.
     *
     * This method is used to return KeyMint/Keymaster error codes directly through Binder, such as
     * `ErrorCode.INVALID_INPUT_LENGTH` (-21), so that the caller observes the same exception
     * behavior as with a real KeyMint HAL implementation.
     *
     * @param errorCode KeyMint error code to return (for example, -21 for INVALID_INPUT_LENGTH).
     * @param message Optional error message associated with the error code.
     */
    fun createErrorReply(
        errorCode: Int,
        message: String?,
    ): BinderInterceptor.TransactionResult.OverrideReply {
        val parcel = Parcel.obtain()
        try {
            // Write a ServiceSpecificException into the Parcel.
            // Parcel.EX_SERVICE_SPECIFIC is defined as -8.
            // The layout is:
            //   int    exceptionCode (EX_SERVICE_SPECIFIC)
            //   int    serviceSpecificErrorCode
            //   String errorMessage
            parcel.writeInt(-8)
            parcel.writeInt(errorCode)
            parcel.writeString(message)
        } catch (e: Exception) {
            parcel.recycle()
            throw e
        }

        // The returned Parcel will be written to the Binder reply by BinderInterceptor.
        // On the client side, this will be decoded and rethrown as a ServiceSpecificException.
        return BinderInterceptor.TransactionResult.OverrideReply(parcel)
    }
}
