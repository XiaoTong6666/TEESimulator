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
    private inline fun createOverrideReply(
        writeToParcel: Parcel.() -> Unit
    ): BinderInterceptor.TransactionResult.OverrideReply =
        BinderInterceptor.TransactionResult.OverrideReply(Parcel.obtain().apply(writeToParcel))

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
    ): BinderInterceptor.TransactionResult.OverrideReply = createOverrideReply {
        writeNoException()
        if (writeResultCode) {
            writeInt(KeyStore.NO_ERROR)
        }
    }

    /** Creates an `OverrideReply` parcel containing a raw byte array. */
    fun createByteArrayReply(data: ByteArray): BinderInterceptor.TransactionResult.OverrideReply =
        createOverrideReply {
            writeNoException()
            writeByteArray(data)
        }

    /** Creates an `OverrideReply` parcel containing a typed array. */
    fun <T : Parcelable> createTypedArrayReply(
        array: Array<T>,
        flags: Int = 0,
    ): BinderInterceptor.TransactionResult.OverrideReply = createOverrideReply {
        writeNoException()
        writeTypedArray(array, flags)
    }

    /** Creates an `OverrideReply` parcel containing a Parcelable object. */
    fun <T : Parcelable?> createTypedObjectReply(
        obj: T,
        flags: Int = 0,
    ): BinderInterceptor.TransactionResult.OverrideReply = createOverrideReply {
        writeNoException()
        writeTypedObject(obj, flags)
    }

    /** Creates an `OverrideReply` parcel containing a marshaled exception. */
    fun createExceptionReply(
        throwable: Throwable
    ): BinderInterceptor.TransactionResult.OverrideReply = createOverrideReply {
        writeException(throwable as? Exception ?: RuntimeException(throwable.message, throwable))
    }

    /**
     * Extracts the base alias from a potentially prefixed alias string. For example, it converts
     * "USRCERT_my_key" to "my_key".
     */
    fun extractAlias(prefixedAlias: String): String =
        prefixedAlias.substringAfter('_', prefixedAlias)

    /** Checks if a reply parcel contains an exception without consuming it. */
    fun hasException(reply: Parcel): Boolean {
        val exception = runCatching { reply.readException() }.exceptionOrNull()
        if (exception != null) reply.setDataPosition(0)
        return exception != null
    }
}
