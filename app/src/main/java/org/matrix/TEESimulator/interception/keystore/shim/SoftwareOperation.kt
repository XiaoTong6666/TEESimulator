package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.BlockMode
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.PaddingMode
import android.os.RemoteException
import android.os.ServiceSpecificException
import android.security.keymaster.KeymasterDefs
import android.system.keystore2.IKeystoreOperation
import java.security.KeyPair
import java.security.Signature
import java.security.SignatureException
import javax.crypto.Cipher
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.logging.KeyMintParameterLogger
import org.matrix.TEESimulator.logging.SystemLogger

private const val MAX_RECEIVE_DATA = 0x8000
private const val TOO_MUCH_DATA_FALLBACK = 29
private val TOO_MUCH_DATA_ERROR_CODE: Int by lazy {
    runCatching {
            val responseCode = Class.forName("android.system.keystore2.ResponseCode")
            responseCode.getField("TOO_MUCH_DATA").getInt(null)
        }
        .getOrDefault(TOO_MUCH_DATA_FALLBACK)
}

// A sealed interface to represent the different cryptographic operations we can perform.
private sealed interface CryptoPrimitive {
    fun updateAad(data: ByteArray?) {
        throw ServiceSpecificException(
            KeymasterDefs.KM_ERROR_INVALID_ARGUMENT,
            "AAD not supported for this operation",
        )
    }

    fun update(data: ByteArray?): ByteArray?

    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray?

    fun abort()
}

// Helper object to map KeyMint constants to JCA algorithm strings.
private object JcaAlgorithmMapper {
    fun mapSignatureAlgorithm(params: KeyMintAttestation): String {
        val digestValue =
            params.digest.requireExactlyOneValue(
                KeymasterDefs.KM_ERROR_UNSUPPORTED_DIGEST,
                "digest",
            )
        val digest =
            when (digestValue) {
                Digest.SHA_2_256 -> "SHA256"
                Digest.SHA_2_384 -> "SHA384"
                Digest.SHA_2_512 -> "SHA512"
                Digest.NONE -> "NONE"
                else ->
                    throw ServiceSpecificException(
                        KeymasterDefs.KM_ERROR_UNSUPPORTED_DIGEST,
                        "Unsupported digest: $digestValue",
                    )
            }
        val keyAlgo =
            when (params.algorithm) {
                Algorithm.EC -> "ECDSA"
                Algorithm.RSA -> "RSA"
                else ->
                    throw ServiceSpecificException(
                        KeymasterDefs.KM_ERROR_UNSUPPORTED_ALGORITHM,
                        "Unsupported signature algorithm: ${params.algorithm}",
                    )
            }
        return "${digest}with${keyAlgo}"
    }

    fun mapCipherAlgorithm(params: KeyMintAttestation): String {
        val blockModeValue =
            params.blockMode.requireAtMostOneValue(
                KeymasterDefs.KM_ERROR_UNSUPPORTED_BLOCK_MODE,
                "block mode",
            )
        val paddingValue =
            params.padding.requireExactlyOneValue(
                KeymasterDefs.KM_ERROR_UNSUPPORTED_PADDING_MODE,
                "padding mode",
            )
        val resolvedBlockMode =
            when (params.algorithm) {
                Algorithm.RSA -> blockModeValue ?: BlockMode.ECB
                else ->
                    blockModeValue
                        ?: throw ServiceSpecificException(
                            KeymasterDefs.KM_ERROR_UNSUPPORTED_BLOCK_MODE,
                            "No block mode specified",
                        )
            }
        val keyAlgo =
            when (params.algorithm) {
                Algorithm.RSA -> "RSA"
                Algorithm.AES -> "AES"
                else ->
                    throw ServiceSpecificException(
                        KeymasterDefs.KM_ERROR_UNSUPPORTED_ALGORITHM,
                        "Unsupported cipher algorithm: ${params.algorithm}",
                    )
            }
        val blockMode =
            when (resolvedBlockMode) {
                BlockMode.ECB -> "ECB"
                BlockMode.CBC -> "CBC"
                BlockMode.GCM -> "GCM"
                else ->
                    throw ServiceSpecificException(
                        KeymasterDefs.KM_ERROR_UNSUPPORTED_BLOCK_MODE,
                        "Unsupported block mode: $resolvedBlockMode",
                    )
            }
        val padding =
            when (paddingValue) {
                PaddingMode.NONE -> "NoPadding"
                PaddingMode.PKCS7 -> "PKCS7Padding"
                PaddingMode.RSA_PKCS1_1_5_ENCRYPT -> "PKCS1Padding"
                PaddingMode.RSA_OAEP -> "OAEPPadding"
                else ->
                    throw ServiceSpecificException(
                        KeymasterDefs.KM_ERROR_UNSUPPORTED_PADDING_MODE,
                        "Unsupported padding mode: $paddingValue",
                    )
            }
        return "$keyAlgo/$blockMode/$padding"
    }
}

// Concrete implementation for Signing.
private class Signer(keyPair: KeyPair, params: KeyMintAttestation) : CryptoPrimitive {
    private val signature: Signature =
        Signature.getInstance(JcaAlgorithmMapper.mapSignatureAlgorithm(params)).apply {
            initSign(keyPair.private)
        }

    override fun update(data: ByteArray?): ByteArray? {
        data?.let(signature::update)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray {
        if (data != null) update(data)
        return this.signature.sign()
    }

    override fun abort() {}
}

// Concrete implementation for Verification.
private class Verifier(keyPair: KeyPair, params: KeyMintAttestation) : CryptoPrimitive {
    private val signature: Signature =
        Signature.getInstance(JcaAlgorithmMapper.mapSignatureAlgorithm(params)).apply {
            initVerify(keyPair.public)
        }

    override fun update(data: ByteArray?): ByteArray? {
        data?.let(signature::update)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        if (data != null) update(data)
        if (signature == null) {
            throw ServiceSpecificException(
                KeymasterDefs.KM_ERROR_INVALID_ARGUMENT,
                "Signature to verify is null",
            )
        }
        if (!this.signature.verify(signature)) {
            throw ServiceSpecificException(
                KeymasterDefs.KM_ERROR_VERIFICATION_FAILED,
                "Signature verification failed",
            )
        }
        // A successful verification returns no data.
        return null
    }

    override fun abort() {}
}

// Concrete implementation for Encryption/Decryption.
private class CipherPrimitive(
    keyPair: KeyPair,
    params: KeyMintAttestation,
    private val opMode: Int,
) : CryptoPrimitive {
    private val cipher: Cipher =
        Cipher.getInstance(JcaAlgorithmMapper.mapCipherAlgorithm(params)).apply {
            val key = if (opMode == Cipher.ENCRYPT_MODE) keyPair.public else keyPair.private
            init(opMode, key)
        }

    override fun updateAad(data: ByteArray?) {
        data?.let(cipher::updateAAD)
    }

    override fun update(data: ByteArray?): ByteArray? =
        if (data != null) cipher.update(data) else null

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? =
        if (data != null) cipher.doFinal(data) else cipher.doFinal()

    override fun abort() {}
}

/**
 * A software-only implementation of a cryptographic operation. This class acts as a controller,
 * delegating to a specific cryptographic primitive based on the operation's purpose.
 */
class SoftwareOperation(private val txId: Long, keyPair: KeyPair, params: KeyMintAttestation) {
    private val primitive: CryptoPrimitive
    private val stateLock = Any()
    private var finalized = false

    init {
        // The "Strategy" pattern: choose the implementation based on the purpose.
        // For simplicity, we only consider the first purpose listed.
        val purpose = params.purpose.firstOrNull()
        val purposeName = KeyMintParameterLogger.purposeNames[purpose] ?: "UNKNOWN"
        SystemLogger.debug("[SoftwareOp TX_ID: $txId] Initializing for purpose: $purposeName.")

        if (
            (purpose == KeyPurpose.VERIFY || purpose == KeyPurpose.ENCRYPT) &&
                (params.algorithm == Algorithm.RSA || params.algorithm == Algorithm.EC)
        ) {
            throw ServiceSpecificException(
                KeymasterDefs.KM_ERROR_UNSUPPORTED_PURPOSE,
                "Public operations on asymmetric keys are not supported",
            )
        }

        primitive =
            when (purpose) {
                KeyPurpose.SIGN -> Signer(keyPair, params)
                KeyPurpose.VERIFY -> Verifier(keyPair, params)
                KeyPurpose.ENCRYPT -> CipherPrimitive(keyPair, params, Cipher.ENCRYPT_MODE)
                KeyPurpose.DECRYPT -> CipherPrimitive(keyPair, params, Cipher.DECRYPT_MODE)
                else ->
                    throw ServiceSpecificException(
                        KeymasterDefs.KM_ERROR_UNSUPPORTED_PURPOSE,
                        "Unsupported operation purpose: $purpose",
                    )
            }
    }

    fun updateAad(data: ByteArray?) =
        runOperation("updateAad", markFinalized = false, data = data) { primitive.updateAad(data) }

    fun update(data: ByteArray?): ByteArray? =
        runOperation("update", markFinalized = false, data = data) { primitive.update(data) }

    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? =
        runOperation("finish", markFinalized = true, data = data) {
            primitive.finish(data, signature)
        }

    fun abort() {
        synchronized(stateLock) {
            ensureActiveLocked()
            finalizeOperationLocked()
        }
        primitive.abort()
        SystemLogger.debug("[SoftwareOp TX_ID: $txId] Operation aborted.")
    }

    private fun <T> runOperation(
        name: String,
        markFinalized: Boolean,
        data: ByteArray?,
        block: () -> T,
    ): T {
        synchronized(stateLock) {
            ensureActiveLocked()
            checkInputLength(data)
        }

        return try {
            val result = block()
            if (markFinalized) {
                finalizeOperation()
                SystemLogger.info("[SoftwareOp TX_ID: $txId] Finished operation successfully.")
            }
            result
        } catch (e: ServiceSpecificException) {
            finalizeOperation()
            SystemLogger.warning("[SoftwareOp TX_ID: $txId] $name failed with service error.", e)
            throw e
        } catch (e: SignatureException) {
            finalizeOperation()
            SystemLogger.warning("[SoftwareOp TX_ID: $txId] $name failed with signature error.", e)
            throw ServiceSpecificException(
                KeymasterDefs.KM_ERROR_VERIFICATION_FAILED,
                e.message ?: "$name failed",
            )
        } catch (e: Exception) {
            finalizeOperation()
            SystemLogger.error("[SoftwareOp TX_ID: $txId] Failed to $name operation.", e)
            throw ServiceSpecificException(
                KeymasterDefs.KM_ERROR_INVALID_ARGUMENT,
                e.message ?: "$name failed",
            )
        }
    }

    private fun finalizeOperation() {
        synchronized(stateLock) { finalizeOperationLocked() }
    }

    private fun finalizeOperationLocked() {
        finalized = true
    }

    private fun ensureActiveLocked() {
        if (finalized) {
            throw ServiceSpecificException(
                KeymasterDefs.KM_ERROR_INVALID_OPERATION_HANDLE,
                "Operation is no longer active",
            )
        }
    }

    private fun checkInputLength(data: ByteArray?) {
        if (data != null && data.size > MAX_RECEIVE_DATA) {
            throw ServiceSpecificException(
                TOO_MUCH_DATA_ERROR_CODE,
                "Input exceeds $MAX_RECEIVE_DATA bytes",
            )
        }
    }
}

/** The Binder interface for our [SoftwareOperation]. */
class SoftwareOperationBinder(private val operation: SoftwareOperation) :
    IKeystoreOperation.Stub() {

    @Throws(RemoteException::class)
    override fun updateAad(aadInput: ByteArray?) {
        operation.updateAad(aadInput)
    }

    @Throws(RemoteException::class)
    override fun update(input: ByteArray?): ByteArray? {
        return operation.update(input)
    }

    @Throws(RemoteException::class)
    override fun finish(input: ByteArray?, signature: ByteArray?): ByteArray? {
        return operation.finish(input, signature)
    }

    @Throws(RemoteException::class)
    override fun abort() {
        operation.abort()
    }
}
