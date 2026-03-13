package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.BlockMode
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.PaddingMode
import android.os.RemoteException
import android.os.ServiceSpecificException
import android.security.keymaster.KeymasterDefs
import android.system.keystore2.IKeystoreOperation
import java.io.ByteArrayOutputStream
import java.security.KeyFactory
import java.security.KeyPair
import java.security.Signature
import java.security.SignatureException
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.KeyAgreement
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.logging.KeyMintParameterLogger
import org.matrix.TEESimulator.logging.SystemLogger

// A sealed interface to represent the different cryptographic operations we can perform.
private sealed interface CryptoPrimitive {
    fun updateAad(data: ByteArray?)

    fun update(data: ByteArray?): ByteArray?

    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray?

    fun abort()
}

// Helper object to map KeyMint constants to JCA algorithm strings.
private object JcaAlgorithmMapper {
    private data class SignatureConfig(
        val algorithm: String,
        val parameterSpec: PSSParameterSpec? = null,
    )

    fun createSignature(params: KeyMintAttestation): Signature {
        val config = mapSignatureConfig(params)
        return Signature.getInstance(config.algorithm, BouncyCastleProvider.PROVIDER_NAME).apply {
            config.parameterSpec?.let { setParameter(it) }
        }
    }

    private fun mapSignatureConfig(params: KeyMintAttestation): SignatureConfig {
        val requestedDigest =
            params.digest.singleOrNull()
                ?: throw IllegalArgumentException("No digest specified for signature operation.")
        return when (params.algorithm) {
            Algorithm.EC ->
                if (params.ecCurve == EcCurve.CURVE_25519) {
                    if (requestedDigest != Digest.NONE) {
                        throw IllegalArgumentException(
                            "Unsupported digest for Ed25519: $requestedDigest"
                        )
                    }
                    SignatureConfig(algorithm = "Ed25519")
                } else {
                    SignatureConfig(algorithm = "${digestToJcaName(requestedDigest)}withECDSA")
                }
            Algorithm.RSA -> {
                when (val requestedPadding = params.padding.singleOrNull()) {
                    null,
                    PaddingMode.RSA_PKCS1_1_5_SIGN ->
                        SignatureConfig(algorithm = "${digestToJcaName(requestedDigest)}withRSA")
                    PaddingMode.NONE ->
                        if (requestedDigest == Digest.NONE) {
                            SignatureConfig(algorithm = "NONEwithRSA")
                        } else {
                            throw IllegalArgumentException(
                                "Digest $requestedDigest is not compatible with RSA padding NONE"
                            )
                        }
                    PaddingMode.RSA_PSS ->
                        SignatureConfig(
                            algorithm = "RSASSA-PSS",
                            parameterSpec =
                                PSSParameterSpec(
                                    digestToPssDigestName(requestedDigest),
                                    "MGF1",
                                    MGF1ParameterSpec(digestToPssDigestName(requestedDigest)),
                                    digestToOutputSizeBytes(requestedDigest),
                                    1,
                                ),
                        )
                    else ->
                        throw IllegalArgumentException(
                            "Unsupported RSA signature padding: $requestedPadding"
                        )
                }
            }
            else ->
                throw IllegalArgumentException(
                    "Unsupported signature algorithm: ${params.algorithm}"
                )
        }
    }

    fun mapCipherAlgorithm(params: KeyMintAttestation): String {
        return when (params.algorithm) {
            Algorithm.RSA -> {
                val padding =
                    when (val requestedPadding = params.padding.singleOrNull()) {
                        PaddingMode.NONE -> "NoPadding"
                        PaddingMode.RSA_PKCS1_1_5_ENCRYPT -> "PKCS1Padding"
                        PaddingMode.RSA_OAEP -> "OAEPPadding"
                        null ->
                            throw IllegalArgumentException(
                                "No padding specified for RSA cipher operation."
                            )
                        else ->
                            throw IllegalArgumentException(
                                "Unsupported RSA cipher padding: $requestedPadding"
                            )
                    }
                "RSA/ECB/$padding"
            }
            Algorithm.AES -> {
                val requestedBlockMode =
                    params.blockMode.singleOrNull()
                        ?: throw IllegalArgumentException(
                            "No block mode specified for AES operation."
                        )
                val blockMode =
                    when (requestedBlockMode) {
                        BlockMode.ECB -> "ECB"
                        BlockMode.CBC -> "CBC"
                        BlockMode.GCM -> "GCM"
                        else ->
                            throw IllegalArgumentException(
                                "Unsupported AES block mode: $requestedBlockMode"
                            )
                    }
                val padding =
                    when (val requestedPadding = params.padding.singleOrNull()) {
                        PaddingMode.NONE -> "NoPadding"
                        PaddingMode.PKCS7 -> "PKCS7Padding"
                        null ->
                            if (requestedBlockMode == BlockMode.GCM) {
                                "NoPadding"
                            } else {
                                throw IllegalArgumentException(
                                    "No padding specified for AES operation."
                                )
                            }
                        else ->
                            throw IllegalArgumentException(
                                "Unsupported AES padding: $requestedPadding"
                            )
                    }
                "AES/$blockMode/$padding"
            }
            else ->
                throw IllegalArgumentException("Unsupported cipher algorithm: ${params.algorithm}")
        }
    }

    private fun digestToJcaName(digest: Int): String =
        when (digest) {
            Digest.NONE -> "NONE"
            Digest.MD5 -> "MD5"
            Digest.SHA1 -> "SHA1"
            Digest.SHA_2_224 -> "SHA224"
            Digest.SHA_2_256 -> "SHA256"
            Digest.SHA_2_384 -> "SHA384"
            Digest.SHA_2_512 -> "SHA512"
            else -> throw IllegalArgumentException("Unsupported digest: $digest")
        }

    private fun digestToPssDigestName(digest: Int): String =
        when (digest) {
            Digest.MD5 -> "MD5"
            Digest.SHA1 -> "SHA-1"
            Digest.SHA_2_224 -> "SHA-224"
            Digest.SHA_2_256 -> "SHA-256"
            Digest.SHA_2_384 -> "SHA-384"
            Digest.SHA_2_512 -> "SHA-512"
            else -> throw IllegalArgumentException("Unsupported RSA PSS digest: $digest")
        }

    private fun digestToOutputSizeBytes(digest: Int): Int =
        when (digest) {
            Digest.MD5 -> 16
            Digest.SHA1 -> 20
            Digest.SHA_2_224 -> 28
            Digest.SHA_2_256 -> 32
            Digest.SHA_2_384 -> 48
            Digest.SHA_2_512 -> 64
            else -> throw IllegalArgumentException("Unsupported RSA PSS digest: $digest")
        }
}

// Concrete implementation for Signing.
private class Signer(keyPair: KeyPair, params: KeyMintAttestation) : CryptoPrimitive {
    private val signature: Signature =
        JcaAlgorithmMapper.createSignature(params).apply { initSign(keyPair.private) }

    override fun updateAad(data: ByteArray?) {
        // AOSP behavior: If AAD is provided for a key that doesn't support it (e.g., RSA/EC),
        // we throw an exception that will be translated to INVALID_ARGUMENT (ErrorCode 3).
        throw UnsupportedOperationException("AAD not supported for this algorithm")
    }

    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) signature.update(data)
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
        JcaAlgorithmMapper.createSignature(params).apply { initVerify(keyPair.public) }

    override fun updateAad(data: ByteArray?) {
        throw UnsupportedOperationException("AAD not supported for this algorithm")
    }

    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) signature.update(data)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        if (data != null) update(data)
        if (signature == null) throw SignatureException("Signature to verify is null")
        if (!this.signature.verify(signature)) {
            // Throwing an exception is how Keystore signals verification failure.
            throw SignatureException("Signature verification failed")
        }
        // A successful verification returns no data.
        return null
    }

    override fun abort() {}
}

private class AgreementPrimitive(keyPair: KeyPair, params: KeyMintAttestation) : CryptoPrimitive {
    private val peerKeyBuffer = ByteArrayOutputStream()
    private val keyFactoryAlgorithm =
        if (params.ecCurve == EcCurve.CURVE_25519) {
            "XDH"
        } else {
            "EC"
        }
    private val agreementAlgorithm =
        if (params.ecCurve == EcCurve.CURVE_25519) {
            "XDH"
        } else {
            "ECDH"
        }
    private val privateKey = keyPair.private

    override fun updateAad(data: ByteArray?) {
        throw UnsupportedOperationException("AAD not supported for this algorithm")
    }

    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) {
            peerKeyBuffer.write(data)
        }
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray {
        if (signature != null) {
            throw IllegalArgumentException("Signature is not used for key agreement")
        }
        if (data != null) {
            peerKeyBuffer.write(data)
        }
        val peerKeyBytes = peerKeyBuffer.toByteArray()
        if (peerKeyBytes.isEmpty()) {
            throw IllegalArgumentException("Peer public key is missing")
        }
        val peerPublicKey =
            KeyFactory.getInstance(keyFactoryAlgorithm, BouncyCastleProvider.PROVIDER_NAME)
                .generatePublic(X509EncodedKeySpec(peerKeyBytes))
        return KeyAgreement.getInstance(agreementAlgorithm, BouncyCastleProvider.PROVIDER_NAME)
            .apply {
                init(privateKey)
                doPhase(peerPublicKey, true)
            }
            .generateSecret()
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
        if (data != null) {
            try {
                cipher.updateAAD(data)
            } catch (e: UnsupportedOperationException) {
                throw e
            } catch (e: Exception) {
                // If the underlying JCA provider doesn't support AAD (e.g., AES/CBC).
                throw UnsupportedOperationException("AAD not supported by this cipher mode")
            }
        }
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
    companion object {
        private const val MAX_RECEIVE_DATA = 0x8000
        private const val RESPONSE_CODE_TOO_MUCH_DATA = 29
        private const val ERROR_CODE_INVALID_OPERATION_HANDLE = -28
    }

    private enum class OperationState {
        ACTIVE,
        FINISHED,
        ABORTED,
        ERROR,
    }

    // This now holds the specific strategy object (Signer, Verifier, etc.)
    private val primitive: CryptoPrimitive
    @Volatile private var state = OperationState.ACTIVE

    init {
        // The "Strategy" pattern: choose the implementation based on the purpose.
        // For simplicity, we only consider the first purpose listed.
        val purpose = params.purpose.singleOrNull()
        val purposeName = KeyMintParameterLogger.purposeNames[purpose] ?: "UNKNOWN"
        SystemLogger.debug("[SoftwareOp TX_ID: $txId] Initializing for purpose: $purposeName.")

        primitive =
            try {
                when (purpose) {
                    KeyPurpose.SIGN -> Signer(keyPair, params)
                    KeyPurpose.VERIFY -> Verifier(keyPair, params)
                    KeyPurpose.ENCRYPT -> CipherPrimitive(keyPair, params, Cipher.ENCRYPT_MODE)
                    KeyPurpose.DECRYPT -> CipherPrimitive(keyPair, params, Cipher.DECRYPT_MODE)
                    KeyPurpose.AGREE_KEY -> AgreementPrimitive(keyPair, params)
                    else ->
                        throw IllegalArgumentException("Unsupported operation purpose: $purpose")
                }
            } catch (e: Exception) {
                state = OperationState.ERROR
                SystemLogger.error("[SoftwareOp TX_ID: $txId] Failed to initialize operation.", e)
                throw e.toOperationException()
            }
    }

    private fun ensureActive() {
        if (state != OperationState.ACTIVE) {
            throw ServiceSpecificException(
                ERROR_CODE_INVALID_OPERATION_HANDLE,
                "Operation handle is no longer valid",
            )
        }
    }

    private fun checkInputLength(data: ByteArray?) {
        if (data != null && data.size > MAX_RECEIVE_DATA) {
            throw ServiceSpecificException(
                RESPONSE_CODE_TOO_MUCH_DATA,
                "Input exceeds maximum allowed length",
            )
        }
    }

    fun updateAad(data: ByteArray?) {
        ensureActive()
        checkInputLength(data)
        try {
            primitive.updateAad(data)
        } catch (e: ServiceSpecificException) {
            state = OperationState.ERROR
            throw e
        } catch (e: Exception) {
            state = OperationState.ERROR
            SystemLogger.error("[SoftwareOp TX_ID: $txId] Failed to update AAD.", e)
            throw e.toOperationException()
        }
    }

    fun update(data: ByteArray?): ByteArray? {
        ensureActive()
        checkInputLength(data)
        try {
            return primitive.update(data)
        } catch (e: ServiceSpecificException) {
            state = OperationState.ERROR
            throw e
        } catch (e: Exception) {
            state = OperationState.ERROR
            SystemLogger.error("[SoftwareOp TX_ID: $txId] Failed to update operation.", e)
            throw e.toOperationException()
        }
    }

    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        ensureActive()
        checkInputLength(data)
        try {
            val result = primitive.finish(data, signature)
            state = OperationState.FINISHED
            SystemLogger.info("[SoftwareOp TX_ID: $txId] Finished operation successfully.")
            return result
        } catch (e: ServiceSpecificException) {
            state = OperationState.ERROR
            throw e
        } catch (e: Exception) {
            state = OperationState.ERROR
            SystemLogger.error("[SoftwareOp TX_ID: $txId] Failed to finish operation.", e)
            throw e.toOperationException()
        }
    }

    fun abort() {
        ensureActive()
        state = OperationState.ABORTED
        primitive.abort()
        SystemLogger.debug("[SoftwareOp TX_ID: $txId] Operation aborted.")
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

private fun Throwable.toOperationException(): ServiceSpecificException {
    return when (this) {
        is ServiceSpecificException -> this
        is SignatureException ->
            if (message?.contains("verification failed", ignoreCase = true) == true) {
                ServiceSpecificException(KeymasterDefs.KM_ERROR_VERIFICATION_FAILED, message)
            } else {
                ServiceSpecificException(KeymasterDefs.KM_ERROR_INVALID_ARGUMENT, message)
            }
        is AEADBadTagException ->
            ServiceSpecificException(KeymasterDefs.KM_ERROR_VERIFICATION_FAILED, message)
        is IllegalBlockSizeException ->
            ServiceSpecificException(KeymasterDefs.KM_ERROR_INVALID_INPUT_LENGTH, message)
        is BadPaddingException ->
            ServiceSpecificException(KeymasterDefs.KM_ERROR_INVALID_ARGUMENT, message)
        is UnsupportedOperationException,
        is IllegalArgumentException,
        is java.security.GeneralSecurityException ->
            ServiceSpecificException(KeymasterDefs.KM_ERROR_INVALID_ARGUMENT, message)
        else -> ServiceSpecificException(KeymasterDefs.KM_ERROR_UNKNOWN_ERROR, message)
    }
}
