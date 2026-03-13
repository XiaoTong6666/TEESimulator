package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.KeyOrigin
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.PaddingMode
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.os.ServiceSpecificException
import android.security.keymaster.KeymasterDefs
import android.system.keystore2.*
import java.security.KeyPair
import java.security.SecureRandom
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap
import org.matrix.TEESimulator.attestation.AttestationPatcher
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.interception.keystore.InterceptorUtils
import org.matrix.TEESimulator.interception.keystore.KeyIdentifier
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateGenerator
import org.matrix.TEESimulator.pki.CertificateHelper

/**
 * Intercepts calls to an `IKeystoreSecurityLevel` service (e.g., TEE or StrongBox). This is where
 * the core logic for key generation and import handling for modern Android resides.
 */
class KeyMintSecurityLevelInterceptor(
    private val original: IKeystoreSecurityLevel,
    private val securityLevel: Int,
) : BinderInterceptor() {

    // --- Data Structures for State Management ---
    data class GeneratedKeyInfo(
        val keyPair: KeyPair,
        val nspace: Long,
        val response: KeyEntryResponse,
    )

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        val shouldSkip = ConfigurationManager.shouldSkipUid(callingUid)

        when (code) {
            GENERATE_KEY_TRANSACTION -> {
                logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

                if (!shouldSkip) return handleGenerateKey(callingUid, data)
            }
            CREATE_OPERATION_TRANSACTION -> {
                logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

                if (!shouldSkip) return handleCreateOperation(txId, callingUid, data)
            }
            IMPORT_KEY_TRANSACTION -> {
                logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!
                SystemLogger.info(
                    "[TX_ID: $txId] Forward to post-importKey hook for ${keyDescriptor.alias}[${keyDescriptor.nspace}]"
                )
                return TransactionResult.Continue
            }
        }

        logTransaction(
            txId,
            transactionNames[code] ?: "unknown code=$code",
            callingUid,
            callingPid,
            true,
        )

        return TransactionResult.ContinueAndSkipPost
    }

    override fun onPostTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int,
    ): TransactionResult {
        // We only care about successful transactions.
        if (resultCode != 0 || reply == null || InterceptorUtils.hasException(reply))
            return TransactionResult.SkipTransaction

        if (code == IMPORT_KEY_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.SkipTransaction
            cleanupKeyData(KeyIdentifier(callingUid, keyDescriptor.alias))
        } else if (code == CREATE_OPERATION_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!
            val params = data.createTypedArray(KeyParameter.CREATOR)!!
            val parsedParams = KeyMintAttestation(params)
            val forced = data.readBoolean()
            if (forced)
                SystemLogger.verbose(
                    "[TX_ID: $txId] Current operation has a very high pruning power."
                )
            val response: CreateOperationResponse =
                reply.readTypedObject(CreateOperationResponse.CREATOR)!!
            SystemLogger.verbose(
                "[TX_ID: $txId] CreateOperationResponse: ${response.iOperation} ${response.operationChallenge}"
            )

            // Intercept the IKeystoreOperation binder
            response.iOperation?.let { operation ->
                val operationBinder = operation.asBinder()
                if (!interceptedOperations.containsKey(operationBinder)) {
                    SystemLogger.info("Found new IKeystoreOperation. Registering interceptor...")
                    val backdoor = getBackdoor(target)
                    if (backdoor != null) {
                        val interceptor = OperationInterceptor(operation, backdoor)
                        register(backdoor, operationBinder, interceptor)
                        interceptedOperations[operationBinder] = interceptor
                    } else {
                        SystemLogger.error(
                            "Failed to get backdoor to register OperationInterceptor."
                        )
                    }
                }
            }
        } else if (code == GENERATE_KEY_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            val metadata: KeyMetadata =
                reply.readTypedObject(KeyMetadata.CREATOR)
                    ?: return TransactionResult.SkipTransaction
            KeyMintAttestation(
                metadata.authorizations?.map { it.keyParameter }?.toTypedArray() ?: emptyArray()
            )
            val originalChain =
                CertificateHelper.getCertificateChain(metadata)
                    ?: return TransactionResult.SkipTransaction
            if (originalChain.size > 1) {
                val newChain = AttestationPatcher.patchCertificateChain(originalChain, callingUid)

                // Cache the newly patched chain to ensure consistency across subsequent API calls.
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!
                val key = metadata.key!!
                val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)
                CertificateHelper.updateCertificateChain(metadata, newChain).getOrThrow()

                // We must clean up cached generated keys before storing the patched chain
                cleanupKeyData(keyId)
                patchedChains[keyId] = newChain
                SystemLogger.debug(
                    "Cached patched certificate chain for $keyId. (${key.alias} [${key.domain}, ${key.nspace}])"
                )

                return InterceptorUtils.createTypedObjectReply(metadata)
            }
        }
        return TransactionResult.SkipTransaction
    }

    /**
     * Handles the `createOperation` transaction. It checks if the operation is for a key that was
     * generated in software. If so, it creates a software-based operation handler. Otherwise, it
     * lets the call proceed to the real hardware service.
     */
    private fun handleCreateOperation(
        txId: Long,
        callingUid: Int,
        data: Parcel,
    ): TransactionResult {
        data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
        val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!

        // An operation must use the KEY_ID domain.
        if (keyDescriptor.domain != Domain.KEY_ID) {
            return TransactionResult.ContinueAndSkipPost
        }

        val nspace = keyDescriptor.nspace
        val generatedKeyInfo = findGeneratedKeyByKeyId(callingUid, nspace)

        if (generatedKeyInfo == null) {
            SystemLogger.debug(
                "[TX_ID: $txId] Operation for unknown/hardware KeyId ($nspace). Forwarding."
            )
            return TransactionResult.Continue
        }

        SystemLogger.info("[TX_ID: $txId] Creating SOFTWARE operation for KeyId $nspace.")

        val params = data.createTypedArray(KeyParameter.CREATOR)!!
        val parsedOpParams = KeyMintAttestation(params)

        val softwareOperation =
            runCatching {
                    val keyAuths =
                        generatedKeyInfo.response.metadata.authorizations
                            ?.map { it.keyParameter }
                            ?.toTypedArray() ?: emptyArray()
                    val parsedKeyParams = KeyMintAttestation(keyAuths)
                    authorizeSoftwareOperationCreate(parsedOpParams, parsedKeyParams)
                    val combinedParams = parsedOpParams.mergeWith(parsedKeyParams)
                    SoftwareOperation(txId, generatedKeyInfo.keyPair, combinedParams)
                }
                .getOrElse { throwable ->
                    return InterceptorUtils.createExceptionReply(
                        throwable.asServiceSpecificException()
                    )
                }
        val operationBinder = SoftwareOperationBinder(softwareOperation)

        val response =
            CreateOperationResponse().apply {
                iOperation = operationBinder
                operationChallenge = null
            }

        return InterceptorUtils.createTypedObjectReply(response)
    }

    /**
     * Handles the `generateKey` transaction. Based on the configuration for the calling UID, it
     * either generates a key in software or lets the call pass through to the hardware.
     */
    private fun handleGenerateKey(callingUid: Int, data: Parcel): TransactionResult {
        return runCatching {
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!
                val attestationKey = data.readTypedObject(KeyDescriptor.CREATOR)
                SystemLogger.debug(
                    "Handling generateKey ${keyDescriptor.alias}, attestKey=${attestationKey?.alias}"
                )
                val params = data.createTypedArray(KeyParameter.CREATOR)!!
                val parsedParams = KeyMintAttestation(params)
                val isAttestKeyRequest = parsedParams.isAttestKey()

                // Determine if we need to generate a key based on config or
                // if it's an attestation request in patch mode.
                val needsSoftwareGeneration =
                    ConfigurationManager.shouldGenerate(callingUid) ||
                        (ConfigurationManager.shouldPatch(callingUid) && isAttestKeyRequest) ||
                        (attestationKey != null &&
                            isAttestationKey(KeyIdentifier(callingUid, attestationKey.alias)))

                if (needsSoftwareGeneration) {
                    runCatching { validateSoftwareKeyGenerationParams(parsedParams) }
                        .getOrElse {
                            return InterceptorUtils.createExceptionReply(
                                it.asServiceSpecificException()
                            )
                        }
                    keyDescriptor.nspace = secureRandom.nextLong()
                    SystemLogger.info(
                        "Generating software key for ${keyDescriptor.alias}[${keyDescriptor.nspace}]."
                    )

                    // Generate the key pair and certificate chain.
                    val keyData =
                        CertificateGenerator.generateAttestedKeyPair(
                            callingUid,
                            keyDescriptor.alias,
                            attestationKey?.alias,
                            parsedParams,
                            securityLevel,
                        ) ?: throw Exception("CertificateGenerator failed to create key pair.")

                    val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)
                    // It is unnecessary but a good practice to clean up possible caches
                    cleanupKeyData(keyId)
                    // Store the generated key data.
                    val response =
                        buildKeyEntryResponse(keyData.second, parsedParams, keyDescriptor)
                    generatedKeys[keyId] =
                        GeneratedKeyInfo(keyData.first, keyDescriptor.nspace, response)
                    if (isAttestKeyRequest) attestationKeys.add(keyId)

                    // Return the metadata of our generated key, skipping the real hardware call.
                    InterceptorUtils.createTypedObjectReply(response.metadata)
                } else if (parsedParams.attestationChallenge != null) {
                    TransactionResult.Continue
                } else {
                    TransactionResult.ContinueAndSkipPost
                }
            }
            .getOrElse {
                SystemLogger.error("No key pair generated for UID $callingUid.", it)
                TransactionResult.ContinueAndSkipPost
            }
    }

    /**
     * Constructs a fake `KeyEntryResponse` that mimics a real response from the Keystore service.
     */
    private fun buildKeyEntryResponse(
        chain: List<Certificate>,
        params: KeyMintAttestation,
        descriptor: KeyDescriptor,
    ): KeyEntryResponse {
        val normalizedKeyDescriptor =
            KeyDescriptor().apply {
                domain = Domain.KEY_ID
                nspace = descriptor.nspace
                alias = null
                blob = null
            }
        val metadata =
            KeyMetadata().apply {
                keySecurityLevel = securityLevel
                key = normalizedKeyDescriptor
                CertificateHelper.updateCertificateChain(this, chain.toTypedArray()).getOrThrow()
                authorizations = params.toAuthorizations(securityLevel)
                modificationTimeMs = System.currentTimeMillis()
            }
        return KeyEntryResponse().apply {
            this.metadata = metadata
            iSecurityLevel = original
        }
    }

    companion object {
        private val secureRandom = SecureRandom()

        // Transaction codes for IKeystoreSecurityLevel interface.
        private val GENERATE_KEY_TRANSACTION =
            InterceptorUtils.getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "generateKey")
        private val IMPORT_KEY_TRANSACTION =
            InterceptorUtils.getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "importKey")
        private val CREATE_OPERATION_TRANSACTION =
            InterceptorUtils.getTransactCode(
                IKeystoreSecurityLevel.Stub::class.java,
                "createOperation",
            )

        private val transactionNames: Map<Int, String> by lazy {
            IKeystoreSecurityLevel.Stub::class
                .java
                .declaredFields
                .filter {
                    it.isAccessible = true
                    it.type == Int::class.java && it.name.startsWith("TRANSACTION_")
                }
                .associate { field -> (field.get(null) as Int) to field.name.split("_")[1] }
        }

        // Stores keys generated entirely in software.
        val generatedKeys = ConcurrentHashMap<KeyIdentifier, GeneratedKeyInfo>()
        // A set to quickly identify keys that were generated for attestation purposes.
        val attestationKeys = ConcurrentHashMap.newKeySet<KeyIdentifier>()
        // Caches patched certificate chains to prevent re-generation and signature inconsistencies.
        val patchedChains = ConcurrentHashMap<KeyIdentifier, Array<Certificate>>()
        // Stores interceptors for active cryptographic operations.
        private val interceptedOperations = ConcurrentHashMap<IBinder, OperationInterceptor>()

        // --- Public Accessors for Other Interceptors ---
        fun getGeneratedKeyResponse(keyId: KeyIdentifier): KeyEntryResponse? =
            generatedKeys[keyId]?.response

        /**
         * Finds a software-generated key by first filtering all known keys by the caller's UID, and
         * then matching the specific nspace.
         *
         * @param callingUid The UID of the process that initiated the createOperation call.
         * @param nspace The unique key identifier from the operation's KeyDescriptor.
         * @return The matching GeneratedKeyInfo if found, otherwise null.
         */
        fun findGeneratedKeyByKeyId(callingUid: Int, nspace: Long?): GeneratedKeyInfo? {
            // Iterate through all entries in the map to check both the key (for UID) and value (for
            // nspace).
            if (nspace == null || nspace == 0L) return null
            return generatedKeys.entries
                .filter { (keyIdentifier, _) -> keyIdentifier.uid == callingUid }
                .find { (_, info) -> info.nspace == nspace }
                ?.value
        }

        fun getPatchedChain(keyId: KeyIdentifier): Array<Certificate>? = patchedChains[keyId]

        fun isAttestationKey(keyId: KeyIdentifier): Boolean = attestationKeys.contains(keyId)

        fun cleanupKeyData(keyId: KeyIdentifier) {
            if (generatedKeys.remove(keyId) != null) {
                SystemLogger.debug("Remove generated key ${keyId}")
            }
            if (patchedChains.remove(keyId) != null) {
                SystemLogger.debug("Remove patched chain for ${keyId}")
            }
            if (attestationKeys.remove(keyId)) {
                SystemLogger.debug("Remove cached attestaion key ${keyId}")
            }
        }

        fun removeOperationInterceptor(operationBinder: IBinder, backdoor: IBinder) {
            // Unregister from the native hook layer first.
            unregister(backdoor, operationBinder)

            if (interceptedOperations.remove(operationBinder) != null) {
                SystemLogger.debug("Removed operation interceptor for binder: $operationBinder")
            }
        }

        // Clears all cached keys.
        fun clearAllGeneratedKeys(reason: String? = null) {
            val count = generatedKeys.size
            val reasonMessage = reason?.let { " due to $it" } ?: ""
            generatedKeys.clear()
            patchedChains.clear()
            attestationKeys.clear()
            SystemLogger.info("Cleared all cached keys ($count entries)$reasonMessage.")
        }
    }
}

/**
 * Extension function to convert parsed `KeyMintAttestation` parameters back into an array of
 * `Authorization` objects for the fake `KeyMetadata`.
 */
private fun KeyMintAttestation.toAuthorizations(securityLevel: Int): Array<Authorization> {
    val authList = mutableListOf<Authorization>()

    /**
     * Helper function to create a fully-formed Authorization object.
     *
     * @param tag The KeyMint tag (e.g., Tag.ALGORITHM).
     * @param value The value for the tag, wrapped in a KeyParameterValue.
     * @return A populated Authorization object.
     */
    fun createAuth(tag: Int, value: KeyParameterValue): Authorization {
        val param =
            KeyParameter().apply {
                this.tag = tag
                this.value = value
            }
        return Authorization().apply {
            this.keyParameter = param
            this.securityLevel = securityLevel
        }
    }

    // Use the helper to add each authorization entry cleanly.
    this.purpose.forEach { authList.add(createAuth(Tag.PURPOSE, KeyParameterValue.keyPurpose(it))) }
    this.digest.forEach { authList.add(createAuth(Tag.DIGEST, KeyParameterValue.digest(it))) }
    this.padding.forEach {
        authList.add(createAuth(Tag.PADDING, KeyParameterValue.paddingMode(it)))
    }
    this.blockMode.forEach {
        authList.add(createAuth(Tag.BLOCK_MODE, KeyParameterValue.blockMode(it)))
    }

    authList.add(createAuth(Tag.ALGORITHM, KeyParameterValue.algorithm(this.algorithm)))
    authList.add(createAuth(Tag.KEY_SIZE, KeyParameterValue.integer(this.keySize)))
    authList.add(createAuth(Tag.EC_CURVE, KeyParameterValue.ecCurve(this.ecCurve)))
    authList.add(
        createAuth(Tag.ORIGIN, KeyParameterValue.origin(this.origin ?: KeyOrigin.GENERATED))
    )
    authList.add(createAuth(Tag.NO_AUTH_REQUIRED, KeyParameterValue.boolValue(true)))

    return authList.toTypedArray()
}

private fun authorizeSoftwareOperationCreate(
    operationParams: KeyMintAttestation,
    keyParams: KeyMintAttestation,
) {
    val requestedPurpose =
        operationParams.purpose.singleRequestedValue("purpose")
            ?: throw ServiceSpecificException(
                KeymasterDefs.KM_ERROR_INVALID_ARGUMENT,
                "No operation purpose specified.",
            )

    when (requestedPurpose) {
        KeyPurpose.SIGN,
        KeyPurpose.DECRYPT -> Unit
        KeyPurpose.WRAP_KEY ->
            throw ServiceSpecificException(
                KeymasterDefs.KM_ERROR_INCOMPATIBLE_PURPOSE,
                "WRAP_KEY purpose is not allowed for createOperation.",
            )
        KeyPurpose.AGREE_KEY -> {
            if (keyParams.algorithm != Algorithm.EC) {
                throw ServiceSpecificException(
                    KeymasterDefs.KM_ERROR_UNSUPPORTED_PURPOSE,
                    "Key agreement is only supported for EC keys.",
                )
            }
        }
        KeyPurpose.VERIFY,
        KeyPurpose.ENCRYPT -> {
            if (keyParams.algorithm == Algorithm.RSA || keyParams.algorithm == Algorithm.EC) {
                throw ServiceSpecificException(
                    KeymasterDefs.KM_ERROR_UNSUPPORTED_PURPOSE,
                    "Public operations on asymmetric keys are not supported.",
                )
            }
        }
        else ->
            throw ServiceSpecificException(
                KeymasterDefs.KM_ERROR_UNSUPPORTED_PURPOSE,
                "Unsupported operation purpose: $requestedPurpose",
            )
    }

    if (!keyParams.purpose.contains(requestedPurpose)) {
        throw ServiceSpecificException(
            KeymasterDefs.KM_ERROR_INCOMPATIBLE_PURPOSE,
            "The requested purpose is not authorized by the key.",
        )
    }

    val requestedPadding = operationParams.padding.singleRequestedValue("padding")
    val requestedBlockMode = operationParams.blockMode.singleRequestedValue("block mode")
    val requestedDigest = operationParams.digest.singleRequestedValue("digest")

    if (requestedPadding != null) {
        if (!isPaddingSupportedForKey(requestedPurpose, keyParams.algorithm, requestedPadding)) {
            throw ServiceSpecificException(
                KeymasterDefs.KM_ERROR_UNSUPPORTED_PADDING_MODE,
                "Padding $requestedPadding is not supported for this key/purpose.",
            )
        }
        if (keyParams.padding.isEmpty()) {
            throw ServiceSpecificException(
                KeymasterDefs.KM_ERROR_UNSUPPORTED_PADDING_MODE,
                "Padding $requestedPadding is not authorized by the key.",
            )
        }
        if (requestedPadding !in keyParams.padding) {
            throw ServiceSpecificException(
                KeymasterDefs.KM_ERROR_INCOMPATIBLE_PADDING_MODE,
                "Padding $requestedPadding is not authorized by the key.",
            )
        }
    } else if (
        keyParams.algorithm == Algorithm.RSA &&
            (requestedPurpose == KeyPurpose.SIGN ||
                requestedPurpose == KeyPurpose.VERIFY ||
                requestedPurpose == KeyPurpose.ENCRYPT ||
                requestedPurpose == KeyPurpose.DECRYPT)
    ) {
        if (keyParams.padding.isEmpty()) {
            throw ServiceSpecificException(
                KeymasterDefs.KM_ERROR_UNSUPPORTED_PADDING_MODE,
                "No padding mode authorized for this RSA key.",
            )
        }
    } else if (
        keyParams.padding.isNotEmpty() &&
            keyParams.algorithm != Algorithm.EC &&
            keyParams.algorithm != Algorithm.HMAC
    ) {
        throw ServiceSpecificException(
            KeymasterDefs.KM_ERROR_INVALID_ARGUMENT,
            "No padding specified for the operation.",
        )
    }

    if (requestedBlockMode != null) {
        if (!isBlockModeSupportedForKey(keyParams.algorithm, requestedBlockMode)) {
            throw ServiceSpecificException(
                KeymasterDefs.KM_ERROR_UNSUPPORTED_BLOCK_MODE,
                "Block mode $requestedBlockMode is not supported for this algorithm.",
            )
        }
        if (keyParams.blockMode.isNotEmpty() && requestedBlockMode !in keyParams.blockMode) {
            throw ServiceSpecificException(
                KeymasterDefs.KM_ERROR_INCOMPATIBLE_BLOCK_MODE,
                "Block mode $requestedBlockMode is not authorized by the key.",
            )
        }
    } else if (keyParams.blockMode.isNotEmpty()) {
        throw ServiceSpecificException(
            KeymasterDefs.KM_ERROR_INVALID_ARGUMENT,
            "No block mode specified for the operation.",
        )
    }

    val effectivePadding = requestedPadding ?: keyParams.padding.singleOrNull()
    val digestIsRequired =
        requestedPurpose == KeyPurpose.SIGN ||
            requestedPurpose == KeyPurpose.VERIFY ||
            effectivePadding == PaddingMode.RSA_OAEP ||
            effectivePadding == PaddingMode.RSA_PSS
    if (digestIsRequired && requestedDigest == null) {
        throw ServiceSpecificException(
            KeymasterDefs.KM_ERROR_UNSUPPORTED_DIGEST,
            "No digest specified for the operation.",
        )
    }
    if (
        keyParams.algorithm == Algorithm.EC &&
            keyParams.ecCurve == android.hardware.security.keymint.EcCurve.CURVE_25519 &&
            (requestedPurpose == KeyPurpose.SIGN || requestedPurpose == KeyPurpose.VERIFY) &&
            requestedDigest != null &&
            requestedDigest != android.hardware.security.keymint.Digest.NONE
    ) {
        throw ServiceSpecificException(
            KeymasterDefs.KM_ERROR_UNSUPPORTED_DIGEST,
            "Digest $requestedDigest is not supported for this key.",
        )
    }
    if (
        requestedDigest == android.hardware.security.keymint.Digest.NONE &&
            (effectivePadding == PaddingMode.RSA_OAEP || effectivePadding == PaddingMode.RSA_PSS)
    ) {
        throw ServiceSpecificException(
            KeymasterDefs.KM_ERROR_INCOMPATIBLE_DIGEST,
            "Digest $requestedDigest is not compatible with padding $effectivePadding.",
        )
    }
    if (
        keyParams.algorithm == Algorithm.RSA &&
            (requestedPurpose == KeyPurpose.SIGN || requestedPurpose == KeyPurpose.VERIFY) &&
            effectivePadding == PaddingMode.NONE &&
            requestedDigest != null &&
            requestedDigest != android.hardware.security.keymint.Digest.NONE
    ) {
        throw ServiceSpecificException(
            KeymasterDefs.KM_ERROR_INCOMPATIBLE_DIGEST,
            "Digest $requestedDigest is not compatible with padding $effectivePadding.",
        )
    }
    if (requestedDigest != null && keyParams.digest.isEmpty()) {
        throw ServiceSpecificException(
            KeymasterDefs.KM_ERROR_UNSUPPORTED_DIGEST,
            "Digest $requestedDigest is not authorized by the key.",
        )
    }
    if (requestedDigest != null && requestedDigest !in keyParams.digest) {
        throw ServiceSpecificException(
            KeymasterDefs.KM_ERROR_INCOMPATIBLE_DIGEST,
            "Digest $requestedDigest is not authorized by the key.",
        )
    }
}

private fun validateSoftwareKeyGenerationParams(params: KeyMintAttestation) {
    val purposes = params.purpose.distinct()
    if (purposes.contains(KeyPurpose.ATTEST_KEY) && purposes.size > 1) {
        throw ServiceSpecificException(
            KeymasterDefs.KM_ERROR_INCOMPATIBLE_PURPOSE,
            "ATTEST_KEY purpose cannot be combined with other purposes.",
        )
    }
    if (
        params.algorithm == Algorithm.EC &&
            params.ecCurve == EcCurve.CURVE_25519 &&
            purposes.contains(KeyPurpose.AGREE_KEY) &&
            purposes.size > 1
    ) {
        throw ServiceSpecificException(
            KeymasterDefs.KM_ERROR_INCOMPATIBLE_PURPOSE,
            "CURVE_25519 AGREE_KEY cannot be combined with other purposes.",
        )
    }
}

private fun List<Int>.singleRequestedValue(name: String): Int? {
    if (size <= 1) return firstOrNull()
    throw ServiceSpecificException(
        KeymasterDefs.KM_ERROR_INVALID_ARGUMENT,
        "Multiple $name values specified for one operation.",
    )
}

private fun isPaddingSupportedForKey(purpose: Int, algorithm: Int, padding: Int): Boolean =
    when (algorithm) {
        Algorithm.RSA ->
            when (purpose) {
                KeyPurpose.ENCRYPT,
                KeyPurpose.DECRYPT ->
                    padding == PaddingMode.NONE ||
                        padding == PaddingMode.RSA_PKCS1_1_5_ENCRYPT ||
                        padding == PaddingMode.RSA_OAEP
                KeyPurpose.SIGN,
                KeyPurpose.VERIFY ->
                    padding == PaddingMode.NONE ||
                        padding == PaddingMode.RSA_PKCS1_1_5_SIGN ||
                        padding == PaddingMode.RSA_PSS
                else -> false
            }
        Algorithm.EC -> false
        Algorithm.AES,
        Algorithm.TRIPLE_DES -> padding == PaddingMode.NONE || padding == PaddingMode.PKCS7
        Algorithm.HMAC -> false
        else -> false
    }

private fun isBlockModeSupportedForKey(algorithm: Int, blockMode: Int): Boolean =
    when (algorithm) {
        Algorithm.AES,
        Algorithm.TRIPLE_DES ->
            blockMode == android.hardware.security.keymint.BlockMode.ECB ||
                blockMode == android.hardware.security.keymint.BlockMode.CBC ||
                blockMode == android.hardware.security.keymint.BlockMode.CTR ||
                blockMode == android.hardware.security.keymint.BlockMode.GCM
        else -> false
    }

private fun Throwable.asServiceSpecificException(): ServiceSpecificException =
    when (this) {
        is ServiceSpecificException -> this
        is IllegalArgumentException ->
            ServiceSpecificException(KeymasterDefs.KM_ERROR_INVALID_ARGUMENT, message)
        else -> ServiceSpecificException(KeymasterDefs.KM_ERROR_UNKNOWN_ERROR, message)
    }
