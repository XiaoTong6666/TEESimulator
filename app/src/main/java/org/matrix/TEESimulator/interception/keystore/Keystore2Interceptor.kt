package org.matrix.TEESimulator.interception.keystore

import android.annotation.SuppressLint
import android.hardware.security.keymint.KeyOrigin
import android.hardware.security.keymint.SecurityLevel
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.Domain
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import java.security.cert.Certificate
import org.matrix.TEESimulator.attestation.AttestationPatcher
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.logging.KeyMintParameterLogger
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateHelper

/**
 * Interceptor for the `IKeystoreService` on Android S (API 31) and newer.
 *
 * This version of Keystore delegates most cryptographic operations to `IKeystoreSecurityLevel`
 * sub-services (for TEE, StrongBox, etc.). This interceptor's main role is to set up interceptors
 * for those sub-services and to patch certificate chains on their way out.
 */
@SuppressLint("BlockedPrivateApi")
object Keystore2Interceptor : AbstractKeystoreInterceptor() {
    // Transaction codes for the IKeystoreService interface methods we are interested in.
    private val GET_KEY_ENTRY_TRANSACTION =
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "getKeyEntry")
    private val LIST_ENTRIES_TRANSACTION =
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "listEntries").also {
            SystemLogger.info("LIST_ENTRIES_TRANSACTION code: $it")
        }
    private val LIST_ENTRIES_BATCHED_TRANSACTION =
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "listEntriesBatched")
            .also { SystemLogger.info("LIST_ENTRIES_BATCHED_TRANSACTION code: $it") }
    private val DELETE_KEY_TRANSACTION =
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "deleteKey")
    private val UPDATE_SUBCOMPONENT_TRANSACTION =
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "updateSubcomponent")
    private val transactionNames: Map<Int, String> by lazy {
        IKeystoreService.Stub::class
            .java
            .declaredFields
            .filter {
                it.isAccessible = true
                it.type == Int::class.java && it.name.startsWith("TRANSACTION_")
            }
            .associate { field -> (field.get(null) as Int) to field.name.split("_")[1] }
    }

    override val serviceName = "android.system.keystore2.IKeystoreService/default"
    override val processName = "keystore2"
    override val injectionCommand = "exec ./inject `pidof keystore2` libTEESimulator.so entry"

    /**
     * This method is called once the main service is hooked. It proceeds to find and hook the
     * security level sub-services (e.g., TEE, StrongBox).
     */
    override fun onInterceptorReady(service: IBinder, backdoor: IBinder) {
        val keystoreInterface = IKeystoreService.Stub.asInterface(service)
        setupSecurityLevelInterceptors(keystoreInterface, backdoor)
    }

    private fun setupSecurityLevelInterceptors(service: IKeystoreService, backdoor: IBinder) {
        // Attempt to get and intercept the TEE security level service.
        runCatching {
                service.getSecurityLevel(SecurityLevel.TRUSTED_ENVIRONMENT)?.let { tee ->
                    SystemLogger.info("Found TEE SecurityLevel. Registering interceptor...")
                    val interceptor =
                        KeyMintSecurityLevelInterceptor(tee, SecurityLevel.TRUSTED_ENVIRONMENT)
                    register(backdoor, tee.asBinder(), interceptor)
                }
            }
            .onFailure { SystemLogger.error("Failed to intercept TEE SecurityLevel.", it) }

        // Attempt to get and intercept the StrongBox security level service.
        runCatching {
                service.getSecurityLevel(SecurityLevel.STRONGBOX)?.let { strongbox ->
                    SystemLogger.info("Found StrongBox SecurityLevel. Registering interceptor...")
                    val interceptor =
                        KeyMintSecurityLevelInterceptor(strongbox, SecurityLevel.STRONGBOX)
                    register(backdoor, strongbox.asBinder(), interceptor)
                }
            }
            .onFailure { SystemLogger.error("Failed to intercept StrongBox SecurityLevel.", it) }
    }

    // Thread-local storage for listEntries parameters to avoid re-parsing in onPostTransact
    // Triple<domain, namespace, startPastAlias?>
    private val listEntriesParams = ThreadLocal<Triple<Int, Long, String?>?>()

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        // Debug: Log all transaction codes to see if listEntries is being called
        if (
            code !in
                setOf(
                    GET_KEY_ENTRY_TRANSACTION,
                    DELETE_KEY_TRANSACTION,
                    UPDATE_SUBCOMPONENT_TRANSACTION,
                    LIST_ENTRIES_TRANSACTION,
                    LIST_ENTRIES_BATCHED_TRANSACTION,
                )
        ) {
            val methodName = transactionNames[code] ?: "unknown"
            SystemLogger.debug(
                "[TX_ID: $txId] Unhandled transaction: code=$code, method=$methodName, uid=$callingUid"
            )
        }

        if (code == LIST_ENTRIES_TRANSACTION || code == LIST_ENTRIES_BATCHED_TRANSACTION) {
            val methodName =
                if (code == LIST_ENTRIES_BATCHED_TRANSACTION) "listEntriesBatched"
                else "listEntries"
            SystemLogger.info("[TX_ID: $txId] $methodName called by UID $callingUid")
            if (ConfigurationManager.shouldSkipUid(callingUid)) {
                listEntriesParams.set(null)
                SystemLogger.debug(
                    "[TX_ID: $txId] $methodName: Skipping UID $callingUid (in skip list)"
                )
                return TransactionResult.ContinueAndSkipPost
            }

            return runCatching {
                    data.setDataPosition(0)
                    data.enforceInterface(IKeystoreService.DESCRIPTOR)
                    val domain = data.readInt()
                    val namespace = data.readLong()

                    // Read startPastAlias for listEntriesBatched (AOSP pagination support)
                    var startPastAlias: String? = null
                    if (code == LIST_ENTRIES_BATCHED_TRANSACTION) {
                        startPastAlias = data.readString()
                    }

                    SystemLogger.debug(
                        "[TX_ID: $txId] $methodName: domain=$domain, namespace=$namespace, startPastAlias=$startPastAlias"
                    )

                    // Cache parameters for post-transaction processing
                    listEntriesParams.set(Triple(domain, namespace, startPastAlias))

                    // Reset data position for AOSP to process
                    data.setDataPosition(0)
                    TransactionResult.Continue
                }
                .getOrElse { e ->
                    SystemLogger.error("[TX_ID: $txId] Failed to parse $methodName parameters", e)
                    listEntriesParams.set(null)
                    TransactionResult.ContinueAndSkipPost
                }
        }

        if (
            code == GET_KEY_ENTRY_TRANSACTION ||
                code == DELETE_KEY_TRANSACTION ||
                code == UPDATE_SUBCOMPONENT_TRANSACTION
        ) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val descriptor =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.SkipTransaction

            if (ConfigurationManager.shouldSkipUid(callingUid))
                return TransactionResult.ContinueAndSkipPost

            SystemLogger.info(
                "Handling ${transactionNames[code]!!} ${descriptor.alias ?: "null"} [nspace=${descriptor.nspace}]"
            )

            val softwareKeyInfo =
                KeyMintSecurityLevelInterceptor.findSoftwareKey(callingUid, descriptor)
            val isSoftwareKey = softwareKeyInfo != null

            val keyId = KeyIdentifier(callingUid, descriptor.alias ?: "")

            if (code == DELETE_KEY_TRANSACTION) {
                if (isSoftwareKey) {
                    if (!descriptor.alias.isNullOrEmpty()) {
                        KeyMintSecurityLevelInterceptor.cleanupKeyData(keyId)
                    } else {
                        KeyMintSecurityLevelInterceptor.cleanupByNspace(
                            callingUid,
                            descriptor.nspace,
                        )
                    }

                    SystemLogger.info(
                        "[TX_ID: $txId] Deleted cached keypair (Software), replying with empty response."
                    )
                    return InterceptorUtils.createSuccessReply(writeResultCode = false)
                }
                return TransactionResult.ContinueAndSkipPost
            }

            if (code == UPDATE_SUBCOMPONENT_TRANSACTION) {

                if (isSoftwareKey) {
                    val publicCert = data.createByteArray()
                    val certificateChain = data.createByteArray()

                    SystemLogger.info(
                        "[TX_ID: $txId] Intercepting updateSubcomponent for Software Key. Updating memory state."
                    )

                    KeyMintSecurityLevelInterceptor.updateSoftwareKey(
                        callingUid,
                        descriptor,
                        publicCert,
                        certificateChain,
                    )
                    return InterceptorUtils.createSuccessReply(writeResultCode = false)
                }
                return TransactionResult.ContinueAndSkipPost
            }

            val response =
                KeyMintSecurityLevelInterceptor.getGeneratedKeyResponse(keyId)
                    ?: return TransactionResult.Continue

            if (KeyMintSecurityLevelInterceptor.isAttestationKey(keyId))
                SystemLogger.info("${descriptor.alias} was an attestation key")

            SystemLogger.info("[TX_ID: $txId] Found generated response for ${descriptor.alias}:")
            response.metadata?.authorizations?.forEach {
                KeyMintParameterLogger.logParameter(it.keyParameter)
            }

            // GET_KEY_ENTRY
            if (isSoftwareKey) {
                SystemLogger.info("[TX_ID: $txId] Found generated response for software key.")
                return InterceptorUtils.createTypedObjectReply(softwareKeyInfo!!.response)
            } else {
                logTransaction(
                    txId,
                    transactionNames[code] ?: "unknown code=$code",
                    callingUid,
                    callingPid,
                    true,
                )
            }
        }

        // Let most calls go through to the real service.
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
        if (target != keystoreService || reply == null || InterceptorUtils.hasException(reply))
            return TransactionResult.SkipTransaction

        if (code == LIST_ENTRIES_TRANSACTION || code == LIST_ENTRIES_BATCHED_TRANSACTION) {
            val methodName =
                if (code == LIST_ENTRIES_BATCHED_TRANSACTION) "listEntriesBatched"
                else "listEntries"
            return runCatching {
                    val params = listEntriesParams.get()
                    if (params == null) {
                        SystemLogger.warning(
                            "[TX_ID: $txId] $methodName: No cached parameters, skipping injection."
                        )
                        return TransactionResult.SkipTransaction
                    }

                    val (domain, namespace, startPastAlias) = params
                    listEntriesParams.remove()

                    logTransaction(txId, "post-$methodName", callingUid, callingPid)

                    if (domain != Domain.APP) {
                        SystemLogger.debug(
                            "[TX_ID: $txId] listEntries: domain=$domain (not APP), skipping injection."
                        )
                        return TransactionResult.SkipTransaction
                    }

                    if (namespace != callingUid.toLong() && namespace != -1L) {
                        SystemLogger.debug(
                            "[TX_ID: $txId] $methodName: namespace ($namespace) != callingUid ($callingUid) and not -1, skipping injection."
                        )
                        return TransactionResult.SkipTransaction
                    }

                    val effectiveNamespace =
                        if (namespace == -1L) callingUid.toLong() else namespace

                    // Get all virtual keys for this UID
                    val allFakeKeys =
                        KeyMintSecurityLevelInterceptor.getSoftwareKeyDescriptorsForUid(
                            callingUid,
                            effectiveNamespace,
                        )

                    // AOSP behavior: Apply startPastAlias filtering for pagination
                    // Only include keys with alias > startPastAlias (lexicographic order)
                    val fakeKeys =
                        if (startPastAlias != null) {
                            allFakeKeys.filter { (it.alias ?: "") > startPastAlias }
                        } else {
                            allFakeKeys
                        }

                    SystemLogger.debug(
                        "[TX_ID: $txId] $methodName: Found ${fakeKeys.size} virtual keys for UID $callingUid (after startPastAlias='$startPastAlias' filter)"
                    )
                    if (fakeKeys.isNotEmpty()) {
                        fakeKeys.forEach { fk ->
                            SystemLogger.debug(
                                "[TX_ID: $txId] listEntries: Virtual key alias='${fk.alias}' domain=${fk.domain} nspace=${fk.nspace}"
                            )
                        }
                    }

                    if (fakeKeys.isEmpty()) return TransactionResult.SkipTransaction

                    reply.setDataPosition(0)
                    reply.readException()

                    val arrayLen = reply.readInt()
                    val encoding = detectKeyDescriptorEncoding(reply, arrayLen)

                    val originalKeys = ArrayList<KeyDescriptor>(maxOf(arrayLen, 0))
                    val existingAliases = HashSet<String>()

                    if (arrayLen > 0) {
                        repeat(arrayLen) {
                            val kd = readKeyDescriptor(reply, encoding)
                            if (kd != null) {
                                originalKeys.add(kd)
                                kd.alias?.let { existingAliases.add(it) }
                            }
                        }
                    }

                    SystemLogger.debug(
                        "[TX_ID: $txId] listEntries: Read ${originalKeys.size} original keys from AOSP (arrayLen=$arrayLen)"
                    )

                    val mergedList = ArrayList<KeyDescriptor>(originalKeys.size + fakeKeys.size)
                    mergedList.addAll(originalKeys)

                    var injectedCount = 0
                    for (fakeKey in fakeKeys) {
                        val alias = fakeKey.alias
                        if (alias != null) {
                            if (existingAliases.add(alias)) {
                                mergedList.add(fakeKey)
                                injectedCount++
                                SystemLogger.debug(
                                    "[TX_ID: $txId] listEntries: Injected virtual key '$alias'"
                                )
                            } else {
                                SystemLogger.warning(
                                    "[TX_ID: $txId] listEntries: Skipped duplicate virtual key '$alias' (already in AOSP list)"
                                )
                            }
                        } else {
                            SystemLogger.warning(
                                "[TX_ID: $txId] listEntries: Skipped virtual key with null alias"
                            )
                        }
                    }

                    if (injectedCount <= 0) {
                        SystemLogger.warning(
                            "[TX_ID: $txId] listEntries: No virtual keys were injected (all duplicates or null aliases)"
                        )
                        return TransactionResult.SkipTransaction
                    }

                    mergedList.sortBy { it.alias }

                    val maxReplySize = 350_000 // ~350KB
                    var estimatedSize = 0
                    val finalList = ArrayList<KeyDescriptor>()
                    for (kd in mergedList) {
                        val entrySize = 16 + (kd.alias?.length ?: 0)
                        if (estimatedSize + entrySize > maxReplySize) {
                            SystemLogger.warning(
                                "[TX_ID: $txId] Truncating listEntries from ${mergedList.size} to ${finalList.size} entries (size limit ~350KB)."
                            )
                            break
                        }
                        finalList.add(kd)
                        estimatedSize += entrySize
                    }

                    SystemLogger.info(
                        "[TX_ID: $txId] Injecting $injectedCount virtual keys into listEntries (Manual Parcel). Total: ${finalList.size} entries."
                    )

                    val newReply = Parcel.obtain()
                    try {
                        newReply.writeNoException()
                        newReply.writeInt(finalList.size)
                        for (kd in finalList) {
                            writeKeyDescriptor(newReply, kd, encoding)
                        }
                    } catch (e: Exception) {
                        newReply.recycle()
                        throw e
                    }

                    TransactionResult.OverrideReply(newReply)
                }
                .getOrElse { e ->
                    SystemLogger.error("[TX_ID: $txId] Failed to inject listEntries reply.", e)
                    TransactionResult.SkipTransaction
                }
        }

        if (code == GET_KEY_ENTRY_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val keyDescriptor =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.SkipTransaction

            if (!ConfigurationManager.shouldPatch(callingUid))
                return TransactionResult.SkipTransaction

            SystemLogger.info("Handling post-${transactionNames[code]!!} ${keyDescriptor.alias}")
            return try {
                val response =
                    reply.readTypedObject(KeyEntryResponse.CREATOR)
                        ?: return TransactionResult.SkipTransaction
                reply.setDataPosition(0) // Reset for potential reuse.

                val originalChain = CertificateHelper.getCertificateChain(response)
                val authorizations = response.metadata?.authorizations
                val origin =
                    authorizations
                        ?.find { it.keyParameter.tag == Tag.ORIGIN }
                        ?.let { it.keyParameter.value.origin }

                if (origin == KeyOrigin.IMPORTED || origin == KeyOrigin.SECURELY_IMPORTED) {
                    SystemLogger.info("[TX_ID: $txId] Skip patching for imported keys.")
                    return TransactionResult.SkipTransaction
                }

                if (originalChain == null || originalChain.size < 2) {
                    SystemLogger.info(
                        "[TX_ID: $txId] Skip patching short certificate chain of length ${originalChain?.size}."
                    )
                    return TransactionResult.SkipTransaction
                }

                // Perform the attestation patch.
                val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)

                // First, try to retrieve the already-patched chain from our cache to ensure
                // consistency.
                val cachedChain = KeyMintSecurityLevelInterceptor.getPatchedChain(keyId)

                val finalChain: Array<Certificate>
                if (cachedChain != null) {
                    SystemLogger.debug(
                        "[TX_ID: $txId] Using cached patched certificate chain for $keyId."
                    )
                    finalChain = cachedChain
                } else {
                    // If no chain is cached (e.g., key existed before simulator started),
                    // perform a live patch as a fallback. This may still be detectable.
                    SystemLogger.info(
                        "[TX_ID: $txId] No cached chain for $keyId. Performing live patch as a fallback."
                    )
                    finalChain = AttestationPatcher.patchCertificateChain(originalChain, callingUid)
                }

                CertificateHelper.updateCertificateChain(response.metadata, finalChain).getOrThrow()

                InterceptorUtils.createTypedObjectReply(response)
            } catch (e: Exception) {
                SystemLogger.error("[TX_ID: $txId] Failed to patch certificate chain.", e)
                TransactionResult.SkipTransaction
            }
        }
        return TransactionResult.SkipTransaction
    }

    private data class KeyDescriptorEncoding(
        val hasPresenceMarker: Boolean,
        val hasParcelableSizeHeader: Boolean,
    )

    private fun detectKeyDescriptorEncoding(reply: Parcel, arrayLen: Int): KeyDescriptorEncoding {
        if (arrayLen <= 0) {
            val hasParcelableSizeHeader =
                runCatching {
                        KeyDescriptor::class
                            .java
                            .getDeclaredMethod("readFromParcel", Parcel::class.java)
                        true
                    }
                    .getOrDefault(false)
            return KeyDescriptorEncoding(
                hasPresenceMarker = false,
                hasParcelableSizeHeader = hasParcelableSizeHeader,
            )
        }

        val startPos = reply.dataPosition()
        val first = reply.readInt()

        val hasPresenceMarker = first == 1
        val probe = if (hasPresenceMarker) reply.readInt() else first

        val hasParcelableSizeHeader = probe >= 16

        reply.setDataPosition(startPos)
        return KeyDescriptorEncoding(hasPresenceMarker, hasParcelableSizeHeader)
    }

    private fun readKeyDescriptor(reply: Parcel, encoding: KeyDescriptorEncoding): KeyDescriptor? {
        if (encoding.hasPresenceMarker) {
            val present = reply.readInt()
            if (present == 0) return null
        }

        return if (encoding.hasParcelableSizeHeader) {
            val startPos = reply.dataPosition()
            val parcelableSize = reply.readInt()
            val endPos = startPos + parcelableSize

            val kd = KeyDescriptor()
            kd.domain = reply.readInt()
            kd.nspace = reply.readLong()
            kd.alias = reply.readString()
            kd.blob = reply.createByteArray()

            reply.setDataPosition(endPos)
            kd
        } else {
            val kd = KeyDescriptor()
            kd.domain = reply.readInt()
            kd.nspace = reply.readLong()
            kd.alias = reply.readString()
            kd.blob = reply.createByteArray()
            kd
        }
    }

    private fun writeKeyDescriptor(
        reply: Parcel,
        kd: KeyDescriptor,
        encoding: KeyDescriptorEncoding,
    ) {
        if (encoding.hasPresenceMarker) {
            reply.writeInt(1)
        }

        if (encoding.hasParcelableSizeHeader) {
            val startPos = reply.dataPosition()
            reply.writeInt(0)
            reply.writeInt(kd.domain)
            reply.writeLong(kd.nspace)
            reply.writeString(kd.alias)
            reply.writeByteArray(kd.blob)
            val endPos = reply.dataPosition()

            reply.setDataPosition(startPos)
            reply.writeInt(endPos - startPos)
            reply.setDataPosition(endPos)
        } else {
            reply.writeInt(kd.domain)
            reply.writeLong(kd.nspace)
            reply.writeString(kd.alias)
            reply.writeByteArray(kd.blob)
        }
    }
}
