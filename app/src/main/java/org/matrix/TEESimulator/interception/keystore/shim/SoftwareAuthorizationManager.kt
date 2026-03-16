package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.HardwareAuthToken
import android.os.SystemClock
import android.security.keymaster.KeymasterDefs
import android.os.ServiceSpecificException
import android.system.keystore2.OperationChallenge
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicReference
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.logging.SystemLogger

internal sealed interface DeferredAuthState {
    data object NoAuthRequired : DeferredAuthState

    data class OpAuthRequired(val challenge: Long) : DeferredAuthState

    data class Token(val token: CachedAuthToken) : DeferredAuthState
}

internal data class CachedAuthToken(
    val token: HardwareAuthToken,
    val receivedAtElapsedRealtime: Long,
) {
    fun satisfies(userSecureIds: List<Long>, authType: Int): Boolean =
        userSecureIds.any { sid ->
            (sid == token.userId || sid == token.authenticatorId) &&
                ((authType and token.authenticatorType) != 0)
        }

    fun ageSeconds(nowElapsedRealtime: Long): Long =
        (nowElapsedRealtime - receivedAtElapsedRealtime).coerceAtLeast(0L) / 1000L
}

internal class SoftwareAuthInfo(
    private val txId: Long,
    private val userSecureIds: List<Long>,
    private val authType: Int?,
    private val authTimeoutSeconds: Int?,
    private val trustedConfirmationRequired: Boolean,
    initialState: DeferredAuthState,
) {
    private val state = AtomicReference(initialState)
    private val opAuthChallenge =
        (initialState as? DeferredAuthState.OpAuthRequired)?.challenge

    fun finalizeCreateAuthorization(): OperationChallenge? {
        if (opAuthChallenge != null) {
            return OperationChallenge().apply { challenge = opAuthChallenge }
        }
        return null
    }

    fun beforeUpdate() {
        ensureAuthenticated("update")
    }

    fun beforeFinish() {
        ensureAuthenticated("finish")
        if (trustedConfirmationRequired) {
            throw unsupportedAuthFeature(
                "Trusted confirmation is not yet wired into the software operation path",
            )
        }
    }

    fun onAuthToken(cachedToken: CachedAuthToken): Boolean {
        if (!matches(cachedToken)) return false
        val updated = state.updateAndGet { current ->
            when (current) {
                is DeferredAuthState.OpAuthRequired -> DeferredAuthState.Token(cachedToken)
                else -> current
            }
        }
        val accepted = updated is DeferredAuthState.Token && updated.token == cachedToken
        if (accepted) {
            SystemLogger.debug(
                "[SoftwareOp TX_ID: $txId] Received matching per-op auth token for challenge ${cachedToken.token.challenge}.",
            )
        }
        return accepted
    }

    private fun ensureAuthenticated(stage: String) {
        when (val current = state.get()) {
            is DeferredAuthState.NoAuthRequired -> Unit
            is DeferredAuthState.Token -> {
                if (authTimeoutSeconds != null) {
                    val ageSeconds = current.token.ageSeconds(SystemClock.elapsedRealtime())
                    if (ageSeconds > authTimeoutSeconds.toLong()) {
                        throw keyUserNotAuthenticated(
                            "Auth token expired before $stage ($ageSeconds s > $authTimeoutSeconds s)",
                        )
                    }
                }
            }
            is DeferredAuthState.OpAuthRequired ->
                throw keyUserNotAuthenticated(
                    "Per-op auth token not yet received for challenge ${current.challenge}",
                )
        }
    }

    private fun matches(cachedToken: CachedAuthToken): Boolean {
        val authType = this.authType ?: return false
        return cachedToken.satisfies(userSecureIds, authType)
    }

    fun operationChallenge(): Long? = opAuthChallenge
}

internal object SoftwareAuthorizationManager {
    private val secureRandom = SecureRandom()
    private val cachedAuthTokens = CopyOnWriteArrayList<CachedAuthToken>()
    private val pendingOperations = ConcurrentHashMap<Long, SoftwareAuthInfo>()

    fun authorizeCreate(txId: Long, keyParams: KeyMintAttestation): SoftwareAuthInfo {
        if (keyParams.userSecureIds.isNotEmpty() && keyParams.noAuthRequired == true) {
            throw invalidKeyBlob(
                "Key has both NO_AUTH_REQUIRED and USER_SECURE_ID tags",
            )
        }
        if ((keyParams.hardwareAuthenticatorType != null) != keyParams.userSecureIds.isNotEmpty()) {
            throw keyUserNotAuthenticated(
                "Auth required, but auth type and secure IDs are inconsistently specified",
            )
        }

        if (keyParams.userSecureIds.isEmpty()) {
            return SoftwareAuthInfo(
                txId = txId,
                userSecureIds = emptyList(),
                authType = null,
                authTimeoutSeconds = null,
                trustedConfirmationRequired = keyParams.trustedConfirmationRequired == true,
                initialState = DeferredAuthState.NoAuthRequired,
            )
        }

        val authType =
            keyParams.hardwareAuthenticatorType
                ?: throw keyUserNotAuthenticated("Missing HARDWARE_AUTHENTICATOR_TYPE")

        val initialState =
            if (keyParams.authTimeout != null) {
                DeferredAuthState.Token(
                    findMatchingAuthToken(keyParams.userSecureIds, authType)
                        ?: throw keyUserNotAuthenticated(
                            "No suitable auth token found for timeout-bound key",
                        ),
                )
            } else {
                val challenge = nextChallenge()
                DeferredAuthState.OpAuthRequired(challenge).also {
                    SystemLogger.debug(
                        "[SoftwareOp TX_ID: $txId] Created per-op auth challenge $challenge.",
                    )
                }
            }

        return SoftwareAuthInfo(
            txId = txId,
            userSecureIds = keyParams.userSecureIds,
            authType = authType,
            authTimeoutSeconds = keyParams.authTimeout,
            trustedConfirmationRequired = keyParams.trustedConfirmationRequired == true,
            initialState = initialState,
        ).also { info ->
            val state = info.finalizeCreateAuthorization()
            if (state != null) {
                pendingOperations[state.challenge] = info
            }
        }
    }

    fun onOperationFinished(authInfo: SoftwareAuthInfo?) {
        authInfo?.operationChallenge()?.let { pendingOperations.remove(it) }
    }

    fun addAuthToken(authToken: HardwareAuthToken) {
        val cached = CachedAuthToken(authToken, SystemClock.elapsedRealtime())
        cachedAuthTokens += cached

        pendingOperations.remove(authToken.challenge)?.let { authInfo ->
            if (!authInfo.onAuthToken(cached)) {
                pendingOperations[authToken.challenge] = authInfo
            }
        }
    }

    private fun findMatchingAuthToken(
        userSecureIds: List<Long>,
        authType: Int,
    ): CachedAuthToken? =
        cachedAuthTokens
            .filter { it.satisfies(userSecureIds, authType) }
            .maxByOrNull { it.receivedAtElapsedRealtime }

    private fun nextChallenge(): Long {
        var challenge: Long
        do {
            challenge = secureRandom.nextLong()
        } while (challenge == 0L || pendingOperations.containsKey(challenge))
        return challenge
    }
}

private fun keyUserNotAuthenticated(message: String): ServiceSpecificException =
    ServiceSpecificException(KeymasterDefs.KM_ERROR_KEY_USER_NOT_AUTHENTICATED, message)

private fun invalidKeyBlob(message: String): ServiceSpecificException =
    ServiceSpecificException(KeymasterDefs.KM_ERROR_INVALID_KEY_BLOB, message)

private val noUserConfirmationErrorCode: Int by lazy {
    runCatching { KeymasterDefs::class.java.getField("KM_ERROR_NO_USER_CONFIRMATION").getInt(null) }
        .getOrDefault(KeymasterDefs.KM_ERROR_INVALID_ARGUMENT)
}

private fun unsupportedAuthFeature(message: String): ServiceSpecificException =
    ServiceSpecificException(noUserConfirmationErrorCode, message)
