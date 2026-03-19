package org.matrix.TEESimulator.util

import android.hardware.security.keymint.Algorithm
import java.security.SecureRandom
import java.util.concurrent.locks.LockSupport
import kotlin.math.abs
import kotlin.math.exp
import kotlin.math.ln
import kotlin.math.max

/**
 * Simulates realistic TEE hardware latency for software key generation.
 *
 * The delay model is derived from 64+ timing measurements across QTEE (Qualcomm) and Trustonic
 * (MediaTek) hardware. It combines four independent noise sources that model different physical
 * latency origins in a real TrustZone-based TEE:
 *
 * 1. Base crypto processing (log-normal): hardware RNG + key derivation + cert signing
 * 2. Binder/kernel transit (exponential): IPC scheduling, context switches
 * 3. TrustZone scheduler jitter (Gaussian): world-switch non-determinism
 * 4. Cold-start penalty (half-normal): first operation after idle is slower due to TEE
 *    secure world re-initialization and TLB/cache warming
 *
 * Per-boot session bias models manufacturing variance between TEE hardware instances.
 */
object TeeLatencySimulator {

    private val rng = SecureRandom()

    private val sessionBiasMs: Double by lazy { rng.nextGaussian() * 5.0 }
    private val coldPenaltyMs: Double by lazy { abs(rng.nextGaussian() * 12.0) }

    @Volatile private var firstCall = true

    fun simulateGenerateKeyDelay(algorithm: Int, elapsedNanos: Long) {
        val elapsedMs = elapsedNanos / 1_000_000.0
        val targetMs = sampleTotalDelay(algorithm)
        val remainingMs = targetMs - elapsedMs

        if (remainingMs > 1.0) {
            LockSupport.parkNanos((remainingMs * 1_000_000).toLong())
        }
    }

    private fun sampleTotalDelay(algorithm: Int): Double {
        val base = sampleBaseCryptoDelay(algorithm)
        val transit = sampleExponential(2.5)
        val jitter = (rng.nextGaussian() * 2.5).coerceIn(-8.0, 12.0)

        var cold = 0.0
        if (firstCall) {
            firstCall = false
            cold = coldPenaltyMs
        }

        return max(20.0, base + transit + jitter + sessionBiasMs + cold)
    }

    /**
     * Log-normal base delay. Parameters tuned to match observed hardware profiles:
     * EC P-256 on QTEE averages ~65ms, RSA-2048 ~75ms, AES ~40ms.
     * Sigma kept low (0.08) to match the tight clustering seen in real measurements.
     */
    private fun sampleBaseCryptoDelay(algorithm: Int): Double {
        val (mu, sigma) =
            when (algorithm) {
                Algorithm.EC -> ln(60.0) to 0.08
                Algorithm.RSA -> ln(70.0) to 0.08
                Algorithm.AES -> ln(35.0) to 0.10
                else -> ln(40.0) to 0.10
            }
        return sampleLogNormal(mu, sigma)
    }

    private fun sampleLogNormal(mu: Double, sigma: Double): Double {
        return exp(mu + sigma * rng.nextGaussian())
    }

    private fun sampleExponential(mean: Double): Double {
        var u = rng.nextDouble()
        while (u == 0.0) u = rng.nextDouble()
        return -mean * ln(u)
    }
}
