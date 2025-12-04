package org.matrix.TEESimulator.logging

import android.util.Log
import org.matrix.TEESimulator.BuildConfig

/**
 * A centralized logging utility for the TEESimulator application. This object provides a consistent
 * logging tag and format for all application logs, making it easier to filter and debug in Logcat.
 */
object SystemLogger {
    // The tag used for all log messages from this application.
    private const val TAG = "TEESimulator"

    private val isDebugBuild = BuildConfig.DEBUG

    /**
     * Logs a debug message. Use this for fine-grained information that is useful for debugging.
     *
     * @param message The message to log.
     */
    fun debug(message: String) {
        Log.d(TAG, message)
    }

    /**
     * Logs an informational message. Use this to report major application lifecycle events.
     *
     * @param message The message to log.
     */
    fun info(message: String) {
        Log.i(TAG, message)
    }

    /**
     * Logs a warning message. Use this to report unexpected but non-fatal issues.
     *
     * @param message The message to log.
     * @param throwable An optional exception to log with the message.
     */
    fun warning(message: String, throwable: Throwable? = null) {
        if (throwable != null) {
            Log.w(TAG, message, throwable)
        } else {
            Log.w(TAG, message)
        }
    }

    /**
     * Logs an error message. Use this to report fatal errors or exceptions that disrupt
     * functionality.
     *
     * @param message The message to log.
     * @param throwable An optional exception to log with the message.
     */
    fun error(message: String, throwable: Throwable? = null) {
        if (throwable != null) {
            Log.e(TAG, message, throwable)
        } else {
            Log.e(TAG, message)
        }
    }

    /**
     * Logs a verbose message. This level is for highly detailed logs that are generally not needed
     * unless tracking a very specific issue.
     *
     * @param message The message to log.
     */
    fun verbose(message: String) {
        if (!isDebugBuild) return
        Log.v(TAG, message)
    }
}
