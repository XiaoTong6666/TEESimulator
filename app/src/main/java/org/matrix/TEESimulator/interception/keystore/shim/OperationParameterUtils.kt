package org.matrix.TEESimulator.interception.keystore.shim

import android.os.ServiceSpecificException

internal fun <T> List<T>.requireExactlyOneValue(errorCode: Int, valueLabel: String): T =
    when (size) {
        1 -> single()
        0 -> throw ServiceSpecificException(errorCode, "No $valueLabel specified")
        else ->
            throw ServiceSpecificException(errorCode, "Exactly one $valueLabel must be specified")
    }

internal fun <T> List<T>.requireAtMostOneValue(errorCode: Int, valueLabel: String): T? =
    when (size) {
        0 -> null
        1 -> single()
        else ->
            throw ServiceSpecificException(errorCode, "Exactly one $valueLabel must be specified")
    }
