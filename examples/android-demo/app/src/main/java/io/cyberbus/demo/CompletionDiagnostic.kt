package io.cyberbus.demo

import com.google.protobuf.ByteString
import cyberbus.easytier.v1.Common.ErrorCode

/** Debug-only projection. Never retains a payload, ProtocolError, URI or auth object. */
internal data class CompletionDiagnostic(
    val kind: Kind,
    val peerDeviceId: ByteString,
    val messageId: ByteString,
    val commandId: ByteString? = null,
    val foregroundReady: Boolean? = null,
    val completion: Completion? = null,
    val result: Result? = null,
    val errorCode: ErrorCode? = null,
    val correlated: Boolean? = null,
    val localFailure: LocalFailure? = null,
) {
    enum class Kind {
        DATA_IMMEDIATE, DATA_DEFERRED, DATA_RELEASED, DATA_CLEARED, DATA_QUEUE_FULL,
        COMPLETE_QUEUED, COMPLETE_ENTERED, COMPLETE_RESULT, COMPLETE_LOCAL_FAILURE
    }
    enum class Completion { PROCESSED, TYPE_MISMATCH, RESOURCE_EXHAUSTED, OTHER }
    enum class Result { OK, ERROR, UNEXPECTED_BODY }
    enum class LocalFailure { EXECUTION_EXCEPTION, INVALID_RESULT, ABI_ERROR }
}
