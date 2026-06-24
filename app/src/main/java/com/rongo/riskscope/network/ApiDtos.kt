package com.rongo.riskscope.network

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** Request body for POST /api/check/batch */
@Serializable
data class BatchRequest(val hashes: List<String>)

/** One verdict as returned by /api/check and inside /api/check/batch results. */
@Serializable
data class HashVerdictDto(
    val hash: String? = null,
    @SerialName("is_malicious") val isMalicious: Boolean = false,
    @SerialName("match_type") val matchType: String = "none",
    val source: String? = null,
    val sources: List<String> = emptyList(),
    val signature: String? = null,
    @SerialName("file_type") val fileType: String? = null,
    val explanation: String = "",
)

/** Response body for POST /api/check/batch */
@Serializable
data class BatchResponse(
    val checked: Int = 0,
    val malicious: Int = 0,
    val results: List<HashVerdictDto> = emptyList(),
)

/** Response body for GET /api/stats */
@Serializable
data class StatsDto(
    @SerialName("malicious_hashes") val maliciousHashes: Long = 0,
    val sha256: Long = 0,
    val sha1: Long = 0,
    val md5: Long = 0,
    @SerialName("whitelisted_hashes") val whitelistedHashes: Long = 0,
)
