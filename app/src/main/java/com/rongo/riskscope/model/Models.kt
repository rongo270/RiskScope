package com.rongo.riskscope.model

import android.graphics.drawable.Drawable

/**
 * The headline classification shown for an app.
 *
 * DANGER  – the APK's hash matches a KNOWN malware sample in the server database
 *           (definitive). This is the real signal; it does not fire for normal apps.
 * WATCH   – no known-malware match, but the on-device heuristics found a genuinely
 *           notable combination worth a manual review (advisory only).
 * SAFE    – not known malware and nothing notable. Normal apps land here.
 */
enum class ThreatLevel { SAFE, WATCH, DANGER }

enum class Severity { LOW, MEDIUM, HIGH }

/** A single behavioural observation from the on-device heuristic analyzer. */
data class RiskFinding(
    val severity: Severity,
    val title: String,
    val detail: String,
    val weight: Int,
)

/** Server answer for one file hash (mapped from the API response). */
data class ServerVerdict(
    val isMalicious: Boolean,
    val matchType: String,
    val source: String?,
    val sources: List<String>,
    val signature: String?,
    val fileType: String?,
    val explanation: String,
)

/** Everything we know about one installed app after a scan. */
data class AppRisk(
    val label: String,
    val packageName: String,
    val versionName: String,
    val apkSha256: String?,
    val certificateSha256: String,
    val installSource: String,
    val trustedInstaller: Boolean,
    val isSystemApp: Boolean,
    val enabled: Boolean,
    val hasLauncher: Boolean,
    val firstInstallTime: Long,
    val lastUpdateTime: Long,
    val heuristicScore: Int,
    val findings: List<RiskFinding>,
    val dangerousPermissions: List<String>,
    val grantedDangerousPermissions: List<String>,
    val serverVerdict: ServerVerdict?,
    val threatLevel: ThreatLevel,
    val reason: String,
    val icon: Drawable?,
)

/** Aggregate view of the whole device after a scan. */
data class DeviceSummary(
    val scannedCount: Int,
    val hashedCount: Int,
    val dangerCount: Int,
    val watchCount: Int,
    val safeCount: Int,
    val scanMillis: Long,
    val serverReachable: Boolean,
) {
    val headline: String
        get() = when {
            !serverReachable && dangerCount == 0 ->
                "Threat database unreachable - showing on-device heuristics only."
            dangerCount > 0 -> "$dangerCount known threat${if (dangerCount == 1) "" else "s"} found"
            watchCount > 0 -> "No known malware - $watchCount app${if (watchCount == 1) "" else "s"} to review"
            else -> "No known malware detected"
        }
}

data class ScanResult(
    val summary: DeviceSummary,
    val apps: List<AppRisk>,
)

/** Progress phases surfaced to the UI while a scan runs. */
sealed interface ScanUiState {
    data object Idle : ScanUiState
    data class Scanning(val phase: String, val fraction: Float) : ScanUiState
    data class Success(val result: ScanResult) : ScanUiState
    data class Error(val message: String) : ScanUiState
}
