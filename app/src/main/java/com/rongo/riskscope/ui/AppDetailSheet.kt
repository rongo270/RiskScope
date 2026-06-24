package com.rongo.riskscope.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.rongo.riskscope.model.AppRisk
import com.rongo.riskscope.model.ThreatLevel
import com.rongo.riskscope.ui.components.AppIcon
import com.rongo.riskscope.ui.components.ThreatBadge
import com.rongo.riskscope.ui.theme.visual
import java.text.DateFormat

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppDetailSheet(
    app: AppRisk,
    onDismiss: () -> Unit,
    onOpenSettings: (String) -> Unit,
    onUninstall: (String) -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState) {
        Column(
            Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(start = 20.dp, end = 20.dp, bottom = 28.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                AppIcon(app, size = 52)
                Column(Modifier.weight(1f).padding(horizontal = 14.dp)) {
                    Text(app.label, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                    Text(
                        app.packageName,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                ThreatBadge(app.threatLevel)
            }

            // Verdict banner
            val v = app.threatLevel.visual()
            Text(
                text = app.serverVerdict?.explanation ?: app.reason,
                style = MaterialTheme.typography.bodyMedium,
                color = v.color,
                fontWeight = FontWeight.Medium,
            )

            HorizontalDivider()

            FactRow("Version", app.versionName)
            FactRow("Type", if (app.isSystemApp) "System app" else "User app")
            FactRow("Install source", app.installSource)
            FactRow("APK SHA-256", app.apkSha256 ?: "Not hashed", mono = true)
            FactRow("Certificate SHA-256", app.certificateSha256, mono = true)
            FactRow("First installed", formatDate(app.firstInstallTime))
            FactRow("Last updated", formatDate(app.lastUpdateTime))

            app.serverVerdict?.signature?.takeIf { it.isNotBlank() }?.let { family ->
                FactRow("Malware family", family)
            }
            app.serverVerdict?.sources?.takeIf { it.isNotEmpty() }?.let { sources ->
                FactRow("Reported by", sources.joinToString(", "))
            }

            if (app.findings.isNotEmpty()) {
                HorizontalDivider()
                Text("Behavioural notes", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                app.findings.forEach { f ->
                    Column {
                        Text("• ${f.title}", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                        Text(
                            f.detail,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(start = 12.dp),
                        )
                    }
                }
            }

            if (app.dangerousPermissions.isNotEmpty()) {
                HorizontalDivider()
                Text(
                    "Dangerous permissions (${app.grantedDangerousPermissions.size} granted / ${app.dangerousPermissions.size} requested)",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    app.dangerousPermissions.joinToString("\n") {
                        val granted = it in app.grantedDangerousPermissions
                        (if (granted) "✓ " else "○ ") + it.substringAfterLast('.')
                    },
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                )
            }

            Row(
                Modifier.fillMaxWidth().padding(top = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                OutlinedButton(onClick = { onOpenSettings(app.packageName) }, modifier = Modifier.weight(1f)) {
                    Icon(Icons.AutoMirrored.Filled.OpenInNew, contentDescription = null, modifier = Modifier.padding(end = 6.dp))
                    Text("App info")
                }
                if (!app.isSystemApp) {
                    Button(
                        onClick = { onUninstall(app.packageName) },
                        modifier = Modifier.weight(1f),
                        colors = if (app.threatLevel == ThreatLevel.DANGER)
                            ButtonDefaults.buttonColors(containerColor = app.threatLevel.visual().color)
                        else ButtonDefaults.buttonColors(),
                    ) {
                        Icon(Icons.Filled.Delete, contentDescription = null, modifier = Modifier.padding(end = 6.dp))
                        Text("Uninstall")
                    }
                }
            }
        }
    }
}

@Composable
private fun FactRow(label: String, value: String, mono: Boolean = false) {
    Column {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = if (mono) FontFamily.Monospace else FontFamily.Default,
        )
    }
}

private fun formatDate(timestamp: Long): String {
    if (timestamp <= 0L) return "Unknown"
    return DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(timestamp)
}
