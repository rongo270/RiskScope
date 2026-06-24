package com.rongo.riskscope.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.rongo.riskscope.ui.theme.RiskDanger
import com.rongo.riskscope.ui.theme.RiskSafe

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(viewModel: ScanViewModel, onBack: () -> Unit) {
    val savedUrl by viewModel.baseUrl.collectAsStateWithLifecycle()
    val scanSystem by viewModel.scanSystemApps.collectAsStateWithLifecycle()
    val connection by viewModel.connection.collectAsStateWithLifecycle()
    var url by remember(savedUrl) { mutableStateOf(savedUrl) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text("Threat database server", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text(
                "The RiskScope-Server URL (your Render deployment). The app checks every installed APK's SHA-256 against it.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = url,
                onValueChange = { url = it },
                label = { Text("Server URL") },
                placeholder = { Text("https://your-app.onrender.com") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(
                    onClick = { viewModel.updateBaseUrl(url); viewModel.testConnection() },
                    modifier = Modifier.weight(1f),
                ) { Text("Save & test") }
                OutlinedButton(
                    onClick = { viewModel.testConnection() },
                    modifier = Modifier.weight(1f),
                ) { Text("Test") }
            }

            ConnectionStatus(connection)

            Row(
                Modifier.fillMaxWidth().padding(top = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text("Scan system apps", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    Text(
                        "Also hash & check pre-installed apps. Slower; usually unnecessary.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(checked = scanSystem, onCheckedChange = { viewModel.setScanSystemApps(it) })
            }
        }
    }
}

@Composable
private fun ConnectionStatus(connection: ConnectionState) {
    when (connection) {
        is ConnectionState.Idle -> Unit
        is ConnectionState.Testing -> Row(verticalAlignment = Alignment.CenterVertically) {
            CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
            Text("  Contacting server…", style = MaterialTheme.typography.bodyMedium)
        }
        is ConnectionState.Ok -> Text(
            "✓ Connected — ${connection.stats.maliciousHashes} malware hashes in database " +
                "(${connection.stats.sha256} SHA-256).",
            color = RiskSafe,
            fontWeight = FontWeight.Medium,
            fontFamily = FontFamily.Default,
        )
        is ConnectionState.Failed -> Text(
            "✗ ${connection.message}",
            color = RiskDanger,
            fontWeight = FontWeight.Medium,
        )
    }
}
