package com.rongo.riskscope.ui

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.rongo.riskscope.model.AppRisk
import com.rongo.riskscope.model.ScanUiState
import com.rongo.riskscope.ui.components.AppRiskRow
import com.rongo.riskscope.ui.components.ScanSummaryCard

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanScreen(viewModel: ScanViewModel, onOpenSettings: () -> Unit) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    var selected by remember { mutableStateOf<AppRisk?>(null) }
    val context = LocalContext.current

    val scanning = state is ScanUiState.Scanning

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Filled.Security, contentDescription = null)
                        Text("  RiskScope", fontWeight = FontWeight.Bold)
                    }
                },
                actions = {
                    IconButton(onClick = onOpenSettings) {
                        Icon(Icons.Filled.Settings, contentDescription = "Settings")
                    }
                },
            )
        },
        floatingActionButton = {
            if (state !is ScanUiState.Idle) {
                ExtendedFloatingActionButton(
                    onClick = { if (!scanning) viewModel.scan() },
                    text = { Text(if (scanning) "Scanning…" else "Rescan") },
                    icon = {
                        if (scanning) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                        else Icon(Icons.Filled.Refresh, contentDescription = null)
                    },
                )
            }
        },
    ) { padding ->
        when (val s = state) {
            is ScanUiState.Idle -> WelcomeView(padding, onScan = { viewModel.scan() })
            is ScanUiState.Scanning -> ScanningView(padding, s)
            is ScanUiState.Error -> CenterMessage(padding, "Scan failed: ${s.message}")
            is ScanUiState.Success -> ResultList(padding, s, onClick = { selected = it })
        }
    }

    selected?.let { app ->
        AppDetailSheet(
            app = app,
            onDismiss = { selected = null },
            onOpenSettings = { pkg -> openAppSettings(context, pkg) },
            onUninstall = { pkg -> uninstall(context, pkg) },
        )
    }
}

@Composable
private fun WelcomeView(padding: PaddingValues, onScan: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(padding).padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(
            Icons.Filled.Security,
            contentDescription = null,
            modifier = Modifier.size(72.dp),
            tint = MaterialTheme.colorScheme.primary,
        )
        Text(
            "Ready to scan",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(top = 16.dp),
        )
        Text(
            "Check your installed apps against known threats.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(top = 8.dp),
        )
        Button(
            onClick = onScan,
            modifier = Modifier.padding(top = 24.dp),
        ) {
            Icon(Icons.Filled.Search, contentDescription = null, modifier = Modifier.size(18.dp))
            Text("  Scan now")
        }
    }
}

@Composable
private fun ResultList(padding: PaddingValues, state: ScanUiState.Success, onClick: (AppRisk) -> Unit) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(padding),
        contentPadding = PaddingValues(16.dp, 8.dp, 16.dp, 96.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item { ScanSummaryCard(state.result) }
        items(state.result.apps, key = { it.packageName }) { app ->
            AppRiskRow(app, onClick = { onClick(app) })
        }
    }
}

@Composable
private fun ScanningView(padding: PaddingValues, state: ScanUiState.Scanning) {
    Column(
        modifier = Modifier.fillMaxSize().padding(padding).padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(state.phase, style = MaterialTheme.typography.titleMedium)
        LinearProgressIndicator(
            progress = { state.fraction },
            modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
        )
    }
}

@Composable
private fun CenterMessage(padding: PaddingValues, message: String) {
    Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
        Text(message, style = MaterialTheme.typography.bodyLarge)
    }
}

private fun openAppSettings(context: android.content.Context, packageName: String) {
    val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName"))
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    try {
        context.startActivity(intent)
    } catch (e: Exception) {
        context.startActivity(Intent(Settings.ACTION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }
}

private fun uninstall(context: android.content.Context, packageName: String) {
    val intent = Intent(Intent.ACTION_DELETE, Uri.parse("package:$packageName"))
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    try {
        context.startActivity(intent)
    } catch (e: Exception) {
        openAppSettings(context, packageName)
    }
}
