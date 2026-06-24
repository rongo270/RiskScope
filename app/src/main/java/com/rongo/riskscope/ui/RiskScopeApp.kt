package com.rongo.riskscope.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.lifecycle.viewmodel.compose.viewModel

/** Root composable: a simple two-screen flow (Scan ⇄ Settings) backed by one ViewModel. */
@Composable
fun RiskScopeApp() {
    val viewModel: ScanViewModel = viewModel()
    var showSettings by rememberSaveable { mutableStateOf(false) }

    if (showSettings) {
        SettingsScreen(viewModel, onBack = { showSettings = false })
    } else {
        ScanScreen(viewModel, onOpenSettings = { showSettings = true })
    }
}
