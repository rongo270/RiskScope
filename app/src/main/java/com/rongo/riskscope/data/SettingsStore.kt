package com.rongo.riskscope.data

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Small SharedPreferences-backed settings store, exposed as StateFlows so Compose
 * recomposes when the server URL or options change.
 */
class SettingsStore(context: Context) {

    private val prefs = context.applicationContext
        .getSharedPreferences("riskscope_settings", Context.MODE_PRIVATE)

    private val _baseUrl = MutableStateFlow(prefs.getString(KEY_BASE_URL, DEFAULT_BASE_URL) ?: DEFAULT_BASE_URL)
    val baseUrl: StateFlow<String> = _baseUrl.asStateFlow()

    private val _scanSystemApps = MutableStateFlow(prefs.getBoolean(KEY_SCAN_SYSTEM, false))
    val scanSystemApps: StateFlow<Boolean> = _scanSystemApps.asStateFlow()

    fun setBaseUrl(value: String) {
        val v = value.trim()
        prefs.edit().putString(KEY_BASE_URL, v).apply()
        _baseUrl.value = v
    }

    fun setScanSystemApps(value: Boolean) {
        prefs.edit().putBoolean(KEY_SCAN_SYSTEM, value).apply()
        _scanSystemApps.value = value
    }

    companion object {
        // Replace with your Render URL (Settings screen lets you change it at runtime).
        const val DEFAULT_BASE_URL = "https://riskscope-backend.onrender.com"
        private const val KEY_BASE_URL = "base_url"
        private const val KEY_SCAN_SYSTEM = "scan_system_apps"
    }
}
