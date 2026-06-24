package com.rongo.riskscope.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.rongo.riskscope.data.SettingsStore
import com.rongo.riskscope.model.AppRisk
import com.rongo.riskscope.model.ScanUiState
import com.rongo.riskscope.network.HashCheckRepository
import com.rongo.riskscope.network.StatsDto
import com.rongo.riskscope.scan.AppScanner
import com.rongo.riskscope.scan.VerdictEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ScanViewModel(app: Application) : AndroidViewModel(app) {

    private val settings = SettingsStore(app)
    private val scanner = AppScanner(app)
    private val repository = HashCheckRepository()

    val baseUrl: StateFlow<String> = settings.baseUrl
    val scanSystemApps: StateFlow<Boolean> = settings.scanSystemApps

    private val _uiState = MutableStateFlow<ScanUiState>(ScanUiState.Idle)
    val uiState: StateFlow<ScanUiState> = _uiState.asStateFlow()

    private val _connection = MutableStateFlow<ConnectionState>(ConnectionState.Idle)
    val connection: StateFlow<ConnectionState> = _connection.asStateFlow()

    fun scan() {
        if (_uiState.value is ScanUiState.Scanning) return
        viewModelScope.launch {
            val started = System.currentTimeMillis()
            try {
                _uiState.value = ScanUiState.Scanning("Reading installed apps…", 0.05f)
                val includeSystem = settings.scanSystemApps.value

                val scanned = withContext(Dispatchers.IO) {
                    scanner.scan(includeSystem) { done, total ->
                        val frac = if (total == 0) 0f else done.toFloat() / total
                        _uiState.value = ScanUiState.Scanning(
                            "Hashing apps ($done/$total)…", 0.05f + 0.70f * frac
                        )
                    }
                }

                _uiState.value = ScanUiState.Scanning("Checking threat database…", 0.80f)
                val hashes = scanned.mapNotNull { it.apkSha256 }
                var serverReachable = true
                val verdicts = try {
                    repository.batchCheck(settings.baseUrl.value, hashes)
                } catch (e: Exception) {
                    serverReachable = false
                    emptyMap()
                }

                _uiState.value = ScanUiState.Scanning("Finishing…", 0.95f)
                val apps: List<AppRisk> = scanned.map { s ->
                    VerdictEngine.finalize(s, s.apkSha256?.let { verdicts[it.lowercase()] })
                }
                val result = VerdictEngine.buildResult(
                    apps, System.currentTimeMillis() - started, serverReachable
                )
                _uiState.value = ScanUiState.Success(result)
            } catch (e: Exception) {
                _uiState.value = ScanUiState.Error(e.message ?: e.javaClass.simpleName)
            }
        }
    }

    fun updateBaseUrl(url: String) {
        settings.setBaseUrl(url)
        _connection.value = ConnectionState.Idle
    }

    fun setScanSystemApps(value: Boolean) = settings.setScanSystemApps(value)

    fun testConnection() {
        viewModelScope.launch {
            _connection.value = ConnectionState.Testing
            _connection.value = try {
                val stats = repository.fetchStats(settings.baseUrl.value)
                ConnectionState.Ok(stats)
            } catch (e: Exception) {
                ConnectionState.Failed(e.message ?: "Could not reach the server")
            }
        }
    }
}

sealed interface ConnectionState {
    data object Idle : ConnectionState
    data object Testing : ConnectionState
    data class Ok(val stats: StatsDto) : ConnectionState
    data class Failed(val message: String) : ConnectionState
}
