package com.rongo.riskscope

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.rongo.riskscope.ui.RiskScopeApp
import com.rongo.riskscope.ui.theme.RiskScopeTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            RiskScopeTheme {
                RiskScopeApp()
            }
        }
    }
}
