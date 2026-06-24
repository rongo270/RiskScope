package com.rongo.riskscope.ui.theme

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.GppBad
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import com.rongo.riskscope.model.ThreatLevel

data class RiskVisual(
    val color: Color,
    val container: Color,
    val label: String,
    val icon: ImageVector,
)

fun ThreatLevel.visual(): RiskVisual = when (this) {
    ThreatLevel.DANGER -> RiskVisual(RiskDanger, RiskDangerContainer, "Threat", Icons.Filled.GppBad)
    ThreatLevel.WATCH -> RiskVisual(RiskWatch, RiskWatchContainer, "Review", Icons.Filled.WarningAmber)
    ThreatLevel.SAFE -> RiskVisual(RiskSafe, RiskSafeContainer, "Clean", Icons.Filled.VerifiedUser)
}
