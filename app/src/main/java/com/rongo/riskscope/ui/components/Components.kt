@file:OptIn(ExperimentalMaterial3Api::class)

package com.rongo.riskscope.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import coil.compose.AsyncImage
import com.rongo.riskscope.model.AppRisk
import com.rongo.riskscope.model.ScanResult
import com.rongo.riskscope.model.ThreatLevel
import com.rongo.riskscope.ui.theme.RiskDanger
import com.rongo.riskscope.ui.theme.RiskSafe
import com.rongo.riskscope.ui.theme.RiskWatch
import com.rongo.riskscope.ui.theme.visual

@Composable
fun ThreatBadge(level: ThreatLevel, modifier: Modifier = Modifier) {
    val v = level.visual()
    Row(
        modifier = modifier
            .clip(RoundedCornerShape(50))
            .background(v.container)
            .padding(horizontal = 10.dp, vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(v.icon, contentDescription = null, tint = v.color, modifier = Modifier.size(15.dp))
        Text(
            v.label,
            color = v.color,
            fontSize = 12.sp,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(start = 5.dp),
        )
    }
}

@Composable
fun ScanSummaryCard(result: ScanResult, modifier: Modifier = Modifier) {
    val s = result.summary
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Column(Modifier.padding(20.dp)) {
            Text(
                s.headline,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
            Row(
                Modifier.fillMaxWidth().padding(top = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                CountChip("Threats", s.dangerCount, RiskDanger, Modifier.weight(1f))
                CountChip("Review", s.watchCount, RiskWatch, Modifier.weight(1f))
                CountChip("Clean", s.safeCount, RiskSafe, Modifier.weight(1f))
            }
            Text(
                buildString {
                    append("${s.scannedCount} apps · ${s.hashedCount} hashed · ${s.scanMillis} ms")
                    append(if (s.serverReachable) " · DB online" else " · DB offline")
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 12.dp),
            )
        }
    }
}

@Composable
private fun CountChip(label: String, count: Int, color: Color, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(14.dp))
            .background(color.copy(alpha = 0.12f))
            .padding(vertical = 12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("$count", color = color, fontSize = 22.sp, fontWeight = FontWeight.Bold)
        Text(label, color = color, fontSize = 12.sp)
    }
}

@Composable
fun AppRiskRow(app: AppRisk, onClick: () -> Unit, modifier: Modifier = Modifier) {
    Card(
        modifier = modifier.fillMaxWidth(),
        onClick = onClick,
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Row(
            Modifier.fillMaxWidth().padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            AppIcon(app)
            Column(Modifier.weight(1f).padding(horizontal = 12.dp)) {
                Text(
                    app.label,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                )
                Text(
                    app.reason,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                )
            }
            ThreatBadge(app.threatLevel)
        }
    }
}

@Composable
fun AppIcon(app: AppRisk, size: Int = 44) {
    if (app.icon != null) {
        AsyncImage(
            model = app.icon,
            contentDescription = app.label,
            modifier = Modifier.size(size.dp).clip(RoundedCornerShape(12.dp)),
        )
    } else {
        Box(
            Modifier
                .size(size.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(MaterialTheme.colorScheme.surfaceVariant),
            contentAlignment = Alignment.Center,
        ) {
            Text(app.label.take(1).uppercase(), fontWeight = FontWeight.Bold)
        }
    }
}
