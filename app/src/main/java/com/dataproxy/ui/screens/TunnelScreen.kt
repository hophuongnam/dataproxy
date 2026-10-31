package com.dataproxy.ui.screens

import android.content.Context
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.dataproxy.proxy.ReverseTunnel
import com.dataproxy.service.ProxyService
import com.dataproxy.ui.theme.Accent
import com.dataproxy.ui.theme.OutlineSoft
import com.dataproxy.ui.theme.OutlineStrong
import com.dataproxy.ui.theme.SurfaceLow
import com.dataproxy.ui.theme.SurfaceMid
import com.dataproxy.ui.theme.TextPrimary
import com.dataproxy.ui.theme.TextSecondary
import com.dataproxy.ui.viewmodel.MainViewModel

/**
 * Reverse tunnel settings. ProxyService reads these once per start, so the
 * fields are locked while the proxy runs, same rule as the Listen screen.
 *
 * ponytail: reads and writes prefs directly instead of six StateFlows on
 * MainViewModel, nothing else observes these keys.
 */
@Composable
fun TunnelScreen(
    viewModel: MainViewModel,
    onBack: () -> Unit,
) {
    BackHandler(onBack = onBack)
    val prefs = LocalContext.current
        .getSharedPreferences(ProxyService.PREFS_NAME, Context.MODE_PRIVATE)
    val serviceState by viewModel.serviceState.collectAsStateWithLifecycle()
    val status by viewModel.tunnelStatus.collectAsStateWithLifecycle()
    val canEdit = serviceState is ProxyService.State.Stopped ||
        serviceState is ProxyService.State.Error
    var enabled by remember { mutableStateOf(prefs.getBoolean(ProxyService.PREF_TUNNEL_ENABLED, false)) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 18.dp)
            .padding(top = 4.dp, bottom = 12.dp),
    ) {
        TopBar(title = "Reverse tunnel", onBack = onBack)
        Spacer(Modifier.height(8.dp))
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(14.dp))
                    .background(SurfaceMid)
                    .border(1.dp, OutlineSoft, RoundedCornerShape(14.dp))
                    .padding(horizontal = 14.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Dial out to a relay", color = TextPrimary, style = MaterialTheme.typography.titleMedium)
                    Text(
                        text = "Status: $status",
                        color = TextSecondary,
                        style = MaterialTheme.typography.labelMedium,
                    )
                }
                Switch(
                    checked = enabled,
                    enabled = canEdit,
                    onCheckedChange = {
                        enabled = it
                        prefs.edit().putBoolean(ProxyService.PREF_TUNNEL_ENABLED, it).apply()
                    },
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = SurfaceLow,
                        checkedTrackColor = Accent,
                        uncheckedThumbColor = TextSecondary,
                        uncheckedTrackColor = SurfaceLow,
                        uncheckedBorderColor = OutlineStrong,
                    ),
                )
            }
            HintBanner(
                if (canEdit) "The phone keeps idle TLS links open to the relay over any " +
                    "network. Clients connect to the relay and get this proxy, with auth. " +
                    "Targets still go out over mobile data. Changes apply on the next start."
                else "Stop the proxy to change these settings."
            )
            PrefField(prefs, ProxyService.PREF_TUNNEL_HOST, "Relay host", "", canEdit)
            PrefField(prefs, ProxyService.PREF_TUNNEL_PORT, "Relay port",
                ReverseTunnel.DEFAULT_PORT.toString(), canEdit, numeric = true)
            PrefField(prefs, ProxyService.PREF_TUNNEL_TOKEN, "Token", "", canEdit)
            PrefField(prefs, ProxyService.PREF_TUNNEL_PIN, "Cert SHA-256 pin (hex)", "", canEdit)
            PrefField(prefs, ProxyService.PREF_TUNNEL_POOL, "Idle links",
                ReverseTunnel.DEFAULT_POOL.toString(), canEdit, numeric = true)
        }
    }
}

@Composable
private fun PrefField(
    prefs: android.content.SharedPreferences,
    key: String,
    label: String,
    default: String,
    enabled: Boolean,
    numeric: Boolean = false,
) {
    var text by remember { mutableStateOf(prefs.getString(key, null) ?: default) }
    OutlinedTextField(
        value = text,
        onValueChange = { v ->
            text = if (numeric) v.filter { it.isDigit() }.take(5) else v
            prefs.edit().putString(key, text).apply()
        },
        label = { Text(label) },
        singleLine = true,
        enabled = enabled,
        keyboardOptions = if (numeric) KeyboardOptions(keyboardType = KeyboardType.Number)
        else KeyboardOptions.Default,
        textStyle = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 15.sp, color = TextPrimary),
        colors = fieldColors(),
        modifier = Modifier.fillMaxWidth(),
    )
}
