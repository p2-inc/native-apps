package io.phasetwo.keycloak.nativedemo

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.phasetwo.keycloak.nativeauth.sdk.json.objectValue
import io.phasetwo.keycloak.nativeauth.sdk.transport.FlowLogEntry
import io.phasetwo.keycloak.nativeauth.sdk.ui.NativeLoginScreen
import io.phasetwo.keycloak.nativeauth.sdk.ui.PushApprovalsScreen

/** Four tabs, as on iOS: Login, Home (the session), Push and Diagnostics. */
@Composable
fun DemoApp(model: DemoModel) {
  MaterialTheme {
    val state by model.state.collectAsState()
    Scaffold(
      bottomBar = {
        NavigationBar {
          DemoTab.entries.forEach { tab ->
            NavigationBarItem(
              selected = state.tab == tab,
              onClick = { model.select(tab) },
              icon = {},
              label = { Text(tab.name.lowercase().replaceFirstChar { it.uppercase() }) },
              modifier = Modifier.testTag("tab-${tab.name.lowercase()}"),
            )
          }
        }
      },
    ) { padding ->
      Column(Modifier.padding(padding).fillMaxSize()) {
        Text(state.status, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp).testTag("status"))
        HorizontalDivider()
        when (state.tab) {
          DemoTab.LOGIN -> LoginTab(model, state)
          DemoTab.HOME -> HomeTab(model, state)
          DemoTab.PUSH -> PushTab(model, state)
          DemoTab.DIAGNOSTICS -> DiagnosticsTab(model, state)
        }
      }
    }
  }
}

@Composable
private fun LoginTab(model: DemoModel, state: DemoModel.State) {
  val flow = state.flow
  if (flow != null) {
    // The default screens of the ui module; a push_enrollment registers the FCM token when configured.
    key(flow) {
      NativeLoginScreen(
        kc = model.sdk(state.flowClient),
        flow = flow,
        onResult = model::finish,
        header = { Text(model.clientId(state.flowClient), style = MaterialTheme.typography.labelMedium) },
        pushRegistration = model.pushRegistration,
      )
    }
    return
  }
  Column(Modifier.verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
    Text("Client", style = MaterialTheme.typography.titleMedium)
    DemoClient.entries.forEach { client ->
      Row(
        Modifier.fillMaxWidth().selectable(selected = state.client == client, onClick = { model.select(client) }).testTag("client-${client.name.lowercase()}"),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
      ) {
        RadioButton(selected = state.client == client, onClick = null)
        Column {
          Text("${client.title} · ${model.clientId(client)}")
          Text(client.description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
      }
    }
    Button(onClick = model::startLogin, modifier = Modifier.fillMaxWidth().testTag("startLogin")) { Text("Start login") }
    Text("Issuer: ${model.config.issuer}", style = MaterialTheme.typography.bodySmall)
  }
}

@Composable
private fun HomeTab(model: DemoModel, state: DemoModel.State) {
  val credentials = state.credentials
  Column(Modifier.verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
    if (credentials == null) {
      Text("Not signed in. Start a login on the Login tab.")
      return@Column
    }
    Text("Signed in with ${state.signedInClient?.let(model::clientId)}", style = MaterialTheme.typography.titleMedium)
    Text("token_type ${credentials.tokenType} · expires ${credentials.expiresAt}", style = MaterialTheme.typography.bodySmall)
    Card(Modifier.fillMaxWidth()) {
      SelectionContainer {
        val claims = credentials.accessTokenClaims.objectValue.orEmpty()
        Text(
          claims.entries.joinToString("\n") { (name, value) -> "$name: $value" },
          fontFamily = FontFamily.Monospace,
          style = MaterialTheme.typography.bodySmall,
          modifier = Modifier.padding(12.dp).testTag("claims"),
        )
      }
    }
    Button(onClick = model::transfer, enabled = !state.isBusy, modifier = Modifier.fillMaxWidth().testTag("transfer")) { Text("Transfer (step-up to acr 2)") }
    state.resourceResult?.let { Text(it, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace) }
    OutlinedButton(onClick = model::refreshTokens, enabled = !state.isBusy, modifier = Modifier.fillMaxWidth().testTag("refresh")) { Text("Refresh tokens") }
    OutlinedButton(onClick = model::registerPasskey, enabled = !state.isBusy, modifier = Modifier.fillMaxWidth()) { Text("Register a passkey") }
    OutlinedButton(onClick = model::endSessionOnServer, enabled = !state.isBusy, modifier = Modifier.fillMaxWidth()) { Text("End session on the server (S8)") }
    Button(onClick = model::logout, enabled = !state.isBusy, modifier = Modifier.fillMaxWidth().testTag("logout")) { Text("Log out") }
  }
}

@Composable
private fun PushTab(model: DemoModel, state: DemoModel.State) {
  val enrollment = state.enrollment
  Column(Modifier.fillMaxSize()) {
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
      if (enrollment == null) {
        Text(
          if (model.config.firebaseConfigured) "This device is not enrolled. Enrolling registers its FCM token, so sign-in requests arrive as notifications."
          else "This device is not enrolled. This build has no google-services.json, so it enrolls without delivery and reads its requests itself.",
        )
        Button(onClick = model::enrollPush, enabled = !state.isBusy && state.credentials != null, modifier = Modifier.fillMaxWidth().testTag("enrollPush")) {
          Text(if (state.credentials == null) "Sign in to enroll" else "Enroll this device")
        }
      } else {
        Text("Enrolled as ${enrollment.username ?: enrollment.userId} (${enrollment.deviceLabel}, ${enrollment.pushProviderType})", style = MaterialTheme.typography.bodyMedium)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
          TextButton(onClick = model::rotatePushKey, enabled = !state.isBusy) { Text("Rotate key") }
          TextButton(onClick = model::lockout, enabled = !state.isBusy, modifier = Modifier.testTag("lockout")) { Text("Lock me out") }
          TextButton(onClick = model::forgetPush, enabled = !state.isBusy) { Text("Forget") }
        }
      }
    }
    HorizontalDivider()
    if (enrollment != null && state.credentials != null) {
      // Re-keyed on resume and on each message so the list reads the server again.
      key(state.approvalsTick, state.approvalsFocus) {
        PushApprovalsScreen(push = model.push, focus = state.approvalsFocus, onResponded = { approval, status -> model.noteApproval(approval.cid, status) })
      }
    } else if (enrollment != null) {
      Text("Sign in to read the sign-in requests (the device API uses the login's DPoP-bound token).", modifier = Modifier.padding(16.dp))
    }
  }
}

@Composable
private fun DiagnosticsTab(model: DemoModel, state: DemoModel.State) {
  val log by model.flowLog.collectAsState()
  LaunchedEffect(Unit) { model.loadDiagnostics() }
  LazyColumn(Modifier.fillMaxSize().padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
    item {
      Column(Modifier.padding(top = 12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        state.metadataSummary?.let { Text(it, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace) }
        Text("DPoP jkt: ${state.dpopThumbprint ?: "-"}", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, modifier = Modifier.testTag("jkt"))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
          TextButton(onClick = model::loadDiagnostics) { Text("Reload") }
          TextButton(onClick = model::clearLog) { Text("Clear log") }
        }
        Text("Flow log (redacted), newest first", style = MaterialTheme.typography.titleSmall)
      }
    }
    items(log.asReversed(), key = { it.id }) { entry -> LogEntry(entry) }
  }
}

@Composable
private fun LogEntry(entry: FlowLogEntry) {
  var expanded by rememberSaveable(entry.id.toString()) { mutableStateOf(false) }
  val summary = remember(entry) { "${entry.statusCode ?: entry.errorCode ?: "…"}  ${entry.method} ${entry.url.path}  (${entry.durationMilliseconds} ms)" }
  Card(Modifier.fillMaxWidth().clickable { expanded = !expanded }) {
    Column(Modifier.padding(8.dp)) {
      Text(summary, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
      if (expanded) {
        SelectionContainer {
          Text(
            listOfNotNull(entry.requestBody?.let { "→ $it" }, entry.responseBody?.let { "← $it" }).joinToString("\n\n"),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
          )
        }
      }
    }
  }
}
