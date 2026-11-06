package io.phasetwo.keycloak.nativeauth.sdk.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import io.phasetwo.keycloak.nativeauth.sdk.errors.NativeAuthError
import io.phasetwo.keycloak.nativeauth.sdk.push.PendingApproval
import io.phasetwo.keycloak.nativeauth.sdk.push.Push
import io.phasetwo.keycloak.nativeauth.sdk.push.PushApprovalAction
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * The pending sign-in approvals of this device's user (spec/05 §5 "Number match UX"): one card per
 * [PendingApproval] with Approve / Deny, or the three number-match buttons when the challenge has
 * them, and a refresh button. A notification tap brings the user here; the list is also worth showing
 * when the app opens, because a backgrounded app does not see FCM data until the user taps. Apps
 * embed it as is or build their own on [Push]. Twin of the iOS `PushApprovalsView`.
 *
 * @param push `kc.push()`.
 * @param focus the `cid` of the approval a notification pointed at (shown first).
 * @param onResponded called with the server's status after each approve / deny.
 */
@Composable
public fun PushApprovalsScreen(
  push: Push,
  modifier: Modifier = Modifier,
  focus: String? = null,
  onResponded: ((PendingApproval, String) -> Unit)? = null,
) {
  val scope = rememberCoroutineScope()
  val currentOnResponded by rememberUpdatedState(onResponded)
  val model = remember(push, focus) { PushApprovalsModel(push, focus, scope) { approval, status -> currentOnResponded?.invoke(approval, status) } }
  LaunchedEffect(model) { model.refresh() }
  val state by model.state.collectAsState()

  LazyColumn(modifier.fillMaxSize().padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
    item {
      Row(Modifier.fillMaxWidth().padding(top = 16.dp), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(stringResource(R.string.nl_push_requests), style = MaterialTheme.typography.titleLarge)
        TextButton(onClick = { scope.launch { model.refresh() } }, enabled = !state.isLoading, modifier = Modifier.testTag("pushRefresh")) {
          Text(stringResource(R.string.nl_refresh))
        }
      }
    }
    if (state.approvals.isEmpty()) {
      item {
        Text(
          stringResource(if (state.isLoading) R.string.nl_contacting_server else R.string.nl_push_no_requests),
          color = MaterialTheme.colorScheme.onSurfaceVariant,
          modifier = Modifier.testTag("pushNoApprovals"),
        )
      }
    }
    items(state.approvals, key = { it.cid }) { approval ->
      PushApprovalCard(approval, state.isBusy) { model.respond(approval, it) }
    }
    state.message?.let { message ->
      item { Text(message, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("pushApprovalsMessage")) }
    }
  }
}

@Composable
private fun PushApprovalCard(approval: PendingApproval, isBusy: Boolean, respond: (PushApprovalAction) -> Unit) {
  Card(Modifier.fillMaxWidth()) {
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
      Text(stringResource(R.string.nl_push_sign_in_to, approval.clientDisplayName), style = MaterialTheme.typography.titleMedium)
      approval.username?.let { Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant) }
      if (approval.numbers.isNotEmpty()) {
        Text(stringResource(R.string.nl_push_pick_number), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
          approval.numbers.forEach { number ->
            Button(onClick = { respond(PushApprovalAction.Approve(number)) }, enabled = !isBusy, modifier = Modifier.testTag("pushNumber-$number")) {
              Text(number, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            }
          }
        }
      } else {
        Button(onClick = { respond(PushApprovalAction.Approve()) }, enabled = !isBusy, modifier = Modifier.fillMaxWidth().testTag("pushApprove")) {
          Text(stringResource(R.string.nl_approve))
        }
      }
      OutlinedButton(
        onClick = { respond(PushApprovalAction.Deny) },
        enabled = !isBusy,
        colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
        modifier = Modifier.fillMaxWidth().testTag("pushDeny"),
      ) {
        Text(stringResource(R.string.nl_deny))
      }
      approval.expiresAt?.let { expires ->
        val time = DateTimeFormatter.ofLocalizedTime(FormatStyle.SHORT).withZone(ZoneId.systemDefault()).format(expires)
        Text(stringResource(R.string.nl_push_expires, time), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
      }
    }
  }
}

/** State behind [PushApprovalsScreen]; plain Kotlin over [StateFlow], tested on the JVM. */
internal class PushApprovalsModel(
  private val push: Push,
  private val focus: String?,
  private val scope: CoroutineScope,
  private val onResponded: (PendingApproval, String) -> Unit,
) {
  data class State(
    val approvals: List<PendingApproval> = emptyList(),
    val isLoading: Boolean = false,
    val isBusy: Boolean = false,
    val message: String? = null,
  )

  private val mutableState = MutableStateFlow(State())
  val state: StateFlow<State> = mutableState.asStateFlow()

  suspend fun refresh() {
    mutableState.update { it.copy(isLoading = true) }
    try {
      val list = push.pendingApprovals().filterNot { it.isExpired() }
      val ordered = list.sortedBy { if (it.cid == focus) 0 else 1 }
      mutableState.update { it.copy(approvals = ordered, message = null) }
    } catch (e: CancellationException) {
      throw e
    } catch (e: Exception) {
      mutableState.update { it.copy(message = describe(e)) }
    } finally {
      mutableState.update { it.copy(isLoading = false) }
    }
  }

  fun respond(approval: PendingApproval, action: PushApprovalAction) {
    scope.launch {
      mutableState.update { it.copy(isBusy = true) }
      try {
        val status = push.respond(approval, action)
        mutableState.update { s -> s.copy(approvals = s.approvals.filterNot { it.cid == approval.cid }, message = null) }
        onResponded(approval, status)
      } catch (e: CancellationException) {
        throw e
      } catch (e: Exception) {
        mutableState.update { it.copy(message = describe(e)) }
        // A wrong number keeps the card (one more try, spec/05 §5); anything else refreshes.
        if ((e as? NativeAuthError)?.code != NativeAuthError.Code.USER_VERIFICATION_MISMATCH) refresh()
      } finally {
        mutableState.update { it.copy(isBusy = false) }
      }
    }
  }

  private fun describe(e: Exception): String = (e as? NativeAuthError)?.let { it.errorDescription ?: it.code } ?: e.toString()
}
