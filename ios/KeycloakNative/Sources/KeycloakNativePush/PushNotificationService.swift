import Foundation
import KeycloakNativeCore
#if canImport(UserNotifications)
import UserNotifications
#endif

/// Helper for a `UNNotificationServiceExtension` (spec/05 §5 "Notification type"): the APNs payload
/// carries `mutable-content: 1` and the `confirmToken`; the extension fetches the pending approval
/// and rewrites the notification before it is shown ("Approve sign-in to Web App?"). The extension
/// shares the Keychain access group with the app so the same `KeycloakNative` instance (DPoP key,
/// enrolment, credentials) is available: configure `keychainAccessGroup` in both.
public enum PushNotificationService {
  /// The body to show for a pending approval; apps localise by passing their own `format`.
  public static func body(for approval: PendingApproval, format: String = "Approve sign-in to %@?") -> String {
    String(format: format, approval.clientDisplayName)
  }

  #if canImport(UserNotifications)
  /// Returns the content to deliver: the original with a context-aware body when the pending
  /// approval could be fetched, the original otherwise (never fails: the user must still see the
  /// prompt). Call from `didReceive(_:withContentHandler:)` and hand the result to the handler
  /// before the extension's time runs out.
  public static func rewrite(_ content: UNNotificationContent, push: Push, bodyFormat: String = "Approve sign-in to %@?") async -> UNNotificationContent {
    guard let mutable = content.mutableCopy() as? UNMutableNotificationContent, let payload = push.handleNotification(content.userInfo) else {
      return content
    }
    if let approval = try? await push.pendingApproval(for: payload) {
      mutable.body = body(for: approval, format: bodyFormat)
      if let username = approval.username, mutable.subtitle.isEmpty { mutable.subtitle = username }
    }
    return mutable
  }
  #endif
}
