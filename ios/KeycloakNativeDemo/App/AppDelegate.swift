import KeycloakNativeDemoApp
import UIKit
import UserNotifications

/// APNs plumbing of the example app (spec/05 §5, spec/06 S9/S12): registers for remote
/// notifications when the user asks (Home → "Enable notifications"), hands the device token to
/// `DemoModel.apnsTokenReceived` (which syncs it with `PUT /push-mfa/device/push-provider` once
/// enrolled), shows push-MFA notifications in the foreground and refreshes the pending approvals
/// when one is tapped. Without an Apple team the simulator gets no real APNs; `xcrun simctl push`
/// can inject a payload with `confirmToken` to exercise the tap path.
final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
  @MainActor var model: DemoModel?

  func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
    UNUserNotificationCenter.current().delegate = self
    return true
  }

  /// Called from the Home screen: the authorisation alert is deliberately not shown at launch (the
  /// XCUITests would have to dismiss it).
  @MainActor
  static func enableNotifications() async {
    _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge])
    UIApplication.shared.registerForRemoteNotifications()
  }

  func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
    Task { @MainActor in await model?.apnsTokenReceived(deviceToken) }
  }

  func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: any Error) {
    // Simulators without an Apple-silicon host and devices without an entitlement land here.
    NSLog("APNs registration failed: \(error.localizedDescription)")
  }

  nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
    completionHandler([.banner, .sound])
  }

  nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
    // Only the Sendable pieces of the payload cross to the main actor.
    let userInfo = response.notification.request.content.userInfo
    let confirmToken = userInfo["confirmToken"] as? String
    let cid = userInfo["cid"] as? String
    completionHandler()
    Task { @MainActor in self.model?.notificationTapped(confirmToken: confirmToken, cid: cid) }
  }
}
