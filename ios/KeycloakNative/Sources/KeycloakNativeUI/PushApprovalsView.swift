import KeycloakNativeCore
import KeycloakNativePush
import SwiftUI

/// The pending sign-in approvals of this device's user (spec/05 §5 "Number match UX"): one row per
/// `PendingApproval` with Approve / Deny, the three number-match buttons when the challenge has
/// them, pull-to-refresh and a refresh button (the simulator never receives APNs; on a device a
/// notification brings the user here). Apps embed it as is or build their own on `Push`.
public struct PushApprovalsView: View {
  @State private var model: PushApprovalsModel
  @Environment(\.nativeLoginStrings) private var l

  /// - Parameters:
  ///   - push: `kc.push()`.
  ///   - focus: the `cid` of the approval a notification pointed at (shown first).
  ///   - onResponded: called with the server's status after each approve / deny.
  public init(push: Push, focus: String? = nil, onResponded: (@MainActor (PendingApproval, String) -> Void)? = nil) {
    _model = State(initialValue: PushApprovalsModel(push: push, focus: focus, onResponded: onResponded))
  }

  public var body: some View {
    List {
      if model.approvals.isEmpty {
        Text(model.isLoading ? l("Contacting the server…") : l("No sign-in requests are waiting."))
          .foregroundStyle(.secondary)
          .accessibilityIdentifier("pushNoApprovals")
      }
      ForEach(model.approvals) { approval in
        Section {
          PushApprovalRow(approval: approval, isBusy: model.isBusy, respond: { model.respond(approval, $0) })
        } header: {
          Text(l("Sign-in to %@", approval.clientDisplayName))
        } footer: {
          if let expires = approval.expiresAt {
            Text(l("Expires %@", expires.formatted(date: .omitted, time: .shortened)))
          }
        }
      }
      if let message = model.message {
        Text(message).font(.footnote).foregroundStyle(.red).accessibilityIdentifier("pushApprovalsMessage")
      }
    }
    .navigationTitle(l("Sign-in requests"))
    .refreshable { await model.refresh() }
    .toolbar {
      Button(l("Refresh")) { Task { await model.refresh() } }
        .accessibilityIdentifier("pushRefresh")
    }
    .task { await model.refresh() }
  }
}

struct PushApprovalRow: View {
  let approval: PendingApproval
  let isBusy: Bool
  let respond: (PushApprovalAction) -> Void
  @Environment(\.nativeLoginStrings) private var l

  var body: some View {
    if let username = approval.username {
      Text(username).font(.subheadline).foregroundStyle(.secondary)
    }
    if !approval.numbers.isEmpty {
      Text(l("Pick the number shown on the other screen")).font(.footnote).foregroundStyle(.secondary)
      HStack(spacing: 12) {
        ForEach(approval.numbers, id: \.self) { number in
          Button(number) { respond(.approve(userVerification: number)) }
            .buttonStyle(.borderedProminent)
            .font(.title3.bold())
            .disabled(isBusy)
            .accessibilityIdentifier("pushNumber-\(number)")
        }
      }
    } else {
      Button(l("Approve")) { respond(.approve()) }
        .buttonStyle(.borderedProminent)
        .disabled(isBusy)
        .accessibilityIdentifier("pushApprove")
    }
    Button(l("Deny"), role: .destructive) { respond(.deny) }
      .disabled(isBusy)
      .accessibilityIdentifier("pushDeny")
  }
}

@MainActor
@Observable
final class PushApprovalsModel {
  private(set) var approvals: [PendingApproval] = []
  private(set) var isLoading = false
  private(set) var isBusy = false
  private(set) var message: String?

  private let push: Push
  private let focus: String?
  private let onResponded: (@MainActor (PendingApproval, String) -> Void)?

  init(push: Push, focus: String?, onResponded: (@MainActor (PendingApproval, String) -> Void)?) {
    self.push = push
    self.focus = focus
    self.onResponded = onResponded
  }

  func refresh() async {
    isLoading = true
    defer { isLoading = false }
    do {
      var list = try await push.pendingApprovals().filter { !$0.isExpired }
      if let focus, let index = list.firstIndex(where: { $0.cid == focus }) {
        list.insert(list.remove(at: index), at: 0)
      }
      approvals = list
      message = nil
    } catch let error as NativeAuthError {
      message = error.errorDescription ?? error.code
    } catch {
      message = String(describing: error)
    }
  }

  func respond(_ approval: PendingApproval, _ action: PushApprovalAction) {
    Task {
      isBusy = true
      defer { isBusy = false }
      do {
        let status = try await push.respond(to: approval, action)
        approvals.removeAll { $0.cid == approval.cid }
        message = nil
        onResponded?(approval, status)
      } catch let error as NativeAuthError {
        // A wrong number keeps the row (one more try, spec/05 §5); anything else refreshes.
        message = error.errorDescription ?? error.code
        if error.code != NativeAuthError.Code.userVerificationMismatch { await refresh() }
      } catch {
        message = String(describing: error)
      }
    }
  }
}
