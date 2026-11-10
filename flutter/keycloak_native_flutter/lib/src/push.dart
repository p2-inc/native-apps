import 'dart:convert';

import 'errors.dart';
import 'messages.g.dart';

/// Where the push device API sends sign-in requests (spec/03 §7): `fcm` with the FCM registration
/// token, `apns` with the hex APNs device token, or `none` (the device reads `/login/pending`
/// itself). The plugin registers with neither service: the app obtains the token (for instance with
/// `firebase_messaging`) and hands it in.
final class PushProviderRegistration {
  const PushProviderRegistration(this.type, this.id);

  /// No delivery: approvals are read when the app asks.
  static const none = PushProviderRegistration('none', null);

  final String type;
  final String? id;

  @override
  String toString() => 'PushProviderRegistration($type)';
}

/// This device's push enrollment (the native `PushEnrollment`).
final class PushEnrollment {
  const PushEnrollment({
    required this.credentialId,
    required this.deviceId,
    required this.userId,
    required this.deviceLabel,
    required this.pushProviderType,
    required this.deviceApiBase,
    required this.keyThumbprint,
    required this.enrolledAt,
    this.username,
    this.pushProviderId,
  });

  final String credentialId;
  final String deviceId;
  final String userId;
  final String? username;
  final String deviceLabel;
  final String pushProviderType;
  final String? pushProviderId;
  final Uri deviceApiBase;

  /// The `jkt` of the device key (the DPoP key).
  final String keyThumbprint;
  final DateTime enrolledAt;
}

/// A sign-in waiting for this device's answer (`/login/pending`).
final class PendingApproval {
  PendingApproval(this.cid, this.raw);

  final String cid;
  final Map<String, Object?> raw;

  String? get userId => raw['userId'] as String?;
  String? get username => raw['username'] as String?;
  String? get clientId => raw['clientId'] as String?;
  String? get clientName => raw['clientName'] as String?;
  DateTime? get createdAt => _seconds(raw['createdAt']);
  DateTime? get expiresAt => _seconds(raw['expiresAt']);

  /// Number match: the three numbers to offer; the other screen shows one of them.
  List<String> get numbers {
    final verification = raw['userVerification'];
    if (verification is! Map) return const [];
    final numbers = verification['numbers'];
    return numbers is List ? [for (final n in numbers) '$n'] : const [];
  }

  /// `pin` user verification: the user types the PIN the other side shows.
  bool get requiresPin => raw['userVerification'] is Map && (raw['userVerification'] as Map)['type'] == 'pin';

  bool isExpired([DateTime? now]) => expiresAt != null && !expiresAt!.isAfter(now ?? DateTime.now());
  String get clientDisplayName => clientName ?? clientId ?? '?';

  static DateTime? _seconds(Object? value) =>
      value is num ? DateTime.fromMillisecondsSinceEpoch((value * 1000).round(), isUtc: true) : null;
}

/// The answer to a [PendingApproval].
sealed class PushApprovalAction {
  const PushApprovalAction();

  /// [userVerification]: the number picked for number match, or the PIN.
  const factory PushApprovalAction.approve([String? userVerification]) = PushApprove;
  const factory PushApprovalAction.deny() = PushDeny;
}

final class PushApprove extends PushApprovalAction {
  const PushApprove([this.userVerification]);
  final String? userVerification;
}

final class PushDeny extends PushApprovalAction {
  const PushDeny();
}

/// What a push message names: the approval to show.
final class PushNotification {
  const PushNotification({required this.cid, this.credentialId, this.expiresAt});

  final String cid;
  final String? credentialId;
  final DateTime? expiresAt;
}

/// Push MFA for this device (spec/03 §7, the native SDKs' `Push`): enrollment, approvals with
/// number match, provider updates, key rotation and the lockout button. The device key is the SDK's
/// DPoP key and the requests use the stored login, so sign in before enrolling.
final class Push {
  Push.internal(this._api, this._instance);

  final KeycloakNativeHostApi _api;
  final String _instance;

  Future<PushEnrollment?> enrollment() async {
    final m = await bridged(() => _api.pushEnrollment(_instance));
    return m == null ? null : enrollmentFromMessage(m);
  }

  Future<bool> isEnrolled() async => await enrollment() != null;

  /// Enrolls this device from inside the app (spec/03 §7.2).
  Future<PushEnrollment> enroll(String deviceLabel, {PushProviderRegistration registration = PushProviderRegistration.none}) async =>
      enrollmentFromMessage(await bridged(() => _api.pushEnroll(_instance, deviceLabel, registration.type, registration.id)));

  /// Forgets the local enrollment (the server credential stays until the user removes it).
  Future<void> forgetEnrollment() => bridged(() => _api.pushForgetEnrollment(_instance));

  Future<List<PendingApproval>> pendingApprovals() async => [
    for (final m in await bridged(() => _api.pushPendingApprovals(_instance)))
      PendingApproval(m.cid, (jsonDecode(m.rawJson) as Map).cast<String, Object?>()),
  ];

  /// Approves or denies; returns the server's status. A wrong number is `user_verification_mismatch`.
  Future<String> respond(PendingApproval approval, PushApprovalAction action) => respondTo(approval.cid, action);

  Future<String> respondTo(String cid, PushApprovalAction action) => bridged(
    () => switch (action) {
      PushApprove(:final userVerification) => _api.pushRespond(_instance, cid, true, userVerification),
      PushDeny() => _api.pushRespond(_instance, cid, false, null),
    },
  );

  /// Reads a push message's data (FCM `data`, APNs `userInfo` as strings); `null` when it is not a
  /// sign-in request. Show [pendingApprovals] focused on the returned `cid`.
  Future<PushNotification?> handleMessage(Map<String, String> data) async {
    final m = await bridged(() => _api.pushHandleMessage(_instance, data));
    if (m == null) return null;
    return PushNotification(
      cid: m.cid,
      credentialId: m.credentialId,
      expiresAt: m.expiresAtMillis == null ? null : DateTime.fromMillisecondsSinceEpoch(m.expiresAtMillis!, isUtc: true),
    );
  }

  /// A new FCM / APNs token for the enrolled device.
  Future<void> updatePushProvider(PushProviderRegistration registration) =>
      bridged(() => _api.pushUpdateProvider(_instance, registration.type, registration.id ?? ''));

  /// Rotates the device key; the stored login is cleared, so the user signs in again.
  Future<void> rotateKey() => bridged(() => _api.pushRotateKey(_instance));

  /// The panic button: the server disables the account; an admin re-enables it.
  Future<void> lockout() => bridged(() => _api.pushLockout(_instance));
}

PushEnrollment enrollmentFromMessage(PushEnrollmentMessage m) => PushEnrollment(
  credentialId: m.credentialId,
  deviceId: m.deviceId,
  userId: m.userId,
  username: m.username,
  deviceLabel: m.deviceLabel,
  pushProviderType: m.pushProviderType,
  pushProviderId: m.pushProviderId,
  deviceApiBase: Uri.parse(m.deviceApiBase),
  keyThumbprint: m.keyThumbprint,
  enrolledAt: DateTime.fromMillisecondsSinceEpoch(m.enrolledAtMillis, isUtc: true),
);
