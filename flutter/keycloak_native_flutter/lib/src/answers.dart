import 'challenges.dart';

/// The answer to one challenge (spec/03 §4), the Dart twin of the native SDKs' `ChallengeAnswer`.
/// The native SDK turns it into form fields, so the wire format stays in one place per platform.
///
/// Passkey assertions, passkey registrations and push enrollments have no case here: their
/// ceremonies run natively and produce the answer there (spec/18 §5, a later phase).
sealed class ChallengeAnswer {
  const ChallengeAnswer();

  const factory ChallengeAnswer.username(String username) = UsernameAnswer;
  const factory ChallengeAnswer.password(String password) = PasswordAnswer;
  const factory ChallengeAnswer.totp(String code, {String? credentialId}) = TotpAnswer;

  /// The code the user received (spec/03 §4.6).
  const factory ChallengeAnswer.otp(String code) = OtpAnswer;

  /// `action=resend`: (re)send a code; also the first send when `OtpChallenge.sent` is `false`.
  const factory ChallengeAnswer.otpResend() = OtpResendAnswer;

  /// The new password, sent as `password` + `password_confirm` (spec/03 §4.12).
  const factory ChallengeAnswer.updatePassword(String password, {required String confirm}) = UpdatePasswordAnswer;
  const factory ChallengeAnswer.verifyEmail(String code) = VerifyEmailAnswer;
  const factory ChallengeAnswer.verifyEmailResend() = VerifyEmailResendAnswer;

  /// `accepted=false` ends the login (spec/03 §4.14).
  const factory ChallengeAnswer.terms({required bool accepted}) = TermsAnswer;
  const factory ChallengeAnswer.recoveryCode(String code) = RecoveryCodeAnswer;

  /// `push`: create (and send) the push challenge (spec/03 §4.7).
  const factory ChallengeAnswer.pushResend() = PushResendAnswer;

  /// `push`: ask whether the device answered.
  const factory ChallengeAnswer.pushPoll() = PushPollAnswer;

  /// `push_enrollment`: the device enrolled through the push device API.
  const factory ChallengeAnswer.pushEnrollmentCheck() = PushEnrollmentCheckAnswer;

  /// `action=skip` (spec/03 §4.11): decline a required action whose challenge `isSkippable`.
  const factory ChallengeAnswer.skip(ChallengeType type) = SkipAnswer;

  /// Any other answer, e.g. for an extension challenge type (spec/03 §4.16). [fields] are sent in
  /// order and must not repeat `auth_session`, `challenge_type` or `challenge_id`.
  const factory ChallengeAnswer.custom(ChallengeType type, List<(String, String)> fields) = CustomAnswer;

  /// The challenge type this answer is for.
  ChallengeType get challengeType;
}

final class UsernameAnswer extends ChallengeAnswer {
  const UsernameAnswer(this.username);
  final String username;
  @override
  ChallengeType get challengeType => ChallengeType.username;
}

final class PasswordAnswer extends ChallengeAnswer {
  const PasswordAnswer(this.password);
  final String password;
  @override
  ChallengeType get challengeType => ChallengeType.password;

  @override
  String toString() => 'PasswordAnswer(***)';
}

final class TotpAnswer extends ChallengeAnswer {
  const TotpAnswer(this.code, {this.credentialId});
  final String code;
  final String? credentialId;
  @override
  ChallengeType get challengeType => ChallengeType.totp;
}

final class OtpAnswer extends ChallengeAnswer {
  const OtpAnswer(this.code);
  final String code;
  @override
  ChallengeType get challengeType => ChallengeType.otp;
}

final class OtpResendAnswer extends ChallengeAnswer {
  const OtpResendAnswer();
  @override
  ChallengeType get challengeType => ChallengeType.otp;
}

final class UpdatePasswordAnswer extends ChallengeAnswer {
  const UpdatePasswordAnswer(this.password, {required this.confirm});
  final String password;
  final String confirm;
  @override
  ChallengeType get challengeType => ChallengeType.updatePassword;

  @override
  String toString() => 'UpdatePasswordAnswer(***)';
}

final class VerifyEmailAnswer extends ChallengeAnswer {
  const VerifyEmailAnswer(this.code);
  final String code;
  @override
  ChallengeType get challengeType => ChallengeType.verifyEmail;
}

final class VerifyEmailResendAnswer extends ChallengeAnswer {
  const VerifyEmailResendAnswer();
  @override
  ChallengeType get challengeType => ChallengeType.verifyEmail;
}

final class TermsAnswer extends ChallengeAnswer {
  const TermsAnswer({required this.accepted});
  final bool accepted;
  @override
  ChallengeType get challengeType => ChallengeType.terms;
}

final class RecoveryCodeAnswer extends ChallengeAnswer {
  const RecoveryCodeAnswer(this.code);
  final String code;
  @override
  ChallengeType get challengeType => ChallengeType.recoveryCode;
}

final class PushResendAnswer extends ChallengeAnswer {
  const PushResendAnswer();
  @override
  ChallengeType get challengeType => ChallengeType.push;
}

final class PushPollAnswer extends ChallengeAnswer {
  const PushPollAnswer();
  @override
  ChallengeType get challengeType => ChallengeType.push;
}

final class PushEnrollmentCheckAnswer extends ChallengeAnswer {
  const PushEnrollmentCheckAnswer();
  @override
  ChallengeType get challengeType => ChallengeType.pushEnrollment;
}

final class SkipAnswer extends ChallengeAnswer {
  const SkipAnswer(this.type);
  final ChallengeType type;
  @override
  ChallengeType get challengeType => type;
}

final class CustomAnswer extends ChallengeAnswer {
  const CustomAnswer(this.type, this.fields);
  final ChallengeType type;
  final List<(String, String)> fields;
  @override
  ChallengeType get challengeType => type;
}
