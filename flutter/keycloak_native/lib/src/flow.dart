import 'answers.dart';
import 'challenges.dart';
import 'credentials.dart';
import 'errors.dart';
import 'mapping.dart';
import 'messages.g.dart';

/// Parameters of the initial request (spec/03 §2.1).
final class LoginParameters {
  const LoginParameters({
    this.scope = 'openid',
    this.acrValues,
    this.loginHint,
    this.prompt,
    this.maxAge,
    this.nonce,
    this.uiLocales,
    this.deviceName,
    this.deviceId,
    this.additionalParameters = const {},
    this.continuationParameters = const {},
  });

  final String? scope;
  final String? acrValues;
  final String? loginHint;
  final String? prompt;
  final int? maxAge;
  final String? nonce;
  final String? uiLocales;

  /// Free-text device label shown in events and push prompts.
  final String? deviceName;

  /// Stable app-generated UUID; the SDK does not generate one.
  final String? deviceId;

  /// Extra fields of the initial request (spec/03 §2.3); use the reserved `x_` prefix.
  final Map<String, String> additionalParameters;

  /// Extra fields appended to every continuation request of the flow.
  final Map<String, String> continuationParameters;
}

/// What the flow hands back after `start()` / `respond(...)` (spec/05 §2.1).
sealed class FlowStep {
  const FlowStep();
}

/// More input is needed: the challenge set in flow order plus context. Show one challenge, offer
/// the others as alternatives ("Try another way").
final class ChallengesStep extends FlowStep {
  const ChallengesStep(this.challenges, this.context);

  final List<Challenge> challenges;
  final FlowContext context;

  /// The challenges the native SDKs can answer, in server order.
  List<Challenge> get supportedChallenges => challenges.where((c) => c.type.isSupported).toList();
}

/// The code was issued and exchanged. Store the credentials with `CredentialsManager.store`.
final class AuthorizedStep extends FlowStep {
  const AuthorizedStep(this.credentials);

  final Credentials credentials;
}

/// The server cannot finish natively (spec/03 §3.4): complete it with `KeycloakNative.webFallback`.
final class RedirectToWebStep extends FlowStep {
  const RedirectToWebStep(this.request);

  final RedirectToWebRequest request;
}

/// One login or step-up, driven by the native SDK's state machine: `start()`, then `respond` to
/// one challenge of each `ChallengesStep` until `AuthorizedStep` or `RedirectToWebStep`. Serialize
/// calls: a second `respond` while one is in flight answers a set that is about to be replaced.
/// Call [dispose] when the flow is no longer needed.
final class NativeLoginFlow {
  NativeLoginFlow.internal(this._api, this.handle, {required this.isStepUp});

  final KeycloakNativeHostApi _api;

  /// The native flow's handle.
  final String handle;
  final bool isStepUp;

  List<Challenge> _pending = const [];
  bool _disposed = false;

  /// The challenges of the last `ChallengesStep`.
  List<Challenge> get pendingChallenges => _pending;

  Future<FlowStep> start() => _step(() => _api.start(handle));

  /// Answers [challenge], which must be in [pendingChallenges]. [additionalFields] are sent with
  /// this request only (spec/03 §2.3).
  Future<FlowStep> respond(ChallengeAnswer answer, Challenge challenge, {Map<String, String> additionalFields = const {}}) {
    if (answer.challengeType != challenge.type) {
      throw NativeAuthException(
        NativeAuthErrorCode.unsupportedChallenge,
        description: 'A ${answer.challengeType} answer cannot be sent for a ${challenge.type} challenge',
      );
    }
    return _step(() => _api.respond(handle, challenge.id, challenge.type.wire, answerToMessage(answer), additionalFields));
  }

  /// `action=cancel`: the server invalidates the session. Safe to call at any point.
  Future<void> cancel() async {
    _pending = const [];
    if (_disposed) return;
    await bridged(() => _api.cancel(handle));
  }

  /// Releases the native flow and any credentials it produced that were not stored.
  Future<void> dispose() async {
    if (_disposed) return;
    _disposed = true;
    await bridged(() => _api.disposeFlow(handle));
  }

  Future<FlowStep> _step(Future<FlowStepMessage> Function() call) async {
    if (_disposed) throw const NativeAuthException(NativeAuthErrorCode.flowState, description: 'The flow is disposed');
    final step = flowStepFromMessage(await bridged(call));
    _pending = step is ChallengesStep ? step.challenges : const [];
    return step;
  }
}
