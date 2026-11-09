import 'package:flutter/foundation.dart';

import '../answers.dart';
import '../challenges.dart';
import '../client.dart';
import '../credentials.dart';
import '../errors.dart';
import '../flow.dart';

/// Outcome of a `NativeLoginView` (spec/05 §4).
sealed class NativeLoginResult {
  const NativeLoginResult();
}

/// The flow ended with tokens; store them with `CredentialsManager.store`.
final class NativeLoginAuthorized extends NativeLoginResult {
  const NativeLoginAuthorized(this.credentials);
  final Credentials credentials;
}

final class NativeLoginCancelled extends NativeLoginResult {
  const NativeLoginCancelled();
}

/// A terminal error (`invalid_session`, `access_denied`, …): start a new flow to try again.
final class NativeLoginFailed extends NativeLoginResult {
  const NativeLoginFailed(this.error);
  final NativeAuthException error;
}

/// What the view shows.
sealed class NativeLoginPhase {
  const NativeLoginPhase();
}

final class NativeLoginStarting extends NativeLoginPhase {
  const NativeLoginStarting();
}

final class NativeLoginChallenges extends NativeLoginPhase {
  const NativeLoginChallenges(this.challenges, this.context, this.selected);

  final List<Challenge> challenges;
  final FlowContext context;

  /// The challenge on screen; the others are the alternatives.
  final Challenge selected;

  List<Challenge> get alternatives => challenges.where((c) => c.id != selected.id).toList();
}

final class NativeLoginRedirectToWeb extends NativeLoginPhase {
  const NativeLoginRedirectToWeb(this.request);
  final RedirectToWebRequest request;
}

final class NativeLoginFinished extends NativeLoginPhase {
  const NativeLoginFinished();
}

/// The challenge types this version of the plugin can answer from Dart. Passkeys, passkey
/// registration and push enrollment need their native ceremonies bridged first (spec/18 §9).
final Set<ChallengeType> answerableChallengeTypes = Set.unmodifiable({
  ChallengeType.username,
  ChallengeType.password,
  ChallengeType.totp,
  ChallengeType.otp,
  ChallengeType.recoveryCode,
  ChallengeType.updatePassword,
  ChallengeType.verifyEmail,
  ChallengeType.terms,
  ChallengeType.push,
});

/// State behind `NativeLoginView`, the twin of the native UI layers' `NativeLoginModel`: drives the
/// flow, picks the screen, runs the browser fallback. A [ChangeNotifier], so it is tested without
/// widgets and can drive an app's own screens.
class NativeLoginController extends ChangeNotifier {
  NativeLoginController({required this.kc, required this.flow, required this.onResult});

  final KeycloakNative kc;

  /// An unstarted flow; [start] starts it.
  final NativeLoginFlow flow;
  final void Function(NativeLoginResult result) onResult;

  NativeLoginPhase _phase = const NativeLoginStarting();
  NativeLoginPhase get phase => _phase;

  int _inFlight = 0;
  bool get isSubmitting => _inFlight > 0;

  /// A user-facing error not attached to a challenge (network, browser failure…).
  String? _message;
  String? get message => _message;

  bool _started = false;
  bool _done = false;
  bool _disposed = false;

  void start() {
    if (_started) return;
    _started = true;
    _perform(flow.start);
  }

  void submit(ChallengeAnswer answer, Challenge challenge) => _perform(() => flow.respond(answer, challenge));

  void select(Challenge challenge) {
    final phase = _phase;
    if (phase is! NativeLoginChallenges || !phase.challenges.any((c) => c.id == challenge.id)) return;
    _phase = NativeLoginChallenges(phase.challenges, phase.context, challenge);
    _message = null;
    _notify();
  }

  void openBrowser() {
    if (_phase is! NativeLoginRedirectToWeb) return;
    _perform(() async => AuthorizedStep(await kc.webFallback.complete(flow)));
  }

  Future<void> cancel() async {
    if (_done) return;
    _done = true;
    try {
      await flow.cancel();
    } on NativeAuthException {
      // The server session ends either way.
    }
    _phase = const NativeLoginFinished();
    _notify();
    onResult(const NativeLoginCancelled());
  }

  Future<void> _perform(Future<FlowStep> Function() body) async {
    if (_done) return;
    _inFlight += 1;
    _message = null;
    _notify();
    try {
      _apply(await body());
    } on NativeAuthException catch (e) {
      switch (e.code) {
        // Not a flow failure: the set stays, the user may pick another way.
        case NativeAuthErrorCode.webFallbackCancelled || NativeAuthErrorCode.passkeyCancelled || NativeAuthErrorCode.savedPasswordCancelled:
          break;
        case NativeAuthErrorCode.networkError ||
            NativeAuthErrorCode.webFallbackFailed ||
            NativeAuthErrorCode.passkeyFailed ||
            NativeAuthErrorCode.passkeyUnavailable ||
            NativeAuthErrorCode.unsupportedChallenge:
          _message = e.description ?? e.code;
        default:
          // Terminal (invalid_session, access_denied, …): the flow is over.
          _done = true;
          _phase = const NativeLoginFinished();
          onResult(NativeLoginFailed(e));
      }
    } finally {
      _inFlight -= 1;
      _notify();
    }
  }

  void _apply(FlowStep step) {
    switch (step) {
      case ChallengesStep(:final challenges, :final context):
        final previous = _phase is NativeLoginChallenges ? (_phase as NativeLoginChallenges).selected : null;
        _phase = NativeLoginChallenges(challenges, context, _pick(challenges, previous));
      case AuthorizedStep(:final credentials):
        _done = true;
        _phase = const NativeLoginFinished();
        onResult(NativeLoginAuthorized(credentials));
      case RedirectToWebStep(:final request):
        _phase = NativeLoginRedirectToWeb(request);
    }
  }

  /// The entry to show: the one that just failed (it carries `error`), else the previously shown
  /// type when it is still offered, else the first answerable entry (server order = flow order).
  static Challenge _pick(List<Challenge> challenges, Challenge? previous) {
    bool answerable(Challenge c) => answerableChallengeTypes.contains(c.type);
    for (final c in challenges) {
      if (c.error != null && answerable(c)) return c;
    }
    if (previous != null) {
      for (final c in challenges) {
        if (c.type == previous.type && answerable(c)) return c;
      }
    }
    return challenges.firstWhere(answerable, orElse: () => challenges.first);
  }

  void _notify() {
    if (!_disposed) notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    super.dispose();
  }
}
