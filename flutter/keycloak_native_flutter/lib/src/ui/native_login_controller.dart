import 'package:flutter/foundation.dart';

import '../answers.dart';
import '../challenges.dart';
import '../client.dart';
import '../credentials.dart';
import '../errors.dart';
import '../flow.dart';
import '../push.dart';

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

/// The challenge types the controller and the default widgets can answer: every spec/03 type but
/// `select`, which no server emits yet.
final Set<ChallengeType> answerableChallengeTypes = Set.unmodifiable(ChallengeType.known.where((t) => t.isSupported));

/// State behind `NativeLoginView`, the twin of the native UI layers' `NativeLoginModel`: drives the
/// flow, picks the screen, runs the passkey, saved-password, push-enrollment and browser ceremonies,
/// and offers to save a typed password. A [ChangeNotifier], so it is tested without widgets and can
/// drive an app's own screens.
class NativeLoginController extends ChangeNotifier {
  NativeLoginController({
    required this.kc,
    required this.flow,
    required this.onResult,
    this.autoSelectPasskey = false,
    this.offersSavedPasswords = true,
    this.offerToSavePassword = true,
    this.pushRegistration,
  });

  final KeycloakNative kc;

  /// An unstarted flow; [start] starts it.
  final NativeLoginFlow flow;
  final void Function(NativeLoginResult result) onResult;

  /// Run the passkey sheet as soon as a set offers `passkey`.
  final bool autoSelectPasskey;

  /// Show "Use a saved password" on the username and password screens.
  final bool offersSavedPasswords;

  /// After `AuthorizedStep` from a typed (or newly set) password, offer it to the password manager.
  final bool offerToSavePassword;

  /// The push provider a `push_enrollment` registers (the app's FCM or APNs token); `null` enrolls
  /// without delivery (`none`).
  final Future<PushProviderRegistration> Function()? pushRegistration;

  NativeLoginPhase _phase = const NativeLoginStarting();
  NativeLoginPhase get phase => _phase;

  int _inFlight = 0;
  bool get isSubmitting => _inFlight > 0;

  /// A user-facing error not attached to a challenge (network, passkey or browser failure…).
  String? _message;
  String? get message => _message;

  bool _started = false;
  bool _done = false;
  bool _disposed = false;

  /// The password of a saved password picked on the `username` step, answered to the `password`
  /// challenge that follows.
  String? _pendingSavedPassword;

  /// A typed password, offered for saving once the flow is authorized.
  SavedPassword? _typedPassword;
  String? _typedUsername;

  void start() {
    if (_started) return;
    _started = true;
    _perform(flow.start);
  }

  void submit(ChallengeAnswer answer, Challenge challenge) {
    switch (answer) {
      case UsernameAnswer(:final username):
        _typedUsername = username;
      case PasswordAnswer(:final password) || UpdatePasswordAnswer(:final password):
        _remember(password);
      default:
        break;
    }
    _perform(() => flow.respond(answer, challenge));
  }

  void usePasskey(PasskeyChallenge challenge, {bool preferImmediatelyAvailableCredentials = false}) =>
      _perform(() => flow.usePasskey(challenge, preferImmediatelyAvailableCredentials: preferImmediatelyAvailableCredentials));

  void registerPasskey(PasskeyRegistrationChallenge challenge, {String? label}) => _perform(() => flow.registerPasskey(challenge, label: label));

  void enrollPush(PushEnrollmentChallenge challenge, String deviceLabel) => _perform(() async {
    final registration = await pushRegistration?.call() ?? PushProviderRegistration.none;
    return flow.enrollPush(challenge, deviceLabel: deviceLabel, registration: registration);
  });

  /// Shows the saved-password sheet. On the `username` step the picked username is answered and its
  /// password kept for the `password` challenge that follows; on the `password` step the password is
  /// answered directly. A picked password is saved already, so it is not offered again.
  void useSavedPassword(Challenge challenge) => _perform(() async {
    final saved = await kc.pickSavedPassword();
    _typedPassword = null;
    if (challenge is PasswordChallenge) return flow.respond(ChallengeAnswer.password(saved.password), challenge);
    _pendingSavedPassword = saved.password;
    return flow.respond(ChallengeAnswer.username(saved.username), challenge);
  });

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

  void _remember(String password) {
    final phase = _phase;
    final username = (phase is NativeLoginChallenges ? phase.context.username : null) ?? _typedUsername;
    if (username != null) _typedPassword = SavedPassword(username, password);
  }

  Future<void> _perform(Future<FlowStep> Function() body) async {
    if (_done) return;
    _inFlight += 1;
    _message = null;
    _notify();
    try {
      await _apply(await body());
    } on NativeAuthException catch (e) {
      _pendingSavedPassword = null;
      switch (e.code) {
        // Not a flow failure: the set stays, the user may pick another way.
        case NativeAuthErrorCode.webFallbackCancelled || NativeAuthErrorCode.passkeyCancelled || NativeAuthErrorCode.savedPasswordCancelled:
          break;
        case NativeAuthErrorCode.networkError ||
            NativeAuthErrorCode.webFallbackFailed ||
            NativeAuthErrorCode.passkeyFailed ||
            NativeAuthErrorCode.passkeyUnavailable ||
            NativeAuthErrorCode.rpIdMismatch ||
            NativeAuthErrorCode.savedPasswordUnavailable ||
            NativeAuthErrorCode.dpopKeyError ||
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

  Future<void> _apply(FlowStep step) async {
    switch (step) {
      case ChallengesStep(:final challenges, :final context):
        // A password that came back with an error was wrong: never offer it for saving.
        if (challenges.any((c) => c is PasswordChallenge && c.error != null)) _typedPassword = null;
        final saved = _pendingSavedPassword;
        if (saved != null) {
          _pendingSavedPassword = null;
          final password = challenges.whereType<PasswordChallenge>().where((c) => c.error == null).firstOrNull;
          if (password != null) {
            _phase = NativeLoginChallenges(challenges, context, password);
            // In the same call, so the screen stays busy until the answer is in.
            return _apply(await flow.respond(ChallengeAnswer.password(saved), password));
          }
        }
        final previous = _phase is NativeLoginChallenges ? (_phase as NativeLoginChallenges).selected : null;
        final selected = _pick(challenges, previous);
        _phase = NativeLoginChallenges(challenges, context, selected);
        if (autoSelectPasskey && selected is PasskeyChallenge && selected.error == null) {
          _notify();
          usePasskey(selected);
        }
      case AuthorizedStep(:final credentials):
        _done = true;
        final typed = _typedPassword;
        _typedPassword = null;
        if (typed != null && offerToSavePassword) {
          try {
            await kc.savePassword(typed.username, typed.password);
          } on NativeAuthException {
            // Closing the prompt or having no password manager does not change the outcome.
          }
        }
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
