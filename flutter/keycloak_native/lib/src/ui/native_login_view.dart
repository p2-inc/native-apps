import 'package:flutter/material.dart';

import '../answers.dart';
import '../challenges.dart';
import '../client.dart';
import '../flow.dart';
import '../push.dart';
import 'default_screens.dart';
import 'native_login_controller.dart';
import 'strings.dart';

/// What a challenge screen gets: the challenge, the flow context and the actions.
final class ChallengePresentation {
  ChallengePresentation.internal(this._controller, this.phase, this.strings);

  final NativeLoginController _controller;
  final NativeLoginChallenges phase;
  final NativeLoginStrings strings;

  Challenge get challenge => phase.selected;
  FlowContext get flowContext => phase.context;
  List<Challenge> get alternatives => phase.alternatives;
  bool get isSubmitting => _controller.isSubmitting;
  bool get isStepUp => _controller.flow.isStepUp;

  /// A message not attached to the challenge (network error, browser failure).
  String? get message => _controller.message;

  /// "Use a saved password" is offered on the username and password screens.
  bool get offersSavedPasswords => _controller.offersSavedPasswords;

  void submit(ChallengeAnswer answer) => _controller.submit(answer, challenge);

  /// `passkey`: runs the passkey sheet and answers natively.
  void usePasskey({bool preferImmediatelyAvailableCredentials = false}) {
    if (challenge case final PasskeyChallenge c) {
      _controller.usePasskey(c, preferImmediatelyAvailableCredentials: preferImmediatelyAvailableCredentials);
    }
  }

  /// `passkey_registration`: creates the passkey and answers natively.
  void registerPasskey({String? label}) {
    if (challenge case final PasskeyRegistrationChallenge c) _controller.registerPasskey(c, label: label);
  }

  /// `push_enrollment`: enrolls this device with the view's `pushRegistration`.
  void enrollPush(String deviceLabel) {
    if (challenge case final PushEnrollmentChallenge c) _controller.enrollPush(c, deviceLabel);
  }

  /// The saved-password sheet, on the username or password step.
  void useSavedPassword() => _controller.useSavedPassword(challenge);
  void switchTo(Challenge other) => _controller.select(other);
  void cancel() => _controller.cancel();
}

/// Builds the screen for one challenge type.
typedef ChallengePresenter = Widget Function(BuildContext context, ChallengePresentation presentation);

/// Builds the "Try another way" list under a screen.
typedef ChallengeChooser = Widget Function(BuildContext context, ChallengePresentation presentation);

/// The whole login (spec/05 §4): starts [flow], shows the default screen of each challenge (or the
/// app's from [presenters]), offers the alternatives, runs the browser fallback and reports one
/// [NativeLoginResult]. It does not store credentials or navigate: [onResult] does.
///
/// Pass an unstarted flow and create a new one for each attempt. Every spec/03 challenge type and
/// required action has a default screen; a type this version does not know shows "update required"
/// unless [presenters] has a screen for it.
class NativeLoginView extends StatefulWidget {
  const NativeLoginView({
    super.key,
    required this.kc,
    required this.flow,
    required this.onResult,
    this.presenters = const {},
    this.chooser,
    this.header,
    this.strings,
    this.autoSelectPasskey = false,
    this.offerSavedPasswords = true,
    this.offerToSavePassword = true,
    this.pushRegistration,
  });

  final KeycloakNative kc;
  final NativeLoginFlow flow;
  final void Function(NativeLoginResult result) onResult;

  /// Replacement screens by challenge type.
  final Map<ChallengeType, ChallengePresenter> presenters;

  /// A replacement "Try another way" list.
  final ChallengeChooser? chooser;

  /// Shown above every screen, for a logo.
  final Widget? header;

  /// The texts; by default English or German after the app's locale ([NativeLoginStrings.of]).
  final NativeLoginStrings? strings;

  /// Run the passkey sheet as soon as a set offers `passkey`.
  final bool autoSelectPasskey;

  /// "Use a saved password" on the username and password screens.
  final bool offerSavedPasswords;

  /// Offer a typed password to the password manager after success (Android; iOS AutoFill offers it).
  final bool offerToSavePassword;

  /// The FCM or APNs token a `push_enrollment` registers; without it the device enrolls as `none`.
  final Future<PushProviderRegistration> Function()? pushRegistration;

  @override
  State<NativeLoginView> createState() => _NativeLoginViewState();
}

class _NativeLoginViewState extends State<NativeLoginView> {
  late final NativeLoginController _controller = NativeLoginController(
    kc: widget.kc,
    flow: widget.flow,
    onResult: widget.onResult,
    autoSelectPasskey: widget.autoSelectPasskey,
    offersSavedPasswords: widget.offerSavedPasswords,
    offerToSavePassword: widget.offerToSavePassword,
    pushRegistration: widget.pushRegistration,
  )
    ..addListener(_changed)
    ..start();

  void _changed() => setState(() {});

  @override
  void dispose() {
    _controller.removeListener(_changed);
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final strings = widget.strings ?? NativeLoginStrings.of(context);
    final phase = _controller.phase;
    final Widget body = switch (phase) {
      NativeLoginStarting() || NativeLoginFinished() => Column(
        key: const ValueKey('starting'),
        children: [const CircularProgressIndicator(), const SizedBox(height: 12), Text(strings.contactingServer)],
      ),
      NativeLoginRedirectToWeb(:final request) => RedirectToWebScreen(
        request: request,
        isSubmitting: _controller.isSubmitting,
        message: _controller.message,
        strings: strings,
        open: _controller.openBrowser,
        cancel: _controller.cancel,
      ),
      NativeLoginChallenges() => _challenge(context, ChallengePresentation.internal(_controller, phase, strings)),
    };
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (widget.header case final header?) ...[header, const SizedBox(height: 16)],
          body,
        ],
      ),
    );
  }

  Widget _challenge(BuildContext context, ChallengePresentation presentation) {
    final presenter = widget.presenters[presentation.challenge.type];
    final alternatives = presentation.alternatives.where((c) => answerableChallengeTypes.contains(c.type) || widget.presenters.containsKey(c.type));
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // A new key per challenge, so a screen's text fields start empty for the next challenge.
        KeyedSubtree(
          key: ValueKey('${presentation.challenge.type.wire}:${presentation.challenge.id}'),
          child: presenter?.call(context, presentation) ?? DefaultChallengeScreen(presentation: presentation),
        ),
        if (alternatives.isNotEmpty)
          widget.chooser?.call(context, presentation) ?? DefaultChallengeChooser(presentation: presentation, alternatives: alternatives.toList()),
      ],
    );
  }
}
