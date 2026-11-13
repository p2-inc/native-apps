import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../answers.dart';
import '../challenges.dart';
import 'native_login_view.dart';
import 'strings.dart';

/// Routes a challenge to its default screen (spec/05 §4 "Provided default screens").
class DefaultChallengeScreen extends StatelessWidget {
  const DefaultChallengeScreen({super.key, required this.presentation});

  final ChallengePresentation presentation;

  @override
  Widget build(BuildContext context) => switch (presentation.challenge) {
    UsernameChallenge() => UsernameScreen(presentation: presentation),
    PasswordChallenge() => PasswordScreen(presentation: presentation),
    TotpChallenge() => TotpScreen(presentation: presentation),
    OtpChallenge() => OtpScreen(presentation: presentation),
    PasskeyChallenge() => PasskeyScreen(presentation: presentation),
    PasskeyRegistrationChallenge() => PasskeyRegistrationScreen(presentation: presentation),
    UpdatePasswordChallenge() => UpdatePasswordScreen(presentation: presentation),
    VerifyEmailChallenge() => VerifyEmailScreen(presentation: presentation),
    TermsChallenge() => TermsScreen(presentation: presentation),
    RecoveryCodeChallenge() => RecoveryCodeScreen(presentation: presentation),
    PushChallenge() => PushScreen(presentation: presentation),
    PushEnrollmentChallenge() => PushEnrollmentScreen(presentation: presentation),
    PinChallenge() => PinScreen(presentation: presentation),
    PinSetupChallenge() => PinSetupScreen(presentation: presentation),
    UnknownChallenge() => UnsupportedScreen(presentation: presentation),
  };
}

/// Shared frame: title, context line, the descriptor's error, the content, a cancel button.
class ChallengeFrame extends StatelessWidget {
  const ChallengeFrame({super.key, required this.presentation, required this.title, this.subtitle, this.errorText, required this.children});

  final ChallengePresentation presentation;
  final String title;
  final String? subtitle;

  /// Replaces the descriptor's `error.message` (screens that localize known error codes).
  final String? errorText;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final strings = presentation.strings;
    final username = presentation.flowContext.username;
    final error = presentation.challenge.error;
    final muted = theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      spacing: 12,
      children: [
        Text(title, style: theme.textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.bold)),
        if (username != null)
          Text(
            presentation.isStepUp
                ? strings.confirmItsYou(presentation.flowContext.displayName ?? username)
                : strings.signingInAs(presentation.flowContext.displayName ?? username),
            style: theme.textTheme.bodyMedium?.copyWith(color: theme.colorScheme.onSurfaceVariant),
          ),
        if (subtitle case final subtitle?) Text(subtitle, style: muted),
        if (error != null) ...[
          Text(
            errorText ?? error.message ?? error.code,
            key: const ValueKey('challengeError'),
            style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error),
          ),
          // spec/03 §3.3: attempts left before the realm's brute-force protection locks the account.
          // A locked credential (spec/03 §4.17) has none left to count.
          if (presentation.challenge.retryRemaining case final remaining? when !presentation.challenge.isLocked)
            Text(strings.attemptsLeft(remaining), key: const ValueKey('retryRemaining'), style: theme.textTheme.bodySmall),
        ],
        if (presentation.message case final message?)
          Text(message, style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error)),
        ...children,
        TextButton(onPressed: presentation.isSubmitting ? null : presentation.cancel, child: Text(strings.cancel)),
      ],
    );
  }
}

/// spec/03 §4.1.
class UsernameScreen extends StatefulWidget {
  const UsernameScreen({super.key, required this.presentation});

  final ChallengePresentation presentation;

  @override
  State<UsernameScreen> createState() => _UsernameScreenState();
}

class _UsernameScreenState extends State<UsernameScreen> {
  late final _username = TextEditingController(text: (widget.presentation.challenge as UsernameChallenge).hint ?? '');

  @override
  void dispose() {
    _username.dispose();
    super.dispose();
  }

  void _submit() {
    if (_username.text.isEmpty) return;
    widget.presentation.submit(ChallengeAnswer.username(_username.text));
  }

  @override
  Widget build(BuildContext context) {
    final p = widget.presentation;
    final allowEmail = (p.challenge as UsernameChallenge).allowEmail;
    return ChallengeFrame(
      presentation: p,
      title: p.strings.signIn,
      subtitle: allowEmail ? p.strings.usernameOrEmail : p.strings.username,
      children: [
        TextField(
          key: const ValueKey('username'),
          controller: _username,
          decoration: InputDecoration(labelText: p.strings.username, border: const OutlineInputBorder()),
          autofillHints: allowEmail ? const [AutofillHints.username, AutofillHints.email] : const [AutofillHints.username],
          keyboardType: allowEmail ? TextInputType.emailAddress : TextInputType.text,
          autocorrect: false,
          textInputAction: TextInputAction.done,
          onChanged: (_) => setState(() {}),
          onSubmitted: (_) => _submit(),
        ),
        FilledButton(onPressed: _username.text.isEmpty || p.isSubmitting ? null : _submit, child: Text(p.strings.continueLabel)),
        SavedPasswordButton(presentation: p),
      ],
    );
  }
}

/// spec/03 §4.2. The username is repeated read-only so password managers can pair the two.
class PasswordScreen extends StatefulWidget {
  const PasswordScreen({super.key, required this.presentation});

  final ChallengePresentation presentation;

  @override
  State<PasswordScreen> createState() => _PasswordScreenState();
}

class _PasswordScreenState extends State<PasswordScreen> {
  final _password = TextEditingController();

  @override
  void dispose() {
    _password.dispose();
    super.dispose();
  }

  void _submit() {
    if (_password.text.isEmpty) return;
    // Ends the autofill context with the username and password on screen, so a password manager can save them.
    TextInput.finishAutofillContext();
    widget.presentation.submit(ChallengeAnswer.password(_password.text));
  }

  @override
  Widget build(BuildContext context) {
    final p = widget.presentation;
    final username = p.flowContext.username;
    return AutofillGroup(
      child: ChallengeFrame(
        presentation: p,
        title: p.strings.enterPassword,
        children: [
          if (username != null)
            TextFormField(
              key: const ValueKey('autofillUsername'),
              initialValue: username,
              readOnly: true,
              autofillHints: const [AutofillHints.username],
              decoration: InputDecoration(labelText: p.strings.username, border: const OutlineInputBorder()),
            ),
          TextField(
            key: const ValueKey('password'),
            controller: _password,
            obscureText: true,
            autofillHints: const [AutofillHints.password],
            decoration: InputDecoration(labelText: p.strings.password, border: const OutlineInputBorder()),
            textInputAction: TextInputAction.done,
            onChanged: (_) => setState(() {}),
            onSubmitted: (_) => _submit(),
          ),
          FilledButton(onPressed: _password.text.isEmpty || p.isSubmitting ? null : _submit, child: Text(p.strings.signIn)),
          SavedPasswordButton(presentation: p),
        ],
      ),
    );
  }
}

/// spec/03 §4.5, with an authenticator picker when the user has several.
class TotpScreen extends StatefulWidget {
  const TotpScreen({super.key, required this.presentation});

  final ChallengePresentation presentation;

  @override
  State<TotpScreen> createState() => _TotpScreenState();
}

class _TotpScreenState extends State<TotpScreen> {
  final _code = TextEditingController();
  String? _credentialId;

  @override
  void dispose() {
    _code.dispose();
    super.dispose();
  }

  void _submit() {
    if (_code.text.isEmpty) return;
    widget.presentation.submit(ChallengeAnswer.totp(_code.text, credentialId: _credentialId));
  }

  @override
  Widget build(BuildContext context) {
    final p = widget.presentation;
    final challenge = p.challenge as TotpChallenge;
    final credentials = challenge.credentials;
    return ChallengeFrame(
      presentation: p,
      title: p.strings.authenticatorCode,
      subtitle: p.strings.enterTotp(challenge.digits),
      children: [
        if (credentials.length > 1)
          DropdownButtonFormField<String?>(
            key: const ValueKey('authenticator'),
            initialValue: _credentialId,
            decoration: InputDecoration(labelText: p.strings.authenticator, border: const OutlineInputBorder()),
            items: [
              DropdownMenuItem(value: null, child: Text(p.strings.defaultAuthenticator)),
              for (final credential in credentials) DropdownMenuItem(value: credential.id, child: Text(credential.label)),
            ],
            onChanged: (value) => setState(() => _credentialId = value),
          ),
        TextField(
          key: const ValueKey('totp'),
          controller: _code,
          // Password managers that keep the account's TOTP secret fill this.
          autofillHints: const [AutofillHints.oneTimeCode],
          keyboardType: TextInputType.number,
          inputFormatters: [FilteringTextInputFormatter.digitsOnly, LengthLimitingTextInputFormatter(challenge.digits)],
          decoration: InputDecoration(labelText: p.strings.code, border: const OutlineInputBorder()),
          textInputAction: TextInputAction.done,
          onChanged: (_) => setState(() {}),
          onSubmitted: (_) => _submit(),
        ),
        FilledButton(onPressed: _code.text.isEmpty || p.isSubmitting ? null : _submit, child: Text(p.strings.verify)),
      ],
    );
  }
}

/// "Use a saved password": the system sheet of passwords saved for the app.
class SavedPasswordButton extends StatelessWidget {
  const SavedPasswordButton({super.key, required this.presentation});

  final ChallengePresentation presentation;

  @override
  Widget build(BuildContext context) {
    if (!presentation.offersSavedPasswords) return const SizedBox.shrink();
    return TextButton(
      key: const ValueKey('useSavedPassword'),
      onPressed: presentation.isSubmitting ? null : presentation.useSavedPassword,
      child: Text(presentation.strings.useSavedPassword),
    );
  }
}

/// Seconds until [until], ticking once a second while it is in the future (resend cooldowns). The
/// timer stops at zero, so a settled screen schedules no frames.
class Countdown extends StatefulWidget {
  const Countdown({super.key, required this.until, required this.builder});

  final DateTime? until;
  final Widget Function(BuildContext context, int secondsLeft) builder;

  @override
  State<Countdown> createState() => _CountdownState();
}

class _CountdownState extends State<Countdown> {
  Timer? _timer;

  int get _left {
    final until = widget.until;
    if (until == null) return 0;
    final ms = until.difference(DateTime.now()).inMilliseconds;
    return ms <= 0 ? 0 : (ms / 1000).ceil();
  }

  void _schedule() {
    _timer?.cancel();
    if (_left > 0) {
      _timer = Timer.periodic(const Duration(seconds: 1), (_) {
        setState(() {});
        if (_left == 0) _timer?.cancel();
      });
    }
  }

  @override
  void initState() {
    super.initState();
    _schedule();
  }

  @override
  void didUpdateWidget(Countdown oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.until != widget.until) _schedule();
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => widget.builder(context, _left);
}

/// A one-line field for codes.
class _CodeField extends StatelessWidget {
  const _CodeField({required this.fieldKey, required this.controller, required this.label, required this.onChanged, required this.onSubmitted, this.digits});

  final String fieldKey;
  final TextEditingController controller;
  final String label;
  final int? digits;
  final VoidCallback onChanged;
  final VoidCallback onSubmitted;

  @override
  Widget build(BuildContext context) => TextField(
    key: ValueKey(fieldKey),
    controller: controller,
    autofillHints: const [AutofillHints.oneTimeCode],
    keyboardType: TextInputType.number,
    inputFormatters: [FilteringTextInputFormatter.digitsOnly, if (digits != null) LengthLimitingTextInputFormatter(digits)],
    decoration: InputDecoration(labelText: label, border: const OutlineInputBorder()),
    textInputAction: TextInputAction.done,
    onChanged: (_) => onChanged(),
    onSubmitted: (_) => onSubmitted(),
  );
}

/// `otp` (spec/03 §4.6): the masked destination, a resend button with the server's cooldown, and a
/// "Send me a code" button first when the server has not sent one yet (`sent: false`).
class OtpScreen extends StatefulWidget {
  const OtpScreen({super.key, required this.presentation});

  final ChallengePresentation presentation;

  @override
  State<OtpScreen> createState() => _OtpScreenState();
}

class _OtpScreenState extends State<OtpScreen> {
  final _code = TextEditingController();

  @override
  void dispose() {
    _code.dispose();
    super.dispose();
  }

  void _submit() {
    if (_code.text.isNotEmpty) widget.presentation.submit(ChallengeAnswer.otp(_code.text));
  }

  @override
  Widget build(BuildContext context) {
    final p = widget.presentation;
    final s = p.strings;
    final c = p.challenge as OtpChallenge;
    final sms = c.channel == 'sms';
    final destination = c.destinationMasked ?? (sms ? s.yourPhone : s.yourEmail);
    return ChallengeFrame(
      presentation: p,
      title: sms ? s.textMessageCode : s.emailCode,
      subtitle: c.sent ? s.weSentCode(c.digits, destination) : s.weCanSendCode(c.digits, destination),
      children: [
        if (c.sent) ...[
          _CodeField(fieldKey: 'otp', controller: _code, label: s.code, digits: c.digits, onChanged: () => setState(() {}), onSubmitted: _submit),
          FilledButton(onPressed: _code.text.isEmpty || p.isSubmitting ? null : _submit, child: Text(s.verify)),
        ],
        Countdown(
          until: c.resendAllowedAt,
          builder: (context, wait) {
            final onPressed = wait > 0 || p.isSubmitting ? null : () => p.submit(const ChallengeAnswer.otpResend());
            return c.sent
                ? OutlinedButton(key: const ValueKey('otpResend'), onPressed: onPressed, child: Text(wait > 0 ? s.resendCodeIn(wait) : s.resendCode))
                : FilledButton(key: const ValueKey('otpSend'), onPressed: onPressed, child: Text(wait > 0 ? s.sendMeCodeIn(wait) : s.sendMeCode));
          },
        ),
      ],
    );
  }
}

/// `passkey` (spec/03 §4.3): the platform sheet runs natively.
class PasskeyScreen extends StatelessWidget {
  const PasskeyScreen({super.key, required this.presentation});

  final ChallengePresentation presentation;

  @override
  Widget build(BuildContext context) {
    final p = presentation;
    final c = p.challenge as PasskeyChallenge;
    return ChallengeFrame(
      presentation: p,
      title: p.strings.passkeyTitle,
      subtitle: c.discoverable ? p.strings.passkeyDiscoverable : p.strings.passkeyAllowList,
      children: [
        FilledButton(key: const ValueKey('usePasskey'), onPressed: p.isSubmitting ? null : p.usePasskey, child: Text(p.strings.continueWithPasskey)),
      ],
    );
  }
}

/// `passkey_registration` (spec/03 §4.4, §4.11): create a passkey, with "Not now" when skippable.
class PasskeyRegistrationScreen extends StatefulWidget {
  const PasskeyRegistrationScreen({super.key, required this.presentation});

  final ChallengePresentation presentation;

  @override
  State<PasskeyRegistrationScreen> createState() => _PasskeyRegistrationScreenState();
}

class _PasskeyRegistrationScreenState extends State<PasskeyRegistrationScreen> {
  final _label = TextEditingController();

  @override
  void dispose() {
    _label.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final p = widget.presentation;
    final s = p.strings;
    final c = p.challenge as PasskeyRegistrationChallenge;
    final user = c.userName ?? s.yourAccount;
    return ChallengeFrame(
      presentation: p,
      title: s.createAPasskey,
      // spec/03 §4.11: a skippable registration is an offer, not a requirement.
      subtitle: c.isSkippable ? s.passkeyOffer(user) : s.passkeyRequired(c.rpName ?? s.thisService, user),
      children: [
        TextField(key: const ValueKey('passkeyLabel'), controller: _label, decoration: InputDecoration(labelText: s.passkeyName, border: const OutlineInputBorder())),
        FilledButton(
          key: const ValueKey('createPasskey'),
          onPressed: p.isSubmitting ? null : () => p.registerPasskey(label: _label.text.isEmpty ? null : _label.text),
          child: Text(s.createPasskey),
        ),
        if (c.isSkippable)
          TextButton(key: const ValueKey('skipChallenge'), onPressed: p.isSubmitting ? null : () => p.submit(ChallengeAnswer.skip(c.type)), child: Text(s.notNow)),
      ],
    );
  }
}

/// `update_password` (spec/03 §4.12): the new password twice, with the realm's policy as hints.
class UpdatePasswordScreen extends StatefulWidget {
  const UpdatePasswordScreen({super.key, required this.presentation});

  final ChallengePresentation presentation;

  @override
  State<UpdatePasswordScreen> createState() => _UpdatePasswordScreenState();
}

class _UpdatePasswordScreenState extends State<UpdatePasswordScreen> {
  final _password = TextEditingController();
  final _confirm = TextEditingController();

  @override
  void dispose() {
    _password.dispose();
    _confirm.dispose();
    super.dispose();
  }

  bool get _canSubmit => _password.text.isNotEmpty && _confirm.text == _password.text && !widget.presentation.isSubmitting;

  void _submit() {
    if (!_canSubmit) return;
    TextInput.finishAutofillContext();
    widget.presentation.submit(ChallengeAnswer.updatePassword(_password.text, confirm: _confirm.text));
  }

  @override
  Widget build(BuildContext context) {
    final p = widget.presentation;
    final s = p.strings;
    final c = p.challenge as UpdatePasswordChallenge;
    final username = p.flowContext.username ?? c.username;
    final hints = s.passwordPolicyHints(c.policy);
    final theme = Theme.of(context);
    return AutofillGroup(
      child: ChallengeFrame(
        presentation: p,
        title: s.chooseNewPassword,
        subtitle: s.passwordMustUpdate,
        children: [
          if (username != null)
            TextFormField(
              key: const ValueKey('autofillUsername'),
              initialValue: username,
              readOnly: true,
              autofillHints: const [AutofillHints.username],
              decoration: InputDecoration(labelText: s.username, border: const OutlineInputBorder()),
            ),
          TextField(
            key: const ValueKey('newPassword'),
            controller: _password,
            obscureText: true,
            autofillHints: const [AutofillHints.newPassword],
            decoration: InputDecoration(labelText: s.newPassword, border: const OutlineInputBorder()),
            onChanged: (_) => setState(() {}),
          ),
          TextField(
            key: const ValueKey('newPasswordConfirm'),
            controller: _confirm,
            obscureText: true,
            autofillHints: const [AutofillHints.newPassword],
            decoration: InputDecoration(labelText: s.confirmNewPassword, border: const OutlineInputBorder()),
            textInputAction: TextInputAction.done,
            onChanged: (_) => setState(() {}),
            onSubmitted: (_) => _submit(),
          ),
          if (hints.isNotEmpty)
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [for (final hint in hints) Text('• $hint', style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant))],
            ),
          if (_confirm.text.isNotEmpty && _confirm.text != _password.text)
            Text(s.passwordsDoNotMatch, style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error)),
          FilledButton(key: const ValueKey('updatePassword'), onPressed: _canSubmit ? _submit : null, child: Text(s.updatePassword)),
        ],
      ),
    );
  }
}

/// `verify_email` (spec/03 §4.13): the code sent to the masked address, with resend and cooldown.
class VerifyEmailScreen extends StatefulWidget {
  const VerifyEmailScreen({super.key, required this.presentation});

  final ChallengePresentation presentation;

  @override
  State<VerifyEmailScreen> createState() => _VerifyEmailScreenState();
}

class _VerifyEmailScreenState extends State<VerifyEmailScreen> {
  final _code = TextEditingController();

  @override
  void dispose() {
    _code.dispose();
    super.dispose();
  }

  void _submit() {
    if (_code.text.isNotEmpty) widget.presentation.submit(ChallengeAnswer.verifyEmail(_code.text));
  }

  @override
  Widget build(BuildContext context) {
    final p = widget.presentation;
    final s = p.strings;
    final c = p.challenge as VerifyEmailChallenge;
    final destination = c.emailMasked ?? s.yourEmail;
    return ChallengeFrame(
      presentation: p,
      title: s.verifyEmail,
      subtitle: c.sent ? s.weSentCode(c.digits, destination) : s.weNeedToSendCode(c.digits, destination),
      children: [
        if (c.sent) ...[
          _CodeField(fieldKey: 'verifyEmailCode', controller: _code, label: s.code, digits: c.digits, onChanged: () => setState(() {}), onSubmitted: _submit),
          FilledButton(onPressed: _code.text.isEmpty || p.isSubmitting ? null : _submit, child: Text(s.verify)),
        ],
        Countdown(
          until: c.resendAllowedAt,
          builder: (context, wait) => OutlinedButton(
            key: const ValueKey('verifyEmailResend'),
            onPressed: wait > 0 || p.isSubmitting ? null : () => p.submit(const ChallengeAnswer.verifyEmailResend()),
            child: Text(switch ((c.sent, wait > 0)) {
              (true, true) => s.resendCodeIn(wait),
              (true, false) => s.resendCode,
              (false, true) => s.sendCodeIn(wait),
              (false, false) => s.sendCode,
            }),
          ),
        ),
      ],
    );
  }
}

/// `terms` (spec/03 §4.14): the text and/or a link, then accept or decline (decline ends the login).
/// The link opens through [TermsScreen.openUrl]; without one it is shown as text to copy.
class TermsScreen extends StatelessWidget {
  const TermsScreen({super.key, required this.presentation, this.openUrl});

  final ChallengePresentation presentation;

  /// Opens the full terms (e.g. `url_launcher`'s `launchUrl`); the plugin has no browser of its own.
  final void Function(Uri url)? openUrl;

  @override
  Widget build(BuildContext context) {
    final p = presentation;
    final s = p.strings;
    final c = p.challenge as TermsChallenge;
    final theme = Theme.of(context);
    return ChallengeFrame(
      presentation: p,
      title: s.terms,
      subtitle: c.version == null ? null : s.termsVersion(c.version!),
      children: [
        if (c.text case final text?)
          ConstrainedBox(
            constraints: const BoxConstraints(maxHeight: 220),
            child: SingleChildScrollView(child: Text(text, key: const ValueKey('termsText'), style: theme.textTheme.bodySmall)),
          ),
        if (c.url case final url?)
          openUrl == null ? SelectableText(url.toString(), style: theme.textTheme.bodySmall) : TextButton(onPressed: () => openUrl!(url), child: Text(s.readFullTerms)),
        FilledButton(key: const ValueKey('acceptTerms'), onPressed: p.isSubmitting ? null : () => p.submit(const ChallengeAnswer.terms(accepted: true)), child: Text(s.accept)),
        OutlinedButton(
          key: const ValueKey('declineTerms'),
          onPressed: p.isSubmitting ? null : () => p.submit(const ChallengeAnswer.terms(accepted: false)),
          child: Text(s.decline, style: TextStyle(color: theme.colorScheme.error)),
        ),
      ],
    );
  }
}

/// `recovery_code` (spec/03 §4.8): one single-use code, with the remaining count and a warning.
class RecoveryCodeScreen extends StatefulWidget {
  const RecoveryCodeScreen({super.key, required this.presentation});

  final ChallengePresentation presentation;

  @override
  State<RecoveryCodeScreen> createState() => _RecoveryCodeScreenState();
}

class _RecoveryCodeScreenState extends State<RecoveryCodeScreen> {
  final _code = TextEditingController();

  @override
  void dispose() {
    _code.dispose();
    super.dispose();
  }

  void _submit() {
    if (_code.text.isNotEmpty) widget.presentation.submit(ChallengeAnswer.recoveryCode(_code.text));
  }

  @override
  Widget build(BuildContext context) {
    final p = widget.presentation;
    final s = p.strings;
    final c = p.challenge as RecoveryCodeChallenge;
    final theme = Theme.of(context);
    return ChallengeFrame(
      presentation: p,
      title: s.recoveryCode,
      subtitle: c.remaining == null ? s.recoveryCodeEnter : s.recoveryCodeLeft(c.remaining!),
      children: [
        if (c.shouldWarn) Text(s.recoveryCodeLow, style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.tertiary)),
        TextField(
          key: const ValueKey('recoveryCode'),
          controller: _code,
          textCapitalization: TextCapitalization.characters,
          autocorrect: false,
          decoration: const InputDecoration(labelText: 'XXXX-XXXX-XXXX', border: OutlineInputBorder()),
          textInputAction: TextInputAction.done,
          onChanged: (_) => setState(() {}),
          onSubmitted: (_) => _submit(),
        ),
        FilledButton(onPressed: _code.text.isEmpty || p.isSubmitting ? null : _submit, child: Text(s.signIn)),
      ],
    );
  }
}

/// `push` (spec/03 §4.7): sends the push when the user asks (or shows the one already sent), shows the
/// number for number match, and polls every `poll_interval` seconds until the device answers.
class PushScreen extends StatefulWidget {
  const PushScreen({super.key, required this.presentation});

  final ChallengePresentation presentation;

  @override
  State<PushScreen> createState() => _PushScreenState();
}

class _PushScreenState extends State<PushScreen> {
  Timer? _poll;

  PushChallenge get _challenge => widget.presentation.challenge as PushChallenge;

  void _schedule() {
    _poll?.cancel();
    final c = _challenge;
    if (!c.isPending) return;
    // The server advances on `approved` (spec/03 §4.7).
    _poll = Timer.periodic(Duration(seconds: c.pollInterval), (_) {
      if (!widget.presentation.isSubmitting) widget.presentation.submit(const ChallengeAnswer.pushPoll());
    });
  }

  @override
  void initState() {
    super.initState();
    _schedule();
  }

  @override
  void didUpdateWidget(PushScreen oldWidget) {
    super.didUpdateWidget(oldWidget);
    _schedule();
  }

  @override
  void dispose() {
    _poll?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final p = widget.presentation;
    final s = p.strings;
    final c = _challenge;
    final theme = Theme.of(context);
    final device = c.devices.isEmpty ? s.yourPhone : c.devices.first;
    return ChallengeFrame(
      presentation: p,
      title: s.approveOnPhone,
      subtitle: c.sent ? s.pushSent(device) : s.pushCanSend(device),
      children: [
        if (c.sent) ...[
          if (c.userVerificationNumber case final number?)
            Column(
              children: [
                Text(s.pushChooseNumber, style: theme.textTheme.bodySmall),
                Text(number, key: const ValueKey('pushNumber'), style: theme.textTheme.displayMedium?.copyWith(fontWeight: FontWeight.bold)),
              ],
            ),
          Row(
            spacing: 8,
            children: [
              const SizedBox.square(dimension: 16, child: CircularProgressIndicator(strokeWidth: 2)),
              Text(s.pushWaiting, key: const ValueKey('pushWaiting'), style: theme.textTheme.bodySmall),
            ],
          ),
          OutlinedButton(key: const ValueKey('pushPoll'), onPressed: p.isSubmitting ? null : () => p.submit(const ChallengeAnswer.pushPoll()), child: Text(s.checkNow)),
        ] else
          Countdown(
            until: c.resendAllowedAt,
            builder: (context, wait) => FilledButton(
              key: const ValueKey('pushSend'),
              onPressed: wait > 0 || p.isSubmitting ? null : () => p.submit(const ChallengeAnswer.pushResend()),
              child: Text(wait > 0 ? s.sendRequestIn(wait) : s.sendRequest),
            ),
          ),
      ],
    );
  }
}

/// `push_enrollment` (spec/03 §4.15): enrolls this device with the SDK's DPoP key. Messages reach it
/// through the view's `pushRegistration`; without one the device reads its approvals itself.
class PushEnrollmentScreen extends StatefulWidget {
  const PushEnrollmentScreen({super.key, required this.presentation});

  final ChallengePresentation presentation;

  @override
  State<PushEnrollmentScreen> createState() => _PushEnrollmentScreenState();
}

class _PushEnrollmentScreenState extends State<PushEnrollmentScreen> {
  final _label = TextEditingController();

  @override
  void dispose() {
    _label.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final p = widget.presentation;
    final s = p.strings;
    return ChallengeFrame(
      presentation: p,
      title: s.pushEnrollTitle,
      subtitle: s.pushEnrollSubtitle(p.flowContext.clientName ?? s.thisService),
      children: [
        TextField(key: const ValueKey('pushDeviceLabel'), controller: _label, decoration: InputDecoration(labelText: s.deviceName, border: const OutlineInputBorder())),
        FilledButton(
          key: const ValueKey('pushEnroll'),
          onPressed: p.isSubmitting ? null : () => p.enrollPush(_label.text.isEmpty ? s.thisDevice : _label.text),
          child: Text(s.pushEnroll),
        ),
        if (p.challenge.isSkippable)
          TextButton(key: const ValueKey('skipChallenge'), onPressed: p.isSubmitting ? null : () => p.submit(ChallengeAnswer.skip(p.challenge.type)), child: Text(s.notNow)),
      ],
    );
  }
}

/// A type without a default screen in this version, or one no SDK can answer.
class UnsupportedScreen extends StatelessWidget {
  const UnsupportedScreen({super.key, required this.presentation});

  final ChallengePresentation presentation;

  @override
  Widget build(BuildContext context) => ChallengeFrame(
    presentation: presentation,
    title: presentation.strings.updateRequired,
    subtitle: presentation.strings.unsupported(presentation.challenge.type.wire),
    children: const [],
  );
}

/// The localized text for a `pin` / `pin_setup` error code, else `null` (the server's message is shown).
String? _pinErrorText(String? code, int length, NativeLoginStrings strings) => switch (code) {
  ChallengeError.invalidCredential => strings.pinIncorrect,
  ChallengeError.missingCredential => strings.pinEnter,
  ChallengeError.pinMismatch => strings.pinMismatch,
  ChallengeError.weakPin => strings.pinWeak,
  ChallengeError.invalidFormat => strings.pinInvalidFormat(length),
  _ => null,
};

/// `pin` (spec/03 §4.17): one slot per digit, a numeric keypad, masked entry; submits when every slot
/// is filled. A `credential_locked` descriptor replaces the keypad with an explanation: the PIN must
/// be reset (on the web or by an administrator), so only cancel (or another way) is left.
class PinScreen extends StatefulWidget {
  const PinScreen({super.key, required this.presentation});

  final ChallengePresentation presentation;

  @override
  State<PinScreen> createState() => _PinScreenState();
}

class _PinScreenState extends State<PinScreen> {
  // Never a TextEditingController: the PIN stays out of the text input and autofill system.
  String _pin = '';

  void _digit(String digit, int length) {
    if (_pin.length >= length) return;
    final next = _pin + digit;
    setState(() => _pin = next.length == length ? '' : next);
    if (next.length == length) widget.presentation.submit(ChallengeAnswer.pin(next));
  }

  @override
  Widget build(BuildContext context) {
    final p = widget.presentation;
    final c = p.challenge as PinChallenge;
    final s = p.strings;
    if (c.isLocked) {
      return ChallengeFrame(
        presentation: p,
        title: s.pinLockedTitle,
        errorText: s.pinTooMany,
        children: [Text(s.pinLocked, key: const ValueKey('pinLocked'), style: Theme.of(context).textTheme.bodyMedium)],
      );
    }
    return ChallengeFrame(
      presentation: p,
      title: s.pinTitle,
      subtitle: s.pinSubtitle(c.length),
      errorText: _pinErrorText(c.error?.code, c.length, s),
      children: [
        PinSlots(length: c.length, filled: _pin.length, strings: s),
        PinKeypad(
          enabled: !p.isSubmitting,
          strings: s,
          onDigit: (digit) => _digit(digit, c.length),
          onDelete: () => setState(() => _pin = _pin.isEmpty ? '' : _pin.substring(0, _pin.length - 1)),
        ),
      ],
    );
  }
}

/// `pin_setup` (spec/03 §4.18): the new PIN, then the same PIN again; a local mismatch starts over
/// without a round trip. The server's `pin_mismatch`, `invalid_format` and `weak_pin` are shown above
/// the slots.
class PinSetupScreen extends StatefulWidget {
  const PinSetupScreen({super.key, required this.presentation});

  final ChallengePresentation presentation;

  @override
  State<PinSetupScreen> createState() => _PinSetupScreenState();
}

class _PinSetupScreenState extends State<PinSetupScreen> {
  String _pin = '';
  String _confirm = '';
  bool _confirming = false;
  bool _localMismatch = false;

  void _digit(String digit, int length) {
    if (_confirming) {
      if (_confirm.length >= length) return;
      final second = _confirm + digit;
      if (second.length < length) {
        setState(() => _confirm = second);
        return;
      }
      final first = _pin;
      setState(() {
        _pin = '';
        _confirm = '';
        _confirming = false;
        _localMismatch = first != second;
      });
      if (first == second) widget.presentation.submit(ChallengeAnswer.pinSetup(first, confirm: second));
    } else if (_pin.length < length) {
      setState(() {
        _pin += digit;
        if (_pin.length == length) {
          _localMismatch = false;
          _confirming = true;
        }
      });
    }
  }

  void _delete() => setState(() {
    if (_confirming && _confirm.isEmpty) {
      _confirming = false;
      _pin = '';
    } else if (_confirming) {
      _confirm = _confirm.substring(0, _confirm.length - 1);
    } else if (_pin.isNotEmpty) {
      _pin = _pin.substring(0, _pin.length - 1);
    }
  });

  @override
  Widget build(BuildContext context) {
    final p = widget.presentation;
    final c = p.challenge as PinSetupChallenge;
    final s = p.strings;
    final theme = Theme.of(context);
    return ChallengeFrame(
      presentation: p,
      title: _confirming ? s.pinConfirmTitle : s.pinChooseTitle,
      subtitle: _confirming ? s.pinConfirmSubtitle(c.length) : s.pinChooseSubtitle(c.length),
      errorText: _pinErrorText(c.error?.code, c.length, s),
      children: [
        if (_localMismatch)
          Text(s.pinMismatch, key: const ValueKey('pinMismatch'), style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error)),
        PinSlots(length: c.length, filled: _confirming ? _confirm.length : _pin.length, strings: s),
        PinKeypad(enabled: !p.isSubmitting, strings: s, onDigit: (digit) => _digit(digit, c.length), onDelete: _delete),
        if (c.isSkippable)
          TextButton(key: const ValueKey('skipChallenge'), onPressed: p.isSubmitting ? null : () => p.submit(ChallengeAnswer.skip(c.type)), child: Text(s.notNow)),
      ],
    );
  }
}

/// One slot per digit; filled slots show a dot, never the digit.
class PinSlots extends StatelessWidget {
  const PinSlots({super.key, required this.length, required this.filled, required this.strings});

  final int length;
  final int filled;
  final NativeLoginStrings strings;

  @override
  Widget build(BuildContext context) {
    final colors = Theme.of(context).colorScheme;
    return Semantics(
      container: true,
      label: strings.pinDigitsEntered(filled, length),
      child: ExcludeSemantics(
        child: Row(
          key: const ValueKey('pinSlots'),
          mainAxisAlignment: MainAxisAlignment.center,
          spacing: 12,
          children: [
            for (var index = 0; index < length; index++)
              Container(
                width: 16,
                height: 16,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  border: Border.all(color: colors.outline, width: 1.5),
                  color: index < filled ? colors.onSurface : Colors.transparent,
                ),
              ),
          ],
        ),
      ),
    );
  }
}

/// A 3×4 numeric keypad (1–9, 0, delete): never the system keyboard, so no autofill or suggestions.
class PinKeypad extends StatelessWidget {
  const PinKeypad({super.key, required this.enabled, required this.strings, required this.onDigit, required this.onDelete});

  final bool enabled;
  final NativeLoginStrings strings;
  final ValueChanged<String> onDigit;
  final VoidCallback onDelete;

  static const _rows = [
    ['1', '2', '3'],
    ['4', '5', '6'],
    ['7', '8', '9'],
    [null, '0', 'delete'],
  ];

  @override
  Widget build(BuildContext context) {
    const size = Size(72, 52);
    return Column(
      spacing: 8,
      children: [
        for (final row in _rows)
          Row(
            mainAxisAlignment: MainAxisAlignment.center,
            spacing: 12,
            children: [
              for (final key in row)
                switch (key) {
                  null => SizedBox.fromSize(size: size),
                  'delete' => SizedBox.fromSize(
                    size: size,
                    child: OutlinedButton(
                      key: const ValueKey('pinDelete'),
                      onPressed: enabled ? onDelete : null,
                      child: Semantics(label: strings.delete, excludeSemantics: true, child: const Text('⌫')),
                    ),
                  ),
                  final digit => SizedBox.fromSize(
                    size: size,
                    child: OutlinedButton(
                      key: ValueKey('pinKey-$digit'),
                      onPressed: enabled ? () => onDigit(digit) : null,
                      child: Text(digit, style: Theme.of(context).textTheme.titleLarge),
                    ),
                  ),
                },
            ],
          ),
      ],
    );
  }
}

/// The default "Try another way" list under a screen.
class DefaultChallengeChooser extends StatelessWidget {
  const DefaultChallengeChooser({super.key, required this.presentation, required this.alternatives});

  final ChallengePresentation presentation;
  final List<Challenge> alternatives;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(presentation.strings.tryAnotherWay, style: theme.textTheme.labelMedium?.copyWith(color: theme.colorScheme.onSurfaceVariant)),
        for (final challenge in alternatives)
          TextButton(
            key: ValueKey('switchTo-${challenge.type.wire}'),
            onPressed: () => presentation.switchTo(challenge),
            child: Text(
              presentation.strings.chooserTitle(challenge.type.wire, otpChannel: challenge is OtpChallenge ? challenge.channel : null),
            ),
          ),
      ],
    );
  }
}

/// `redirect_to_web` (spec/03 §3.4): explains why and opens the browser.
class RedirectToWebScreen extends StatelessWidget {
  const RedirectToWebScreen({
    super.key,
    required this.request,
    required this.isSubmitting,
    required this.message,
    required this.strings,
    required this.open,
    required this.cancel,
  });

  final RedirectToWebRequest request;
  final bool isSubmitting;
  final String? message;
  final NativeLoginStrings strings;
  final VoidCallback open;
  final VoidCallback cancel;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final reason = request.reason;
    final explanation = reason != null && reason.startsWith('required_action:')
        ? strings.accountNeedsAttention(reason.substring('required_action:'.length).replaceAll('_', ' ').toLowerCase())
        : request.errorDescription ?? strings.completeOnWeb;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      spacing: 12,
      children: [
        Text(strings.continueInBrowser, style: theme.textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.bold)),
        Text(explanation, style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant)),
        if (message case final message?) Text(message, style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error)),
        FilledButton(key: const ValueKey('openBrowser'), onPressed: isSubmitting ? null : open, child: Text(strings.openBrowser)),
        TextButton(onPressed: cancel, child: Text(strings.cancel)),
      ],
    );
  }
}
