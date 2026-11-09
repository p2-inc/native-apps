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
    _ => UnsupportedScreen(presentation: presentation),
  };
}

/// Shared frame: title, context line, the descriptor's error, the content, a cancel button.
class ChallengeFrame extends StatelessWidget {
  const ChallengeFrame({super.key, required this.presentation, required this.title, this.subtitle, required this.children});

  final ChallengePresentation presentation;
  final String title;
  final String? subtitle;
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
          Text(error.message ?? error.code, key: const ValueKey('challengeError'), style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.error)),
          // spec/03 §3.3: attempts left before the realm's brute-force protection locks the account.
          if (presentation.challenge.retryRemaining case final remaining?)
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
