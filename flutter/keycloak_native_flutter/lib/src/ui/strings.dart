import 'package:flutter/widgets.dart';

/// Texts of the default widgets: English here, German in [NativeLoginStringsDe] (the native UI
/// layers' two catalogues, same wording). `NativeLoginView` picks by the app's locale through
/// [NativeLoginStrings.of]; subclass and pass your own to reword or add a language.
class NativeLoginStrings {
  const NativeLoginStrings();

  /// German for `de`, English otherwise.
  static NativeLoginStrings forLocale(Locale? locale) => locale?.languageCode == 'de' ? const NativeLoginStringsDe() : const NativeLoginStrings();

  /// The strings for the locale of [context] (English without a `Localizations` ancestor).
  static NativeLoginStrings of(BuildContext context) => forLocale(Localizations.maybeLocaleOf(context));

  String get contactingServer => 'Contacting the server…';
  String get cancel => 'Cancel';
  String signingInAs(String name) => 'Signing in as $name';
  String confirmItsYou(String name) => "Confirm it's you, $name";
  String get tryAnotherWay => 'Try another way';
  String get signIn => 'Sign in';
  String get username => 'Username';
  String get usernameOrEmail => 'Username or email';
  String get continueLabel => 'Continue';
  String get useSavedPassword => 'Use a saved password';
  String get enterPassword => 'Enter your password';
  String get password => 'Password';
  String get authenticatorCode => 'Authenticator code';
  String enterTotp(int digits) => 'Enter the $digits-digit code from your authenticator app.';
  String get authenticator => 'Authenticator';
  String get defaultAuthenticator => 'Default';
  String get code => 'Code';
  String get verify => 'Verify';
  String get textMessageCode => 'Text message code';
  String get emailCode => 'Email code';
  String get yourPhone => 'your phone';
  String get yourEmail => 'your email address';
  String weSentCode(int digits, String destination) => 'We sent a $digits-digit code to $destination.';
  String weCanSendCode(int digits, String destination) => 'We can send a $digits-digit code to $destination.';
  String weNeedToSendCode(int digits, String destination) => 'We need to send a $digits-digit code to $destination.';
  String get resendCode => 'Resend code';
  String resendCodeIn(int seconds) => 'Resend code in $seconds s';
  String get sendMeCode => 'Send me a code';
  String sendMeCodeIn(int seconds) => 'Send me a code ($seconds s)';
  String get sendCode => 'Send a code';
  String sendCodeIn(int seconds) => 'Send a code ($seconds s)';
  String get passkeyTitle => 'Sign in with a passkey';
  String get passkeyDiscoverable => 'Use a passkey saved on this device.';
  String get passkeyAllowList => 'Use the passkey registered for this account.';
  String get continueWithPasskey => 'Continue with passkey';
  String get createAPasskey => 'Create a passkey';
  String get createPasskey => 'Create passkey';
  String get passkeyName => 'Passkey name (optional)';
  String passkeyOffer(String user) => 'Sign in faster next time: create a passkey for $user on this device.';
  String passkeyRequired(String service, String user) => '$service requires a passkey for $user before you can continue.';
  String get thisService => 'This service';
  String get yourAccount => 'your account';
  String get notNow => 'Not now';
  String get recoveryCode => 'Recovery code';
  String recoveryCodeLeft(int remaining) => 'Enter one of your unused recovery codes ($remaining left).';
  String get recoveryCodeEnter => 'Enter one of your unused recovery codes.';
  String get recoveryCodeLow => 'You are running low on recovery codes; generate new ones after signing in.';
  String get chooseNewPassword => 'Choose a new password';
  String get passwordMustUpdate => 'Your password must be updated before you can continue.';
  String get newPassword => 'New password';
  String get confirmNewPassword => 'Confirm new password';
  String get passwordsDoNotMatch => 'Passwords do not match';
  String get updatePassword => 'Update password';
  String get verifyEmail => 'Verify your email';
  String get terms => 'Terms and conditions';
  String termsVersion(String version) => 'Version $version';
  String get readFullTerms => 'Read the full terms';
  String get accept => 'Accept';
  String get decline => 'Decline';
  String get updateRequired => 'Update required';
  String unsupported(String type) => "This version of the app cannot handle the '$type' sign-in method. Update the app or sign in on the web.";
  String get usePasskey => 'Use a passkey';
  String get usePassword => 'Use your password';
  String get useAuthenticator => 'Use an authenticator app';
  String get textMeCode => 'Text me a code';
  String get emailMeCode => 'Email me a code';
  String get useRecoveryCode => 'Use a recovery code';
  String get approveOnPhone => 'Approve on your phone';
  String pushSent(String device) => 'We sent a sign-in request to $device. Approve it there to continue.';
  String pushCanSend(String device) => 'We can send a sign-in request to $device.';
  String get pushChooseNumber => 'Choose this number on your phone';
  String get pushWaiting => 'Waiting for your approval…';
  String get pushEnrollTitle => 'Set up sign-in approvals';
  String pushEnrollSubtitle(String client) => '$client asks you to enroll this device so you can approve sign-ins from here.';
  String get deviceName => 'Device name (optional)';
  String get pushEnroll => 'Enroll this device';
  String get thisDevice => 'This device';
  String get pushRequests => 'Sign-in requests';
  String get pushNoRequests => 'No sign-in requests are waiting.';
  String pushSignInTo(String client) => 'Sign-in to $client';
  String pushExpires(String time) => 'Expires $time';
  String get pushPickNumber => 'Pick the number shown on the other screen';
  String get pushPin => 'PIN';
  String get refresh => 'Refresh';
  String get approve => 'Approve';
  String get deny => 'Deny';
  String get checkNow => 'Check now';
  String get sendRequest => 'Send request';
  String sendRequestIn(int seconds) => 'Send request ($seconds s)';
  String get continueInBrowser => 'Continue in your browser';
  String get openBrowser => 'Open browser';
  String accountNeedsAttention(String action) => 'Your account needs attention ($action). Finish it on the web, then you will be returned here.';
  String get completeOnWeb => 'This sign-in has to be completed on the web.';
  String attemptsLeft(int remaining) => remaining == 1 ? '1 attempt left' : '$remaining attempts left';

  /// The label of an alternative in the "Try another way" list.
  String chooserTitle(String type, {String? otpChannel}) => switch (type) {
    'passkey' => usePasskey,
    'password' => usePassword,
    'totp' => useAuthenticator,
    'otp' => otpChannel == 'sms' ? textMeCode : emailMeCode,
    'recovery_code' => useRecoveryCode,
    'push' => approveOnPhone,
    _ => type,
  };

  /// Hints for the realm's password policy (`update_password` params, spec/03 §4.12) in a stable
  /// order; the native SDKs' `UpdatePasswordParams.hints`.
  List<String> passwordPolicyHints(Map<String, Object?> policy) => [
    if (_int(policy['length']) case final n?) 'At least $n characters',
    if (_int(policy['maxLength']) case final n?) 'At most $n characters',
    if (_int(policy['digits']) case final n?) _atLeast(n, 'digit'),
    if (_int(policy['upperCase']) case final n?) _atLeast(n, 'upper-case letter'),
    if (_int(policy['lowerCase']) case final n?) _atLeast(n, 'lower-case letter'),
    if (_int(policy['specialChars']) case final n?) _atLeast(n, 'special character'),
    if (policy['notUsername'] != null) 'Not your username',
    if (policy['notEmail'] != null) 'Not your email address',
    if (policy['notContainsUsername'] != null) 'Must not contain your username',
    if (_int(policy['passwordHistory']) case final n?) 'Not one of your last $n passwords',
    if (policy['regexPattern'] case final String pattern) 'Must match $pattern',
  ];

  String _atLeast(int n, String word) => 'At least $n $word${n == 1 ? '' : 's'}';
}

/// German texts, the translations of the native SDKs' catalogues.
class NativeLoginStringsDe extends NativeLoginStrings {
  const NativeLoginStringsDe();

  @override
  String get contactingServer => 'Verbindung zum Server…';
  @override
  String get cancel => 'Abbrechen';
  @override
  String signingInAs(String name) => 'Anmeldung als $name';
  @override
  String confirmItsYou(String name) => 'Bestätigen Sie, dass Sie es sind, $name';
  @override
  String get tryAnotherWay => 'Anderen Weg versuchen';
  @override
  String get signIn => 'Anmelden';
  @override
  String get username => 'Benutzername';
  @override
  String get usernameOrEmail => 'Benutzername oder E-Mail';
  @override
  String get continueLabel => 'Weiter';
  @override
  String get useSavedPassword => 'Gespeichertes Passwort verwenden';
  @override
  String get enterPassword => 'Passwort eingeben';
  @override
  String get password => 'Passwort';
  @override
  String get authenticatorCode => 'Authenticator-Code';
  @override
  String enterTotp(int digits) => 'Geben Sie den $digits-stelligen Code aus Ihrer Authenticator-App ein.';
  @override
  String get authenticator => 'Authenticator';
  @override
  String get defaultAuthenticator => 'Standard';
  @override
  String get code => 'Code';
  @override
  String get verify => 'Prüfen';
  @override
  String get textMessageCode => 'SMS-Code';
  @override
  String get emailCode => 'E-Mail-Code';
  @override
  String get yourPhone => 'Ihr Telefon';
  @override
  String get yourEmail => 'Ihre E-Mail-Adresse';
  @override
  String weSentCode(int digits, String destination) => 'Wir haben einen $digits-stelligen Code an $destination gesendet.';
  @override
  String weCanSendCode(int digits, String destination) => 'Wir können einen $digits-stelligen Code an $destination senden.';
  @override
  String weNeedToSendCode(int digits, String destination) => 'Wir müssen einen $digits-stelligen Code an $destination senden.';
  @override
  String get resendCode => 'Code erneut senden';
  @override
  String resendCodeIn(int seconds) => 'Erneut senden in $seconds s';
  @override
  String get sendMeCode => 'Code senden';
  @override
  String sendMeCodeIn(int seconds) => 'Code senden ($seconds s)';
  @override
  String get sendCode => 'Code senden';
  @override
  String sendCodeIn(int seconds) => 'Code senden ($seconds s)';
  @override
  String get passkeyTitle => 'Mit Passkey anmelden';
  @override
  String get passkeyDiscoverable => 'Verwenden Sie einen auf diesem Gerät gespeicherten Passkey.';
  @override
  String get passkeyAllowList => 'Verwenden Sie den für dieses Konto registrierten Passkey.';
  @override
  String get continueWithPasskey => 'Mit Passkey fortfahren';
  @override
  String get createAPasskey => 'Passkey erstellen';
  @override
  String get createPasskey => 'Passkey erstellen';
  @override
  String get passkeyName => 'Name des Passkeys (optional)';
  @override
  String passkeyOffer(String user) => 'Beim nächsten Mal schneller anmelden: Erstellen Sie auf diesem Gerät einen Passkey für $user.';
  @override
  String passkeyRequired(String service, String user) => '$service benötigt einen Passkey für $user, bevor Sie fortfahren können.';
  @override
  String get thisService => 'Dieser Dienst';
  @override
  String get yourAccount => 'Ihr Konto';
  @override
  String get notNow => 'Nicht jetzt';
  @override
  String get recoveryCode => 'Wiederherstellungscode';
  @override
  String recoveryCodeLeft(int remaining) => 'Geben Sie einen unbenutzten Wiederherstellungscode ein (noch $remaining).';
  @override
  String get recoveryCodeEnter => 'Geben Sie einen unbenutzten Wiederherstellungscode ein.';
  @override
  String get recoveryCodeLow => 'Ihre Wiederherstellungscodes gehen zur Neige; erzeugen Sie nach der Anmeldung neue.';
  @override
  String get chooseNewPassword => 'Neues Passwort wählen';
  @override
  String get passwordMustUpdate => 'Ihr Passwort muss aktualisiert werden, bevor Sie fortfahren können.';
  @override
  String get newPassword => 'Neues Passwort';
  @override
  String get confirmNewPassword => 'Neues Passwort bestätigen';
  @override
  String get passwordsDoNotMatch => 'Die Passwörter stimmen nicht überein';
  @override
  String get updatePassword => 'Passwort aktualisieren';
  @override
  String get verifyEmail => 'E-Mail-Adresse bestätigen';
  @override
  String get terms => 'Nutzungsbedingungen';
  @override
  String termsVersion(String version) => 'Version $version';
  @override
  String get readFullTerms => 'Vollständige Bedingungen lesen';
  @override
  String get accept => 'Akzeptieren';
  @override
  String get decline => 'Ablehnen';
  @override
  String get updateRequired => 'Aktualisierung erforderlich';
  @override
  String unsupported(String type) => 'Diese App-Version unterstützt die Anmeldemethode „$type“ nicht. Aktualisieren Sie die App oder melden Sie sich im Web an.';
  @override
  String get usePasskey => 'Passkey verwenden';
  @override
  String get usePassword => 'Passwort verwenden';
  @override
  String get useAuthenticator => 'Authenticator-App verwenden';
  @override
  String get textMeCode => 'Code per SMS senden';
  @override
  String get emailMeCode => 'Code per E-Mail senden';
  @override
  String get useRecoveryCode => 'Wiederherstellungscode verwenden';
  @override
  String get approveOnPhone => 'Auf dem Telefon bestätigen';
  @override
  String pushSent(String device) => 'Wir haben eine Anmeldeanfrage an $device gesendet. Bestätigen Sie sie dort, um fortzufahren.';
  @override
  String pushCanSend(String device) => 'Wir können eine Anmeldeanfrage an $device senden.';
  @override
  String get pushChooseNumber => 'Wählen Sie diese Zahl auf Ihrem Telefon';
  @override
  String get pushWaiting => 'Warten auf Ihre Bestätigung…';
  @override
  String get pushEnrollTitle => 'Anmeldebestätigungen einrichten';
  @override
  String pushEnrollSubtitle(String client) => '$client bittet Sie, dieses Gerät zu registrieren, damit Sie Anmeldungen von hier bestätigen können.';
  @override
  String get deviceName => 'Gerätename (optional)';
  @override
  String get pushEnroll => 'Dieses Gerät registrieren';
  @override
  String get thisDevice => 'Dieses Gerät';
  @override
  String get pushRequests => 'Anmeldeanfragen';
  @override
  String get pushNoRequests => 'Es warten keine Anmeldeanfragen.';
  @override
  String pushSignInTo(String client) => 'Anmeldung bei $client';
  @override
  String pushExpires(String time) => 'Läuft ab $time';
  @override
  String get pushPickNumber => 'Wählen Sie die Zahl, die auf dem anderen Bildschirm angezeigt wird';
  @override
  String get refresh => 'Aktualisieren';
  @override
  String get approve => 'Bestätigen';
  @override
  String get deny => 'Ablehnen';
  @override
  String get checkNow => 'Jetzt prüfen';
  @override
  String get sendRequest => 'Anfrage senden';
  @override
  String sendRequestIn(int seconds) => 'Anfrage senden ($seconds s)';
  @override
  String get continueInBrowser => 'Im Browser fortfahren';
  @override
  String get openBrowser => 'Browser öffnen';
  @override
  String accountNeedsAttention(String action) => 'Ihr Konto benötigt Aufmerksamkeit ($action). Schließen Sie dies im Web ab; danach kehren Sie hierher zurück.';
  @override
  String get completeOnWeb => 'Diese Anmeldung muss im Web abgeschlossen werden.';
  @override
  String attemptsLeft(int remaining) => remaining == 1 ? 'Noch 1 Versuch' : 'Noch $remaining Versuche';

  @override
  List<String> passwordPolicyHints(Map<String, Object?> policy) => [
    if (_int(policy['length']) case final n?) 'Mindestens $n Zeichen',
    if (_int(policy['maxLength']) case final n?) 'Höchstens $n Zeichen',
    if (_int(policy['digits']) case final n?) 'Mindestens $n ${n == 1 ? 'Ziffer' : 'Ziffern'}',
    if (_int(policy['upperCase']) case final n?) 'Mindestens $n ${n == 1 ? 'Großbuchstabe' : 'Großbuchstaben'}',
    if (_int(policy['lowerCase']) case final n?) 'Mindestens $n ${n == 1 ? 'Kleinbuchstabe' : 'Kleinbuchstaben'}',
    if (_int(policy['specialChars']) case final n?) 'Mindestens $n ${n == 1 ? 'Sonderzeichen' : 'Sonderzeichen'}',
    if (policy['notUsername'] != null) 'Nicht Ihr Benutzername',
    if (policy['notEmail'] != null) 'Nicht Ihre E-Mail-Adresse',
    if (policy['notContainsUsername'] != null) 'Darf Ihren Benutzernamen nicht enthalten',
    if (_int(policy['passwordHistory']) case final n?) 'Keines Ihrer letzten $n Passwörter',
    if (policy['regexPattern'] case final String pattern) 'Muss $pattern entsprechen',
  ];
}

int? _int(Object? value) => switch (value) {
  final int v => v,
  final double v when v == v.roundToDouble() => v.toInt(),
  final String v => int.tryParse(v),
  _ => null,
};
