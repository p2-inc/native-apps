/// Texts of the default widgets, English by default (the native UI layers' strings). Pass a
/// [NativeLoginStrings] with your own texts to `NativeLoginView` to translate or reword them.
class NativeLoginStrings {
  const NativeLoginStrings();

  String get contactingServer => 'Contacting the server…';
  String get cancel => 'Cancel';
  String signingInAs(String name) => 'Signing in as $name';
  String confirmItsYou(String name) => "Confirm it's you, $name";
  String get tryAnotherWay => 'Try another way';
  String get signIn => 'Sign in';
  String get username => 'Username';
  String get usernameOrEmail => 'Username or email';
  String get continueLabel => 'Continue';
  String get enterPassword => 'Enter your password';
  String get password => 'Password';
  String get authenticatorCode => 'Authenticator code';
  String enterTotp(int digits) => 'Enter the $digits-digit code from your authenticator app.';
  String get authenticator => 'Authenticator';
  String get defaultAuthenticator => 'Default';
  String get code => 'Code';
  String get verify => 'Verify';
  String get updateRequired => 'Update required';
  String unsupported(String type) => "This version of the app cannot handle the '$type' sign-in method. Update the app or sign in on the web.";
  String attemptsLeft(int remaining) => remaining == 1 ? '1 attempt left' : '$remaining attempts left';
  String get continueInBrowser => 'Continue in your browser';
  String get openBrowser => 'Open browser';
  String accountNeedsAttention(String action) => 'Your account needs attention ($action). Finish it on the web, then you will be returned here.';
  String get completeOnWeb => 'This sign-in has to be completed on the web.';

  /// The label of an alternative in the "Try another way" list.
  String chooserTitle(String type, {String? otpChannel}) => switch (type) {
    'passkey' => 'Use a passkey',
    'password' => 'Use your password',
    'totp' => 'Use an authenticator app',
    'otp' => otpChannel == 'sms' ? 'Text me a code' : 'Email me a code',
    'recovery_code' => 'Use a recovery code',
    'push' => 'Approve on your phone',
    _ => type,
  };
}
