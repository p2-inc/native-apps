/**
 * The default screens' strings, English. The native UI layers ship English and German string
 * catalogues; here an app passes its own (all or some) through `NativeLoginScreen`'s `strings`.
 */
export const defaultStrings = {
  contactingServer: 'Contacting the server…',
  continue: 'Continue',
  signIn: 'Sign in',
  verify: 'Verify',
  cancel: 'Cancel',
  tryAnotherWay: 'Try another way',
  username: 'Username',
  usernameOrEmail: 'Username or email',
  password: 'Password',
  passwordFor: (username: string) => `Password for ${username}`,
  verificationCode: 'Verification code',
  totpPrompt: (digits: number) =>
    `Enter the ${digits}-digit code from your authenticator app.`,
  totpPickAuthenticator: 'Authenticator',
  attemptsRemaining: (n: number) =>
    n === 1 ? '1 attempt remaining' : `${n} attempts remaining`,
  browserTitle: 'Continue in the browser',
  browserMessage:
    'This sign-in needs a step this app cannot show. Continue in the browser to finish it.',
  openBrowser: 'Open browser',
  unsupportedTitle: 'Update required',
  unsupportedMessage:
    'This sign-in step is not supported by this version of the app. Try another way, or update the app.',
  /** Labels for the "Try another way" list, by wire type. */
  challengeName: (wireType: string, label?: string): string =>
    label ??
    (
      {
        username: 'Username',
        password: 'Password',
        totp: 'Authenticator app',
        otp: 'One-time code',
        passkey: 'Passkey',
        recovery_code: 'Recovery code',
        push: 'Approve on another device',
      } as Record<string, string>
    )[wireType] ??
    wireType,
};

export type NativeLoginStrings = typeof defaultStrings;
