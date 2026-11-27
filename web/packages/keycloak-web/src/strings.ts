/**
 * The default UI strings of the React components and the web components, in English. Replace some or
 * all through the components' `strings` prop / property, or pass a whole catalogue for another
 * language. Server-sent labels and error messages (already localized through `ui_locales`) win over
 * these where the server sends them.
 */
export interface LoginStrings {
  signIn: string;
  contactingServer: string;
  cancel: string;
  continue: string;
  verify: string;
  tryAnotherWay: string;
  signingInAs(name: string): string;
  username: string;
  usernameOrEmail: string;
  password: string;
  enterPassword: string;
  authenticatorCode: string;
  enterTotp(digits: number): string;
  code: string;
  emailCode: string;
  textMessageCode: string;
  weSentCode(digits: number, destination: string): string;
  weCanSendCode(digits: number, destination: string): string;
  sendCode: string;
  resendCode: string;
  resendCodeIn(seconds: number): string;
  passkeyTitle: string;
  continueWithPasskey: string;
  passkeyAutofillHint: string;
  createAPasskey: string;
  createPasskey: string;
  passkeyName: string;
  notNow: string;
  recoveryCode: string;
  recoveryCodeLeft(remaining: number): string;
  chooseNewPassword: string;
  newPassword: string;
  confirmNewPassword: string;
  passwordsDoNotMatch: string;
  logoutOtherSessions: string;
  updatePassword: string;
  verifyEmail: string;
  weSentEmailCode(digits: number, destination: string): string;
  terms: string;
  readFullTerms: string;
  accept: string;
  decline: string;
  approveOnPhone: string;
  pushSent(device: string): string;
  pushCanSend(device: string): string;
  pushChooseNumber(number: string): string;
  pushWaiting: string;
  sendRequest: string;
  pinTitle: string;
  pinSubtitle(length: number): string;
  pinChooseTitle: string;
  pinChooseSubtitle(length: number): string;
  pinConfirm: string;
  continueInBrowser: string;
  completeInPopup: string;
  openWindow: string;
  attemptsLeft(remaining: number): string;
  unsupported(wireType: string): string;
  /** "Try another way" entries, by challenge type. */
  alternative(type: string): string;
  errors: Partial<Record<string, string>>;
}

const alternatives: Record<string, string> = {
  passkey: 'Use a passkey',
  password: 'Use your password',
  totp: 'Use your authenticator app',
  otp: 'Get a code',
  push: 'Approve on your phone',
  recovery_code: 'Use a recovery code',
  pin: 'Use your PIN',
  username: 'Enter your username',
};

export const defaultLoginStrings: LoginStrings = {
  signIn: 'Sign in',
  contactingServer: 'Contacting the server…',
  cancel: 'Cancel',
  continue: 'Continue',
  verify: 'Verify',
  tryAnotherWay: 'Try another way',
  signingInAs: (name) => `Signing in as ${name}`,
  username: 'Username',
  usernameOrEmail: 'Username or email',
  password: 'Password',
  enterPassword: 'Enter your password',
  authenticatorCode: 'Authenticator code',
  enterTotp: (digits) => `Enter the ${digits}-digit code from your authenticator app.`,
  code: 'Code',
  emailCode: 'Email code',
  textMessageCode: 'Text message code',
  weSentCode: (digits, destination) => `We sent a ${digits}-digit code to ${destination}.`,
  weCanSendCode: (digits, destination) => `We can send a ${digits}-digit code to ${destination}.`,
  sendCode: 'Send code',
  resendCode: 'Resend code',
  resendCodeIn: (seconds) => `Resend code in ${seconds} s`,
  passkeyTitle: 'Sign in with a passkey',
  continueWithPasskey: 'Continue with a passkey',
  passkeyAutofillHint: 'Your saved passkeys also appear when you select the username field.',
  createAPasskey: 'Create a passkey',
  createPasskey: 'Create passkey',
  passkeyName: 'Passkey name',
  notNow: 'Not now',
  recoveryCode: 'Recovery code',
  recoveryCodeLeft: (remaining) => `${remaining} recovery code${remaining === 1 ? '' : 's'} left`,
  chooseNewPassword: 'Choose a new password',
  newPassword: 'New password',
  confirmNewPassword: 'Confirm new password',
  passwordsDoNotMatch: 'The passwords do not match.',
  logoutOtherSessions: 'Sign out of other devices',
  updatePassword: 'Update password',
  verifyEmail: 'Verify your email',
  weSentEmailCode: (digits, destination) => `Enter the ${digits}-digit code we sent to ${destination}.`,
  terms: 'Terms and conditions',
  readFullTerms: 'Read the full terms',
  accept: 'Accept',
  decline: 'Decline',
  approveOnPhone: 'Approve on your phone',
  pushSent: (device) => `We sent a sign-in request to ${device}.`,
  pushCanSend: (device) => `We can send a sign-in request to ${device}.`,
  pushChooseNumber: (number) => `Choose ${number} on your phone.`,
  pushWaiting: 'Waiting for your approval…',
  sendRequest: 'Send request',
  pinTitle: 'Enter your PIN',
  pinSubtitle: (length) => `Enter your ${length}-digit PIN.`,
  pinChooseTitle: 'Choose a PIN',
  pinChooseSubtitle: (length) => `Choose a ${length}-digit PIN.`,
  pinConfirm: 'Confirm PIN',
  continueInBrowser: 'Continue in a new window',
  completeInPopup: 'This step continues on the sign-in page. A window opens; come back here when you are done.',
  openWindow: 'Open window',
  attemptsLeft: (remaining) => `${remaining} attempt${remaining === 1 ? '' : 's'} left`,
  unsupported: (wireType) => `This sign-in step (${wireType}) is not supported here.`,
  alternative: (type) => alternatives[type] ?? type,
  errors: {
    invalid_credential: 'That did not work. Try again.',
    invalid_user: 'We do not know that user.',
    missing_credential: 'Fill in this field.',
    expired_code: 'The code expired. Send a new one.',
    resend_too_soon: 'Wait a moment before asking for another code.',
    password_mismatch: 'The passwords do not match.',
    invalid_password: 'That password does not meet the requirements.',
    denied: 'The request was denied on your phone.',
    expired: 'The request expired. Send a new one.',
    credential_locked: 'Too many attempts. Your PIN is locked.',
    pin_mismatch: 'The PINs do not match.',
    invalid_format: 'Enter digits only.',
    weak_pin: 'That PIN is too easy to guess.',
    network_error: 'We could not reach the server. Check your connection.',
    passkey_unavailable: 'Passkeys are not available in this browser.',
    rp_id_mismatch: 'Passkeys are not set up for this site.',
    web_fallback_failed: 'The sign-in window was blocked. Allow pop-ups for this site and try again.',
  },
};

/** A message for a challenge error or an SDK error code, falling back to the server's text. */
export function errorMessage(strings: LoginStrings, code: string | undefined, serverMessage?: string): string | undefined {
  if (code === undefined) return undefined;
  return serverMessage ?? strings.errors[code] ?? code;
}
