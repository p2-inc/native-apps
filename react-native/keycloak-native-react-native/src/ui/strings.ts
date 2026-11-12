/**
 * The default screens' strings, in English and German like the native UI layers' catalogues
 * (`Localizable.xcstrings`, `res/values*\/strings.xml`). `NativeLoginScreen` and `PushApprovalsScreen`
 * pick the catalogue for the device locale; an app replaces some or all strings through their
 * `strings` prop, or passes a catalogue of its own for another language.
 */
export interface NativeLoginStrings {
  contactingServer: string;
  cancel: string;
  signingInAs(name: string): string;
  confirmItsYou(name: string): string;
  tryAnotherWay: string;
  signIn: string;
  username: string;
  usernameOrEmail: string;
  continue: string;
  useSavedPassword: string;
  enterPassword: string;
  password: string;
  authenticatorCode: string;
  enterTotp(digits: number): string;
  authenticator: string;
  defaultAuthenticator: string;
  code: string;
  verify: string;
  textMessageCode: string;
  emailCode: string;
  yourPhone: string;
  yourEmail: string;
  weSentCode(digits: number, destination: string): string;
  weCanSendCode(digits: number, destination: string): string;
  weNeedToSendCode(digits: number, destination: string): string;
  resendCode: string;
  resendCodeIn(seconds: number): string;
  sendMeCode: string;
  sendMeCodeIn(seconds: number): string;
  sendCode: string;
  sendCodeIn(seconds: number): string;
  passkeyTitle: string;
  passkeyDiscoverable: string;
  passkeyAllowList: string;
  continueWithPasskey: string;
  createAPasskey: string;
  createPasskey: string;
  passkeyName: string;
  passkeyOffer(user: string): string;
  passkeyRequired(service: string, user: string): string;
  thisService: string;
  yourAccount: string;
  notNow: string;
  recoveryCode: string;
  recoveryCodeLeft(remaining: number): string;
  recoveryCodeEnter: string;
  recoveryCodeLow: string;
  chooseNewPassword: string;
  passwordMustUpdate: string;
  newPassword: string;
  confirmNewPassword: string;
  passwordsDoNotMatch: string;
  updatePassword: string;
  verifyEmail: string;
  terms: string;
  termsVersion(version: string): string;
  readFullTerms: string;
  accept: string;
  decline: string;
  updateRequired: string;
  unsupported(wireType: string): string;
  usePasskey: string;
  usePassword: string;
  useAuthenticator: string;
  textMeCode: string;
  emailMeCode: string;
  useRecoveryCode: string;
  approveOnPhone: string;
  pushSent(device: string): string;
  pushCanSend(device: string): string;
  pushChooseNumber: string;
  pushWaiting: string;
  pushEnrollTitle: string;
  pushEnrollSubtitle(client: string): string;
  deviceName: string;
  pushEnroll: string;
  thisDevice: string;
  pushRequests: string;
  pushNoRequests: string;
  pushSignInTo(client: string): string;
  pushExpires(time: string): string;
  pushPickNumber: string;
  pushEnterPin: string;
  refresh: string;
  approve: string;
  deny: string;
  checkNow: string;
  sendRequest: string;
  sendRequestIn(seconds: number): string;
  continueInBrowser: string;
  openBrowser: string;
  accountNeedsAttention(action: string): string;
  completeOnWeb: string;
  attemptsLeft(remaining: number): string;
  usePin: string;
  pinTitle: string;
  pinSubtitle(length: number): string;
  pinIncorrect: string;
  pinEnter: string;
  pinLockedTitle: string;
  pinTooMany: string;
  pinLocked: string;
  pinChooseTitle: string;
  pinChooseSubtitle(length: number): string;
  pinConfirmTitle: string;
  pinConfirmSubtitle(length: number): string;
  pinMismatch: string;
  pinWeak: string;
  pinInvalidFormat(length: number): string;
  pinDigitsEntered(filled: number, length: number): string;
  delete: string;
}

export const englishStrings: NativeLoginStrings = {
  contactingServer: 'Contacting the server…',
  cancel: 'Cancel',
  signingInAs: (name) => `Signing in as ${name}`,
  confirmItsYou: (name) => `Confirm it's you, ${name}`,
  tryAnotherWay: 'Try another way',
  signIn: 'Sign in',
  username: 'Username',
  usernameOrEmail: 'Username or email',
  continue: 'Continue',
  useSavedPassword: 'Use a saved password',
  enterPassword: 'Enter your password',
  password: 'Password',
  authenticatorCode: 'Authenticator code',
  enterTotp: (digits) =>
    `Enter the ${digits}-digit code from your authenticator app.`,
  authenticator: 'Authenticator',
  defaultAuthenticator: 'Default',
  code: 'Code',
  verify: 'Verify',
  textMessageCode: 'Text message code',
  emailCode: 'Email code',
  yourPhone: 'your phone',
  yourEmail: 'your email address',
  weSentCode: (digits, destination) =>
    `We sent a ${digits}-digit code to ${destination}.`,
  weCanSendCode: (digits, destination) =>
    `We can send a ${digits}-digit code to ${destination}.`,
  weNeedToSendCode: (digits, destination) =>
    `We need to send a ${digits}-digit code to ${destination}.`,
  resendCode: 'Resend code',
  resendCodeIn: (seconds) => `Resend code in ${seconds} s`,
  sendMeCode: 'Send me a code',
  sendMeCodeIn: (seconds) => `Send me a code (${seconds} s)`,
  sendCode: 'Send a code',
  sendCodeIn: (seconds) => `Send a code (${seconds} s)`,
  passkeyTitle: 'Sign in with a passkey',
  passkeyDiscoverable: 'Use a passkey saved on this device.',
  passkeyAllowList: 'Use the passkey registered for this account.',
  continueWithPasskey: 'Continue with passkey',
  createAPasskey: 'Create a passkey',
  createPasskey: 'Create passkey',
  passkeyName: 'Passkey name (optional)',
  passkeyOffer: (user) =>
    `Sign in faster next time: create a passkey for ${user} on this device.`,
  passkeyRequired: (service, user) =>
    `${service} requires a passkey for ${user} before you can continue.`,
  thisService: 'This service',
  yourAccount: 'your account',
  notNow: 'Not now',
  recoveryCode: 'Recovery code',
  recoveryCodeLeft: (remaining) =>
    `Enter one of your unused recovery codes (${remaining} left).`,
  recoveryCodeEnter: 'Enter one of your unused recovery codes.',
  recoveryCodeLow:
    'You are running low on recovery codes; generate new ones after signing in.',
  chooseNewPassword: 'Choose a new password',
  passwordMustUpdate: 'Your password must be updated before you can continue.',
  newPassword: 'New password',
  confirmNewPassword: 'Confirm new password',
  passwordsDoNotMatch: 'Passwords do not match',
  updatePassword: 'Update password',
  verifyEmail: 'Verify your email',
  terms: 'Terms and conditions',
  termsVersion: (version) => `Version ${version}`,
  readFullTerms: 'Read the full terms',
  accept: 'Accept',
  decline: 'Decline',
  updateRequired: 'Update required',
  unsupported: (wireType) =>
    `This version of the app cannot handle the '${wireType}' sign-in method. Update the app or sign in on the web.`,
  usePasskey: 'Use a passkey',
  usePassword: 'Use your password',
  useAuthenticator: 'Use an authenticator app',
  textMeCode: 'Text me a code',
  emailMeCode: 'Email me a code',
  useRecoveryCode: 'Use a recovery code',
  approveOnPhone: 'Approve on your phone',
  pushSent: (device) =>
    `We sent a sign-in request to ${device}. Approve it there to continue.`,
  pushCanSend: (device) => `We can send a sign-in request to ${device}.`,
  pushChooseNumber: 'Choose this number on your phone',
  pushWaiting: 'Waiting for your approval…',
  pushEnrollTitle: 'Set up sign-in approvals',
  pushEnrollSubtitle: (client) =>
    `${client} asks you to enroll this device so you can approve sign-ins from here.`,
  deviceName: 'Device name (optional)',
  pushEnroll: 'Enroll this device',
  thisDevice: 'This device',
  pushRequests: 'Sign-in requests',
  pushNoRequests: 'No sign-in requests are waiting.',
  pushSignInTo: (client) => `Sign-in to ${client}`,
  pushExpires: (time) => `Expires ${time}`,
  pushPickNumber: 'Pick the number shown on the other screen',
  pushEnterPin: 'Enter the PIN shown on the other screen',
  refresh: 'Refresh',
  approve: 'Approve',
  deny: 'Deny',
  checkNow: 'Check now',
  sendRequest: 'Send request',
  sendRequestIn: (seconds) => `Send request (${seconds} s)`,
  continueInBrowser: 'Continue in your browser',
  openBrowser: 'Open browser',
  accountNeedsAttention: (action) =>
    `Your account needs attention (${action}). Finish it on the web, then you will be returned here.`,
  completeOnWeb: 'This sign-in has to be completed on the web.',
  attemptsLeft: (remaining) =>
    remaining === 1 ? '1 attempt left' : `${remaining} attempts left`,
  usePin: 'Use your PIN',
  pinTitle: 'Enter your PIN',
  pinSubtitle: (length) => `Enter your ${length}-digit PIN.`,
  pinIncorrect: 'Incorrect PIN',
  pinEnter: 'Enter your PIN.',
  pinLockedTitle: 'PIN locked',
  pinTooMany: 'Too many incorrect PINs.',
  pinLocked:
    'Your PIN is locked. Reset it on the web or ask your administrator, then sign in again.',
  pinChooseTitle: 'Choose a PIN',
  pinChooseSubtitle: (length) =>
    `Choose a ${length}-digit PIN. Avoid easy sequences like 1234 or 1111.`,
  pinConfirmTitle: 'Confirm your PIN',
  pinConfirmSubtitle: (length) => `Enter the same ${length} digits again.`,
  pinMismatch: 'The PINs do not match. Try again.',
  pinWeak: 'This PIN is too easy to guess. Choose another one.',
  pinInvalidFormat: (length) => `The PIN must be exactly ${length} digits.`,
  pinDigitsEntered: (filled, length) => `${filled} of ${length} digits entered`,
  delete: 'Delete',
};

export const germanStrings: NativeLoginStrings = {
  contactingServer: 'Verbindung zum Server…',
  cancel: 'Abbrechen',
  signingInAs: (name) => `Anmeldung als ${name}`,
  confirmItsYou: (name) => `Bestätigen Sie, dass Sie es sind, ${name}`,
  tryAnotherWay: 'Anderen Weg versuchen',
  signIn: 'Anmelden',
  username: 'Benutzername',
  usernameOrEmail: 'Benutzername oder E-Mail',
  continue: 'Weiter',
  useSavedPassword: 'Gespeichertes Passwort verwenden',
  enterPassword: 'Passwort eingeben',
  password: 'Passwort',
  authenticatorCode: 'Authenticator-Code',
  enterTotp: (digits) =>
    `Geben Sie den ${digits}-stelligen Code aus Ihrer Authenticator-App ein.`,
  authenticator: 'Authenticator',
  defaultAuthenticator: 'Standard',
  code: 'Code',
  verify: 'Prüfen',
  textMessageCode: 'SMS-Code',
  emailCode: 'E-Mail-Code',
  yourPhone: 'Ihr Telefon',
  yourEmail: 'Ihre E-Mail-Adresse',
  weSentCode: (digits, destination) =>
    `Wir haben einen ${digits}-stelligen Code an ${destination} gesendet.`,
  weCanSendCode: (digits, destination) =>
    `Wir können einen ${digits}-stelligen Code an ${destination} senden.`,
  weNeedToSendCode: (digits, destination) =>
    `Wir müssen einen ${digits}-stelligen Code an ${destination} senden.`,
  resendCode: 'Code erneut senden',
  resendCodeIn: (seconds) => `Erneut senden in ${seconds} s`,
  sendMeCode: 'Code senden',
  sendMeCodeIn: (seconds) => `Code senden (${seconds} s)`,
  sendCode: 'Code senden',
  sendCodeIn: (seconds) => `Code senden (${seconds} s)`,
  passkeyTitle: 'Mit Passkey anmelden',
  passkeyDiscoverable:
    'Verwenden Sie einen auf diesem Gerät gespeicherten Passkey.',
  passkeyAllowList: 'Verwenden Sie den für dieses Konto registrierten Passkey.',
  continueWithPasskey: 'Mit Passkey fortfahren',
  createAPasskey: 'Passkey erstellen',
  createPasskey: 'Passkey erstellen',
  passkeyName: 'Name des Passkeys (optional)',
  passkeyOffer: (user) =>
    `Beim nächsten Mal schneller anmelden: Erstellen Sie auf diesem Gerät einen Passkey für ${user}.`,
  passkeyRequired: (service, user) =>
    `${service} benötigt einen Passkey für ${user}, bevor Sie fortfahren können.`,
  thisService: 'Dieser Dienst',
  yourAccount: 'Ihr Konto',
  notNow: 'Nicht jetzt',
  recoveryCode: 'Wiederherstellungscode',
  recoveryCodeLeft: (remaining) =>
    `Geben Sie einen unbenutzten Wiederherstellungscode ein (noch ${remaining}).`,
  recoveryCodeEnter: 'Geben Sie einen unbenutzten Wiederherstellungscode ein.',
  recoveryCodeLow:
    'Ihre Wiederherstellungscodes gehen zur Neige; erzeugen Sie nach der Anmeldung neue.',
  chooseNewPassword: 'Neues Passwort wählen',
  passwordMustUpdate:
    'Ihr Passwort muss aktualisiert werden, bevor Sie fortfahren können.',
  newPassword: 'Neues Passwort',
  confirmNewPassword: 'Neues Passwort bestätigen',
  passwordsDoNotMatch: 'Die Passwörter stimmen nicht überein',
  updatePassword: 'Passwort aktualisieren',
  verifyEmail: 'E-Mail-Adresse bestätigen',
  terms: 'Nutzungsbedingungen',
  termsVersion: (version) => `Version ${version}`,
  readFullTerms: 'Vollständige Bedingungen lesen',
  accept: 'Akzeptieren',
  decline: 'Ablehnen',
  updateRequired: 'Aktualisierung erforderlich',
  unsupported: (wireType) =>
    `Diese App-Version unterstützt die Anmeldemethode „${wireType}“ nicht. Aktualisieren Sie die App oder melden Sie sich im Web an.`,
  usePasskey: 'Passkey verwenden',
  usePassword: 'Passwort verwenden',
  useAuthenticator: 'Authenticator-App verwenden',
  textMeCode: 'Code per SMS senden',
  emailMeCode: 'Code per E-Mail senden',
  useRecoveryCode: 'Wiederherstellungscode verwenden',
  approveOnPhone: 'Auf dem Telefon bestätigen',
  pushSent: (device) =>
    `Wir haben eine Anmeldeanfrage an ${device} gesendet. Bestätigen Sie sie dort, um fortzufahren.`,
  pushCanSend: (device) =>
    `Wir können eine Anmeldeanfrage an ${device} senden.`,
  pushChooseNumber: 'Wählen Sie diese Zahl auf Ihrem Telefon',
  pushWaiting: 'Warten auf Ihre Bestätigung…',
  pushEnrollTitle: 'Anmeldebestätigungen einrichten',
  pushEnrollSubtitle: (client) =>
    `${client} bittet Sie, dieses Gerät zu registrieren, damit Sie Anmeldungen von hier bestätigen können.`,
  deviceName: 'Gerätename (optional)',
  pushEnroll: 'Dieses Gerät registrieren',
  thisDevice: 'Dieses Gerät',
  pushRequests: 'Anmeldeanfragen',
  pushNoRequests: 'Es warten keine Anmeldeanfragen.',
  pushSignInTo: (client) => `Anmeldung bei ${client}`,
  pushExpires: (time) => `Läuft ab ${time}`,
  pushPickNumber:
    'Wählen Sie die Zahl, die auf dem anderen Bildschirm angezeigt wird',
  pushEnterPin:
    'Geben Sie die PIN ein, die auf dem anderen Bildschirm angezeigt wird',
  refresh: 'Aktualisieren',
  approve: 'Bestätigen',
  deny: 'Ablehnen',
  checkNow: 'Jetzt prüfen',
  sendRequest: 'Anfrage senden',
  sendRequestIn: (seconds) => `Anfrage senden (${seconds} s)`,
  continueInBrowser: 'Im Browser fortfahren',
  openBrowser: 'Browser öffnen',
  accountNeedsAttention: (action) =>
    `Ihr Konto benötigt Aufmerksamkeit (${action}). Schließen Sie dies im Web ab; danach kehren Sie hierher zurück.`,
  completeOnWeb: 'Diese Anmeldung muss im Web abgeschlossen werden.',
  attemptsLeft: (remaining) =>
    remaining === 1 ? 'Noch 1 Versuch' : `Noch ${remaining} Versuche`,
  usePin: 'PIN verwenden',
  pinTitle: 'PIN eingeben',
  pinSubtitle: (length) => `Geben Sie Ihre ${length}-stellige PIN ein.`,
  pinIncorrect: 'Falsche PIN',
  pinEnter: 'Geben Sie Ihre PIN ein.',
  pinLockedTitle: 'PIN gesperrt',
  pinTooMany: 'Zu viele falsche PIN-Eingaben.',
  pinLocked:
    'Ihre PIN ist gesperrt. Setzen Sie sie im Web zurück oder wenden Sie sich an Ihren Administrator und melden Sie sich dann erneut an.',
  pinChooseTitle: 'PIN festlegen',
  pinChooseSubtitle: (length) =>
    `Wählen Sie eine ${length}-stellige PIN. Vermeiden Sie einfache Folgen wie 1234 oder 1111.`,
  pinConfirmTitle: 'PIN bestätigen',
  pinConfirmSubtitle: (length) =>
    `Geben Sie dieselben ${length} Ziffern erneut ein.`,
  pinMismatch: 'Die PINs stimmen nicht überein. Versuchen Sie es erneut.',
  pinWeak: 'Diese PIN ist zu leicht zu erraten. Wählen Sie eine andere.',
  pinInvalidFormat: (length) => `Die PIN muss genau ${length} Ziffern haben.`,
  pinDigitsEntered: (filled, length) =>
    `${filled} von ${length} Ziffern eingegeben`,
  delete: 'Löschen',
};

/** The catalogue for a BCP 47 locale (`de-AT` → German); English for every other language. */
export function stringsForLocale(
  locale: string | undefined
): NativeLoginStrings {
  return locale?.toLowerCase().split(/[-_]/)[0] === 'de'
    ? germanStrings
    : englishStrings;
}

/** The device locale as `Intl` reports it (Hermes has `Intl`), or `undefined`. */
export function deviceLocale(): string | undefined {
  try {
    return Intl.DateTimeFormat().resolvedOptions().locale;
  } catch {
    return undefined;
  }
}

/** The English catalogue, under the name earlier versions exported. */
export const defaultStrings: NativeLoginStrings = englishStrings;
