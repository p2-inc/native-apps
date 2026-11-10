import { useEffect, useRef, useState, type ReactNode } from 'react';
import {
  ActivityIndicator,
  Linking,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
  type TextInputProps,
} from 'react-native';
import {
  millisUntil,
  type Challenge,
  type ChallengeAnswer,
  type ChallengeOf,
  type ChallengeType,
  type FlowContext,
  type RedirectToWebRequest,
} from '../model';
import type { NativeLoginStrings } from './strings';

/**
 * What a challenge screen gets (spec/05 §4): the challenge, the set it belongs to, the flow context
 * and the actions it may trigger, the twin of `ChallengePresentationContext` in the native UI layers.
 * Replacement screens are plain components built from these props.
 */
export interface ChallengePresentationProps<
  T extends ChallengeType = ChallengeType,
> {
  challenge: ChallengeOf<T>;
  challenges: Challenge[];
  /** Entries of the set other than this one, in server order. */
  alternatives: Challenge[];
  flowContext: FlowContext;
  isSubmitting: boolean;
  /** The step is a step-up / re-authentication (`context.step_up`). */
  isStepUp: boolean;
  /** The default `username` and `password` screens show "Use a saved password". */
  offersSavedPasswords: boolean;
  strings: NativeLoginStrings;
  submit(answer: ChallengeAnswer): void;
  /** Runs the platform passkey prompt for a `passkey` challenge and submits the assertion. */
  usePasskey(preferImmediatelyAvailableCredentials?: boolean): void;
  /** Runs the platform registration for a `passkey_registration` challenge and submits it. */
  registerPasskey(label?: string): void;
  /** Enrolls this device on a `push_enrollment` challenge with the screen's `pushRegistration`. */
  enrollPush(deviceLabel: string): void;
  /**
   * Shows the system sheet of saved passwords; on a `username` challenge the picked password also
   * answers the `password` challenge that follows.
   */
  useSavedPassword(): void;
  /** Show another entry of the current set instead. */
  switchTo(other: Challenge): void;
  cancel(): void;
}

/** Replacement screens by challenge type. */
export type ChallengePresenters = {
  [K in ChallengeType]?: React.ComponentType<ChallengePresentationProps<K>>;
};

/** Input of a chooser (the "Try another way" list). */
export interface ChallengeChooserProps {
  current: Challenge;
  alternatives: Challenge[];
  strings: NativeLoginStrings;
  select(challenge: Challenge): void;
}

/** Routes a challenge to its default screen (spec/05 §4 "Provided default screens"). */
export function DefaultChallengeScreen(props: ChallengePresentationProps) {
  const p = props as any;
  switch (props.challenge.type) {
    case 'username':
      return <UsernameScreen {...p} />;
    case 'password':
      return <PasswordScreen {...p} />;
    case 'totp':
      return <TotpScreen {...p} />;
    case 'otp':
      return <OtpScreen {...p} />;
    case 'passkey':
      return <PasskeyScreen {...p} />;
    case 'passkey_registration':
      return <PasskeyRegistrationScreen {...p} />;
    case 'update_password':
      return <UpdatePasswordScreen {...p} />;
    case 'verify_email':
      return <VerifyEmailScreen {...p} />;
    case 'terms':
      return <TermsScreen {...p} />;
    case 'recovery_code':
      return <RecoveryCodeScreen {...p} />;
    case 'push':
      return <PushScreen {...p} />;
    case 'push_enrollment':
      return <PushEnrollmentScreen {...p} />;
    default:
      return <UnsupportedScreen {...props} />;
  }
}

// MARK: - Building blocks

/** Shared frame: title, context line, the descriptor's error and attempts left, content, cancel. */
export function ChallengeFrame({
  presentation,
  title,
  subtitle,
  children,
}: {
  presentation: ChallengePresentationProps;
  title: string;
  subtitle?: string;
  children?: ReactNode;
}) {
  const { flowContext, challenge, strings } = presentation;
  const name = flowContext.displayName ?? flowContext.username;
  return (
    <View style={styles.screen}>
      <Text style={styles.title} accessibilityRole="header">
        {title}
      </Text>
      {flowContext.username !== undefined && name !== undefined && (
        <Text style={styles.body}>
          {presentation.isStepUp
            ? strings.confirmItsYou(name)
            : strings.signingInAs(name)}
        </Text>
      )}
      {subtitle !== undefined && <Text style={styles.caption}>{subtitle}</Text>}
      {challenge.error !== undefined && (
        <Text style={styles.error} accessibilityRole="alert" testID="kc-error">
          {challenge.error.message ?? challenge.error.code}
        </Text>
      )}
      {challenge.error !== undefined &&
        challenge.retry?.remaining !== undefined && (
          // spec/03 §3.3: attempts left before brute-force protection locks the account.
          <Text style={styles.caption} testID="kc-retry">
            {strings.attemptsLeft(challenge.retry.remaining)}
          </Text>
        )}
      {children}
      <SecondaryButton
        title={strings.cancel}
        onPress={presentation.cancel}
        disabled={presentation.isSubmitting}
        testID="kc-cancel"
      />
    </View>
  );
}

export function PrimaryButton({
  title,
  onPress,
  disabled,
  busy,
  destructive,
  testID,
}: {
  title: string;
  onPress: () => void;
  disabled?: boolean;
  busy?: boolean;
  destructive?: boolean;
  testID?: string;
}) {
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ disabled: disabled === true, busy: busy === true }}
      disabled={disabled}
      onPress={onPress}
      style={({ pressed }) => [
        styles.button,
        destructive === true && styles.buttonDestructive,
        disabled === true && styles.buttonDisabled,
        pressed && styles.buttonPressed,
      ]}
      testID={testID}
    >
      {busy === true ? (
        <ActivityIndicator color="#ffffff" />
      ) : (
        <Text style={styles.buttonText}>{title}</Text>
      )}
    </Pressable>
  );
}

export function SecondaryButton({
  title,
  onPress,
  disabled,
  destructive,
  testID,
}: {
  title: string;
  onPress: () => void;
  disabled?: boolean;
  destructive?: boolean;
  testID?: string;
}) {
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ disabled: disabled === true }}
      disabled={disabled}
      onPress={onPress}
      style={[
        styles.secondaryButton,
        disabled === true && styles.buttonDisabled,
      ]}
      testID={testID}
    >
      <Text
        style={[
          styles.secondaryButtonText,
          destructive === true && styles.destructiveText,
        ]}
      >
        {title}
      </Text>
    </Pressable>
  );
}

function Field({
  label,
  testID,
  ...input
}: TextInputProps & { label: string; testID: string }) {
  return (
    <View style={styles.field}>
      <Text style={styles.label}>{label}</Text>
      <TextInput
        style={[styles.input, input.editable === false && styles.readOnly]}
        autoCapitalize="none"
        autoCorrect={false}
        accessibilityLabel={label}
        testID={testID}
        {...input}
      />
    </View>
  );
}

/**
 * The account the password belongs to, read-only with the username content type. Keycloak asks for
 * the username and the password on separate screens; password managers pair a password with the
 * username field on the same screen, so without it they cannot match or save the entry.
 */
function AutofillUsernameField({
  username,
  strings,
}: {
  username?: string;
  strings: NativeLoginStrings;
}) {
  if (username === undefined) return null;
  return (
    <Field
      label={strings.username}
      value={username}
      editable={false}
      autoComplete="username"
      textContentType="username"
      testID="kc-autofill-username"
    />
  );
}

function SavedPasswordButton({
  presentation,
}: {
  presentation: ChallengePresentationProps;
}) {
  if (!presentation.offersSavedPasswords) return null;
  return (
    <SecondaryButton
      title={presentation.strings.useSavedPassword}
      onPress={presentation.useSavedPassword}
      disabled={presentation.isSubmitting}
      testID="kc-use-saved-password"
    />
  );
}

/** The current time, ticking every second while `active`, for resend cooldowns. */
export function useNow(active = true): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return undefined;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [active]);
  return now;
}

/** Whole seconds until `instant` (epoch milliseconds), rounded up; zero when past or absent. */
function secondsUntil(instant: number | undefined, now: number): number {
  return Math.ceil(millisUntil(instant, now) / 1000);
}

const digitsOnly = (text: string, max: number) =>
  text.replace(/\D/g, '').slice(0, max);

// MARK: - Screens

export function UsernameScreen(
  presentation: ChallengePresentationProps<'username'>
) {
  const { challenge, isSubmitting, strings, submit } = presentation;
  const allowEmail = challenge.params.allowEmail;
  const [username, setUsername] = useState(challenge.params.hint ?? '');
  const valid = username.trim().length > 0;
  const send = () => {
    if (valid && !isSubmitting)
      submit({ kind: 'username', username: username.trim() });
  };
  return (
    <ChallengeFrame
      presentation={presentation as ChallengePresentationProps}
      title={strings.signIn}
      subtitle={allowEmail ? strings.usernameOrEmail : strings.username}
    >
      <Field
        label={strings.username}
        value={username}
        onChangeText={setUsername}
        autoComplete={allowEmail ? 'email' : 'username'}
        textContentType="username"
        keyboardType={allowEmail ? 'email-address' : 'default'}
        returnKeyType="next"
        onSubmitEditing={send}
        editable={!isSubmitting}
        testID="kc-username"
      />
      <PrimaryButton
        title={strings.continue}
        onPress={send}
        disabled={!valid || isSubmitting}
        busy={isSubmitting}
        testID="kc-username-submit"
      />
      <SavedPasswordButton
        presentation={presentation as ChallengePresentationProps}
      />
    </ChallengeFrame>
  );
}

export function PasswordScreen(
  presentation: ChallengePresentationProps<'password'>
) {
  const { flowContext, isSubmitting, strings, submit } = presentation;
  const [password, setPassword] = useState('');
  const valid = password.length > 0;
  const send = () => {
    if (valid && !isSubmitting) submit({ kind: 'password', password });
  };
  return (
    <ChallengeFrame
      presentation={presentation as ChallengePresentationProps}
      title={strings.enterPassword}
    >
      <AutofillUsernameField
        username={flowContext.username}
        strings={strings}
      />
      <Field
        label={strings.password}
        value={password}
        onChangeText={setPassword}
        secureTextEntry
        autoComplete="current-password"
        textContentType="password"
        returnKeyType="go"
        onSubmitEditing={send}
        editable={!isSubmitting}
        autoFocus
        testID="kc-password"
      />
      <PrimaryButton
        title={strings.signIn}
        onPress={send}
        disabled={!valid || isSubmitting}
        busy={isSubmitting}
        testID="kc-password-submit"
      />
      <SavedPasswordButton
        presentation={presentation as ChallengePresentationProps}
      />
    </ChallengeFrame>
  );
}

export function TotpScreen(presentation: ChallengePresentationProps<'totp'>) {
  const { challenge, isSubmitting, strings, submit } = presentation;
  const { digits, credentials } = challenge.params;
  const [code, setCode] = useState('');
  // `undefined`: the user's default authenticator (no `credential_id`).
  const [credentialId, setCredentialId] = useState<string | undefined>();
  const valid = code.length === digits;
  const send = () => {
    if (valid && !isSubmitting) submit({ kind: 'totp', code, credentialId });
  };
  const choices = [
    { id: undefined, label: strings.defaultAuthenticator },
    ...credentials.map((c) => ({
      id: c.id as string | undefined,
      label: c.label.length > 0 ? c.label : c.id,
    })),
  ];
  return (
    <ChallengeFrame
      presentation={presentation as ChallengePresentationProps}
      title={strings.authenticatorCode}
      subtitle={strings.enterTotp(digits)}
    >
      {credentials.length > 1 && (
        <View style={styles.picker} accessibilityLabel={strings.authenticator}>
          {choices.map((c) => (
            <Pressable
              key={c.id ?? ''}
              accessibilityRole="radio"
              accessibilityState={{ selected: c.id === credentialId }}
              onPress={() => setCredentialId(c.id)}
              style={[
                styles.chip,
                c.id === credentialId && styles.chipSelected,
              ]}
              testID={`kc-totp-credential-${c.id ?? 'default'}`}
            >
              <Text>{c.label}</Text>
            </Pressable>
          ))}
        </View>
      )}
      <Field
        label={strings.code}
        value={code}
        onChangeText={(t) => setCode(digitsOnly(t, digits))}
        keyboardType="number-pad"
        autoComplete="one-time-code"
        textContentType="oneTimeCode"
        maxLength={digits}
        onSubmitEditing={send}
        editable={!isSubmitting}
        autoFocus
        style={[styles.input, styles.code]}
        testID="kc-totp"
      />
      <PrimaryButton
        title={strings.verify}
        onPress={send}
        disabled={!valid || isSubmitting}
        busy={isSubmitting}
        testID="kc-totp-submit"
      />
    </ChallengeFrame>
  );
}

/**
 * `otp` (spec/03 §4.6): the masked destination, a resend button with the server's cooldown, and a
 * "Send me a code" button first when the server has not sent one yet (`sent: false`).
 */
export function OtpScreen(presentation: ChallengePresentationProps<'otp'>) {
  const { challenge, isSubmitting, strings, submit } = presentation;
  const { sent, digits, channel, destinationMasked, resendAllowedAt } =
    challenge.params;
  const now = useNow(resendAllowedAt !== undefined);
  const wait = secondsUntil(resendAllowedAt, now);
  const sms = channel === 'sms';
  const destination =
    destinationMasked ?? (sms ? strings.yourPhone : strings.yourEmail);
  const [code, setCode] = useState('');
  const send = () => {
    if (code.length > 0 && !isSubmitting) submit({ kind: 'otp', code });
  };
  return (
    <ChallengeFrame
      presentation={presentation as ChallengePresentationProps}
      title={sms ? strings.textMessageCode : strings.emailCode}
      subtitle={
        sent
          ? strings.weSentCode(digits, destination)
          : strings.weCanSendCode(digits, destination)
      }
    >
      {sent ? (
        <>
          <Field
            label={strings.code}
            value={code}
            onChangeText={(t) => setCode(digitsOnly(t, digits))}
            keyboardType="number-pad"
            autoComplete={sms ? 'sms-otp' : 'one-time-code'}
            textContentType="oneTimeCode"
            maxLength={digits}
            onSubmitEditing={send}
            editable={!isSubmitting}
            autoFocus
            style={[styles.input, styles.code]}
            testID="kc-otp"
          />
          <PrimaryButton
            title={strings.verify}
            onPress={send}
            disabled={code.length === 0 || isSubmitting}
            busy={isSubmitting}
            testID="kc-otp-submit"
          />
          <SecondaryButton
            title={wait > 0 ? strings.resendCodeIn(wait) : strings.resendCode}
            onPress={() => submit({ kind: 'otpResend' })}
            disabled={wait > 0 || isSubmitting}
            testID="kc-otp-resend"
          />
        </>
      ) : (
        <PrimaryButton
          title={wait > 0 ? strings.sendMeCodeIn(wait) : strings.sendMeCode}
          onPress={() => submit({ kind: 'otpResend' })}
          disabled={wait > 0 || isSubmitting}
          busy={isSubmitting}
          testID="kc-otp-send"
        />
      )}
    </ChallengeFrame>
  );
}

export function PasskeyScreen(
  presentation: ChallengePresentationProps<'passkey'>
) {
  const { challenge, isSubmitting, strings } = presentation;
  return (
    <ChallengeFrame
      presentation={presentation as ChallengePresentationProps}
      title={strings.passkeyTitle}
      subtitle={
        challenge.params?.discoverable === true
          ? strings.passkeyDiscoverable
          : strings.passkeyAllowList
      }
    >
      <PrimaryButton
        title={strings.continueWithPasskey}
        onPress={() => presentation.usePasskey()}
        disabled={isSubmitting || challenge.params === undefined}
        busy={isSubmitting}
        testID="kc-use-passkey"
      />
    </ChallengeFrame>
  );
}

export function PasskeyRegistrationScreen(
  presentation: ChallengePresentationProps<'passkey_registration'>
) {
  const { challenge, isSubmitting, strings, submit } = presentation;
  const params = challenge.params;
  const [label, setLabel] = useState('');
  const user = params?.user.name ?? strings.yourAccount;
  // spec/03 §4.11: a skippable registration is an offer ("Not now"), not a requirement.
  const subtitle = challenge.skippable
    ? strings.passkeyOffer(user)
    : strings.passkeyRequired(params?.rp.name ?? strings.thisService, user);
  return (
    <ChallengeFrame
      presentation={presentation as ChallengePresentationProps}
      title={strings.createAPasskey}
      subtitle={subtitle}
    >
      <Field
        label={strings.passkeyName}
        value={label}
        onChangeText={setLabel}
        editable={!isSubmitting}
        testID="kc-passkey-label"
      />
      <PrimaryButton
        title={strings.createPasskey}
        onPress={() =>
          presentation.registerPasskey(
            label.trim().length > 0 ? label.trim() : undefined
          )
        }
        disabled={isSubmitting || params === undefined}
        busy={isSubmitting}
        testID="kc-create-passkey"
      />
      {challenge.skippable && (
        <SecondaryButton
          title={strings.notNow}
          onPress={() => submit({ kind: 'skip' })}
          disabled={isSubmitting}
          testID="kc-skip"
        />
      )}
    </ChallengeFrame>
  );
}

/**
 * `push_enrollment` (spec/03 §4.15): enrolls this device with the DPoP key. Messages reach it through
 * the screen's `pushRegistration`; without one the device reads its approvals itself (`none`).
 */
export function PushEnrollmentScreen(
  presentation: ChallengePresentationProps<'push_enrollment'>
) {
  const { flowContext, isSubmitting, strings } = presentation;
  const [label, setLabel] = useState('');
  return (
    <ChallengeFrame
      presentation={presentation as ChallengePresentationProps}
      title={strings.pushEnrollTitle}
      subtitle={strings.pushEnrollSubtitle(
        flowContext.clientName ?? strings.thisService
      )}
    >
      <Field
        label={strings.deviceName}
        value={label}
        onChangeText={setLabel}
        editable={!isSubmitting}
        testID="kc-push-device-label"
      />
      <PrimaryButton
        title={strings.pushEnroll}
        onPress={() =>
          presentation.enrollPush(
            label.trim().length > 0 ? label.trim() : strings.thisDevice
          )
        }
        disabled={isSubmitting}
        busy={isSubmitting}
        testID="kc-push-enroll"
      />
    </ChallengeFrame>
  );
}

/** `recovery_code` (spec/03 §4.8): one single-use code, with the remaining count and a warning. */
export function RecoveryCodeScreen(
  presentation: ChallengePresentationProps<'recovery_code'>
) {
  const { challenge, isSubmitting, strings, submit } = presentation;
  const { remaining, shouldWarn } = challenge.params;
  const [code, setCode] = useState('');
  const send = () => {
    if (code.trim().length > 0 && !isSubmitting)
      submit({ kind: 'recoveryCode', code: code.trim() });
  };
  return (
    <ChallengeFrame
      presentation={presentation as ChallengePresentationProps}
      title={strings.recoveryCode}
      subtitle={
        remaining !== undefined
          ? strings.recoveryCodeLeft(remaining)
          : strings.recoveryCodeEnter
      }
    >
      {shouldWarn && (
        <Text style={styles.warning} testID="kc-recovery-low">
          {strings.recoveryCodeLow}
        </Text>
      )}
      <Field
        label={strings.recoveryCode}
        placeholder="XXXX-XXXX-XXXX"
        value={code}
        onChangeText={setCode}
        autoCapitalize="characters"
        onSubmitEditing={send}
        editable={!isSubmitting}
        autoFocus
        testID="kc-recovery-code"
      />
      <PrimaryButton
        title={strings.signIn}
        onPress={send}
        disabled={code.trim().length === 0 || isSubmitting}
        busy={isSubmitting}
        testID="kc-recovery-code-submit"
      />
    </ChallengeFrame>
  );
}

/** `update_password` (spec/03 §4.12): the new password twice, with the realm's policy as hints. */
export function UpdatePasswordScreen(
  presentation: ChallengePresentationProps<'update_password'>
) {
  const { challenge, flowContext, isSubmitting, strings, submit } =
    presentation;
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const canSubmit =
    password.length > 0 && confirm === password && !isSubmitting;
  const send = () => {
    if (canSubmit) submit({ kind: 'updatePassword', password, confirm });
  };
  return (
    <ChallengeFrame
      presentation={presentation as ChallengePresentationProps}
      title={strings.chooseNewPassword}
      subtitle={strings.passwordMustUpdate}
    >
      <AutofillUsernameField
        username={flowContext.username ?? challenge.params.username}
        strings={strings}
      />
      <Field
        label={strings.newPassword}
        value={password}
        onChangeText={setPassword}
        secureTextEntry
        autoComplete="new-password"
        textContentType="newPassword"
        editable={!isSubmitting}
        testID="kc-new-password"
      />
      <Field
        label={strings.confirmNewPassword}
        value={confirm}
        onChangeText={setConfirm}
        secureTextEntry
        autoComplete="new-password"
        textContentType="newPassword"
        onSubmitEditing={send}
        editable={!isSubmitting}
        testID="kc-new-password-confirm"
      />
      {challenge.params.hints.length > 0 && (
        <View>
          {challenge.params.hints.map((hint) => (
            <Text key={hint} style={styles.caption}>
              {`• ${hint}`}
            </Text>
          ))}
        </View>
      )}
      {confirm.length > 0 && confirm !== password && (
        <Text style={styles.error}>{strings.passwordsDoNotMatch}</Text>
      )}
      <PrimaryButton
        title={strings.updatePassword}
        onPress={send}
        disabled={!canSubmit}
        busy={isSubmitting}
        testID="kc-update-password"
      />
      {challenge.skippable && (
        <SecondaryButton
          title={strings.notNow}
          onPress={() => submit({ kind: 'skip' })}
          disabled={isSubmitting}
          testID="kc-skip"
        />
      )}
    </ChallengeFrame>
  );
}

/** `verify_email` (spec/03 §4.13): the code sent to the masked address, with resend and cooldown. */
export function VerifyEmailScreen(
  presentation: ChallengePresentationProps<'verify_email'>
) {
  const { challenge, isSubmitting, strings, submit } = presentation;
  const { sent, digits, emailMasked, resendAllowedAt } = challenge.params;
  const now = useNow(resendAllowedAt !== undefined);
  const wait = secondsUntil(resendAllowedAt, now);
  const destination = emailMasked ?? strings.yourEmail;
  const [code, setCode] = useState('');
  const send = () => {
    if (code.length > 0 && !isSubmitting) submit({ kind: 'verifyEmail', code });
  };
  const resendTitle = sent
    ? wait > 0
      ? strings.resendCodeIn(wait)
      : strings.resendCode
    : wait > 0
      ? strings.sendCodeIn(wait)
      : strings.sendCode;
  return (
    <ChallengeFrame
      presentation={presentation as ChallengePresentationProps}
      title={strings.verifyEmail}
      subtitle={
        sent
          ? strings.weSentCode(digits, destination)
          : strings.weNeedToSendCode(digits, destination)
      }
    >
      {sent && (
        <>
          <Field
            label={strings.code}
            value={code}
            onChangeText={(t) => setCode(digitsOnly(t, digits))}
            keyboardType="number-pad"
            autoComplete="one-time-code"
            textContentType="oneTimeCode"
            maxLength={digits}
            onSubmitEditing={send}
            editable={!isSubmitting}
            autoFocus
            style={[styles.input, styles.code]}
            testID="kc-verify-email-code"
          />
          <PrimaryButton
            title={strings.verify}
            onPress={send}
            disabled={code.length === 0 || isSubmitting}
            busy={isSubmitting}
            testID="kc-verify-email-submit"
          />
        </>
      )}
      <SecondaryButton
        title={resendTitle}
        onPress={() => submit({ kind: 'verifyEmailResend' })}
        disabled={wait > 0 || isSubmitting}
        testID="kc-verify-email-resend"
      />
      {challenge.skippable && (
        <SecondaryButton
          title={strings.notNow}
          onPress={() => submit({ kind: 'skip' })}
          disabled={isSubmitting}
          testID="kc-skip"
        />
      )}
    </ChallengeFrame>
  );
}

/** `terms` (spec/03 §4.14): the text and/or a link, then accept or decline (decline ends the login). */
export function TermsScreen(presentation: ChallengePresentationProps<'terms'>) {
  const { challenge, isSubmitting, strings, submit } = presentation;
  const { text, url, version } = challenge.params;
  return (
    <ChallengeFrame
      presentation={presentation as ChallengePresentationProps}
      title={strings.terms}
      subtitle={
        version !== undefined ? strings.termsVersion(version) : undefined
      }
    >
      {text !== undefined && (
        <ScrollView style={styles.termsText} nestedScrollEnabled>
          <Text style={styles.caption} testID="kc-terms-text">
            {text}
          </Text>
        </ScrollView>
      )}
      {url !== undefined && (
        <SecondaryButton
          title={strings.readFullTerms}
          onPress={() => {
            Linking.openURL(url).catch(() => {});
          }}
          testID="kc-terms-link"
        />
      )}
      <PrimaryButton
        title={strings.accept}
        onPress={() => submit({ kind: 'terms', accepted: true })}
        disabled={isSubmitting}
        busy={isSubmitting}
        testID="kc-terms-accept"
      />
      <SecondaryButton
        title={strings.decline}
        onPress={() => submit({ kind: 'terms', accepted: false })}
        disabled={isSubmitting}
        destructive
        testID="kc-terms-decline"
      />
    </ChallengeFrame>
  );
}

/**
 * `push` (spec/03 §4.7): sends the request when the user asks (or shows the one already sent), shows
 * the number for number match, and polls every `poll_interval` seconds until the device answers.
 */
export function PushScreen(presentation: ChallengePresentationProps<'push'>) {
  const { challenge, isSubmitting, strings, submit } = presentation;
  const params = challenge.params;
  const now = useNow(params.resendAllowedAt !== undefined);
  const wait = secondsUntil(params.resendAllowedAt, now);
  const device = params.devices[0] ?? strings.yourPhone;
  // Poll while the challenge is pending; the server advances on `approved` (spec/03 §4.7).
  const latest = useRef(presentation);
  latest.current = presentation;
  useEffect(() => {
    if (!params.isPending) return undefined;
    const timer = setInterval(() => {
      if (!latest.current.isSubmitting)
        latest.current.submit({ kind: 'pushPoll' });
    }, params.pollInterval * 1000);
    return () => clearInterval(timer);
  }, [params.cid, params.isPending, params.pollInterval]);
  return (
    <ChallengeFrame
      presentation={presentation as ChallengePresentationProps}
      title={strings.approveOnPhone}
      subtitle={
        params.sent ? strings.pushSent(device) : strings.pushCanSend(device)
      }
    >
      {params.sent ? (
        <>
          {params.userVerificationNumber !== undefined && (
            <View style={styles.centered}>
              <Text style={styles.caption}>{strings.pushChooseNumber}</Text>
              <Text style={styles.bigNumber} testID="kc-push-number">
                {params.userVerificationNumber}
              </Text>
            </View>
          )}
          <View style={styles.row}>
            <ActivityIndicator size="small" />
            <Text style={styles.caption} testID="kc-push-waiting">
              {strings.pushWaiting}
            </Text>
          </View>
          <SecondaryButton
            title={strings.checkNow}
            onPress={() => submit({ kind: 'pushPoll' })}
            disabled={isSubmitting}
            testID="kc-push-poll"
          />
        </>
      ) : (
        <PrimaryButton
          title={wait > 0 ? strings.sendRequestIn(wait) : strings.sendRequest}
          onPress={() => submit({ kind: 'pushResend' })}
          disabled={wait > 0 || isSubmitting}
          busy={isSubmitting}
          testID="kc-push-send"
        />
      )}
    </ChallengeFrame>
  );
}

/** Shown for `select` and unknown types: offer the alternatives or the web. */
export function UnsupportedScreen(presentation: ChallengePresentationProps) {
  const { strings, challenge } = presentation;
  return (
    <ChallengeFrame
      presentation={presentation}
      title={strings.updateRequired}
      subtitle={strings.unsupported(challenge.wireType)}
    />
  );
}

/** The chooser's label for a challenge, as in the native UI layers. */
export function chooserTitle(
  challenge: Challenge,
  strings: NativeLoginStrings
): string {
  switch (challenge.type) {
    case 'passkey':
      return strings.usePasskey;
    case 'password':
      return strings.usePassword;
    case 'totp':
      return strings.useAuthenticator;
    case 'otp':
      return challenge.params.channel === 'sms'
        ? strings.textMeCode
        : strings.emailMeCode;
    case 'recovery_code':
      return strings.useRecoveryCode;
    case 'push':
      return strings.approveOnPhone;
    default:
      return challenge.label ?? challenge.wireType;
  }
}

export function DefaultChallengeChooser({
  alternatives,
  strings,
  select,
}: ChallengeChooserProps) {
  const choices = alternatives.filter((c) => c.supported);
  if (choices.length === 0) return null;
  return (
    <View style={styles.chooser}>
      <Text style={styles.caption}>{strings.tryAnotherWay}</Text>
      {choices.map((c) => (
        <SecondaryButton
          key={c.id}
          title={chooserTitle(c, strings)}
          onPress={() => select(c)}
          testID={`kc-switch-to-${c.wireType}`}
        />
      ))}
    </View>
  );
}

/** `redirect_to_web` (spec/03 §3.4): explains and opens the browser. */
export function RedirectToWebScreen({
  request,
  isSubmitting,
  message,
  strings,
  open,
  cancel,
}: {
  request: RedirectToWebRequest;
  isSubmitting: boolean;
  message?: string;
  strings: NativeLoginStrings;
  open(): void;
  cancel(): void;
}) {
  const reason = request.reason;
  const explanation =
    reason !== undefined && reason.startsWith('required_action:')
      ? strings.accountNeedsAttention(
          reason
            .slice('required_action:'.length)
            .replace(/_/g, ' ')
            .toLowerCase()
        )
      : (request.errorDescription ?? strings.completeOnWeb);
  return (
    <View style={styles.screen}>
      <Text style={styles.title} accessibilityRole="header">
        {strings.continueInBrowser}
      </Text>
      <Text style={styles.caption}>{explanation}</Text>
      {message !== undefined && <Text style={styles.error}>{message}</Text>}
      <PrimaryButton
        title={strings.openBrowser}
        onPress={open}
        disabled={isSubmitting}
        busy={isSubmitting}
        testID="kc-open-browser"
      />
      <SecondaryButton
        title={strings.cancel}
        onPress={cancel}
        disabled={isSubmitting}
        testID="kc-cancel"
      />
    </View>
  );
}

export const styles = StyleSheet.create({
  screen: { gap: 12 },
  field: { gap: 4 },
  title: { fontSize: 22, fontWeight: '700' },
  label: { fontSize: 15, fontWeight: '500' },
  body: { fontSize: 15 },
  caption: { fontSize: 13, color: '#6b7280' },
  error: { fontSize: 13, color: '#b91c1c' },
  warning: { fontSize: 13, color: '#b45309' },
  input: {
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: '#9ca3af',
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: 10,
    fontSize: 16,
  },
  readOnly: { color: '#6b7280', backgroundColor: '#f3f4f6' },
  code: { letterSpacing: 6, fontSize: 22, textAlign: 'center' },
  button: {
    backgroundColor: '#2563eb',
    borderRadius: 8,
    paddingVertical: 12,
    alignItems: 'center',
  },
  buttonDestructive: { backgroundColor: '#b91c1c' },
  buttonDisabled: { opacity: 0.5 },
  buttonPressed: { opacity: 0.8 },
  buttonText: { color: '#ffffff', fontSize: 16, fontWeight: '600' },
  secondaryButton: { paddingVertical: 10, alignItems: 'center' },
  secondaryButtonText: { color: '#2563eb', fontSize: 15 },
  destructiveText: { color: '#b91c1c' },
  chooser: { gap: 4, marginTop: 8 },
  picker: { flexDirection: 'row', flexWrap: 'wrap', gap: 8 },
  chip: {
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: '#9ca3af',
    borderRadius: 16,
    paddingHorizontal: 12,
    paddingVertical: 6,
  },
  chipSelected: { borderColor: '#2563eb', backgroundColor: '#dbeafe' },
  centered: { alignItems: 'center', gap: 4 },
  bigNumber: { fontSize: 44, fontWeight: '700' },
  row: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  termsText: { maxHeight: 220 },
});
