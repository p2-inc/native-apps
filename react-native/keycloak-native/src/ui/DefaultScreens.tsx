import { useState } from 'react';
import {
  ActivityIndicator,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import type {
  Challenge,
  ChallengeAnswer,
  ChallengeOf,
  ChallengeType,
  FlowContext,
  RedirectToWebRequest,
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
  strings: NativeLoginStrings;
  submit(answer: ChallengeAnswer): void;
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

export function DefaultChallengeScreen(props: ChallengePresentationProps) {
  switch (props.challenge.type) {
    case 'username':
      return (
        <UsernameScreen
          {...(props as ChallengePresentationProps<'username'>)}
        />
      );
    case 'password':
      return (
        <PasswordScreen
          {...(props as ChallengePresentationProps<'password'>)}
        />
      );
    case 'totp':
      return <TotpScreen {...(props as ChallengePresentationProps<'totp'>)} />;
    default:
      return <UnsupportedScreen {...props} />;
  }
}

function ErrorText({ challenge }: { challenge: Challenge }) {
  if (challenge.error === undefined) return null;
  return (
    <Text style={styles.error} accessibilityRole="alert">
      {challenge.error.message ?? challenge.error.code}
    </Text>
  );
}

function RetryText({
  challenge,
  strings,
}: {
  challenge: Challenge;
  strings: NativeLoginStrings;
}) {
  const remaining = challenge.retry?.remaining;
  if (remaining === undefined || challenge.error === undefined) return null;
  return (
    <Text style={styles.caption}>{strings.attemptsRemaining(remaining)}</Text>
  );
}

function PrimaryButton({
  title,
  onPress,
  disabled,
  busy,
  testID,
}: {
  title: string;
  onPress: () => void;
  disabled?: boolean;
  busy?: boolean;
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

function SecondaryButton({
  title,
  onPress,
  disabled,
}: {
  title: string;
  onPress: () => void;
  disabled?: boolean;
}) {
  return (
    <Pressable
      accessibilityRole="button"
      disabled={disabled}
      onPress={onPress}
      style={styles.secondaryButton}
    >
      <Text style={styles.secondaryButtonText}>{title}</Text>
    </Pressable>
  );
}

export function UsernameScreen({
  challenge,
  isSubmitting,
  strings,
  submit,
}: ChallengePresentationProps<'username'>) {
  const [username, setUsername] = useState(challenge.params.hint ?? '');
  const valid = username.trim().length > 0;
  const send = () => {
    if (valid && !isSubmitting)
      submit({ kind: 'username', username: username.trim() });
  };
  return (
    <View style={styles.screen}>
      <Text style={styles.label}>
        {challenge.params.allowEmail
          ? strings.usernameOrEmail
          : strings.username}
      </Text>
      <TextInput
        style={styles.input}
        value={username}
        onChangeText={setUsername}
        autoCapitalize="none"
        autoCorrect={false}
        autoComplete="username"
        textContentType="username"
        keyboardType={challenge.params.allowEmail ? 'email-address' : 'default'}
        returnKeyType="next"
        onSubmitEditing={send}
        editable={!isSubmitting}
        testID="kc-username"
      />
      <ErrorText challenge={challenge} />
      <PrimaryButton
        title={strings.continue}
        onPress={send}
        disabled={!valid || isSubmitting}
        busy={isSubmitting}
        testID="kc-username-submit"
      />
    </View>
  );
}

export function PasswordScreen({
  challenge,
  flowContext,
  isSubmitting,
  strings,
  submit,
}: ChallengePresentationProps<'password'>) {
  const [password, setPassword] = useState('');
  const valid = password.length > 0;
  const send = () => {
    if (valid && !isSubmitting) submit({ kind: 'password', password });
  };
  return (
    <View style={styles.screen}>
      {flowContext.username !== undefined && (
        // Password managers pair a password with a username on the same screen, and Keycloak asks for
        // the username on the previous one, so it is repeated read-only.
        <TextInput
          style={[styles.input, styles.readOnly]}
          value={flowContext.username}
          editable={false}
          autoComplete="username"
          textContentType="username"
          accessibilityLabel={strings.username}
        />
      )}
      <Text style={styles.label}>{strings.password}</Text>
      <TextInput
        style={styles.input}
        value={password}
        onChangeText={setPassword}
        secureTextEntry
        autoCapitalize="none"
        autoCorrect={false}
        autoComplete="current-password"
        textContentType="password"
        returnKeyType="go"
        onSubmitEditing={send}
        editable={!isSubmitting}
        autoFocus
        testID="kc-password"
      />
      <ErrorText challenge={challenge} />
      <RetryText challenge={challenge} strings={strings} />
      <PrimaryButton
        title={strings.signIn}
        onPress={send}
        disabled={!valid || isSubmitting}
        busy={isSubmitting}
        testID="kc-password-submit"
      />
    </View>
  );
}

export function TotpScreen({
  challenge,
  isSubmitting,
  strings,
  submit,
}: ChallengePresentationProps<'totp'>) {
  const { digits, credentials } = challenge.params;
  const [code, setCode] = useState('');
  const [credentialId, setCredentialId] = useState<string | undefined>(
    credentials[0]?.id
  );
  const valid = code.length === digits;
  const send = () => {
    if (valid && !isSubmitting)
      submit({
        kind: 'totp',
        code,
        credentialId: credentials.length > 1 ? credentialId : undefined,
      });
  };
  return (
    <View style={styles.screen}>
      <Text style={styles.body}>{strings.totpPrompt(digits)}</Text>
      {credentials.length > 1 && (
        <View
          style={styles.picker}
          accessibilityLabel={strings.totpPickAuthenticator}
        >
          {credentials.map((c) => (
            <Pressable
              key={c.id}
              accessibilityRole="radio"
              accessibilityState={{ selected: c.id === credentialId }}
              onPress={() => setCredentialId(c.id)}
              style={[
                styles.chip,
                c.id === credentialId && styles.chipSelected,
              ]}
            >
              <Text>{c.label.length > 0 ? c.label : c.id}</Text>
            </Pressable>
          ))}
        </View>
      )}
      <Text style={styles.label}>{strings.verificationCode}</Text>
      <TextInput
        style={[styles.input, styles.code]}
        value={code}
        onChangeText={(t) => setCode(t.replace(/\D/g, '').slice(0, digits))}
        keyboardType="number-pad"
        autoComplete="one-time-code"
        textContentType="oneTimeCode"
        maxLength={digits}
        onSubmitEditing={send}
        editable={!isSubmitting}
        autoFocus
        testID="kc-totp"
      />
      <ErrorText challenge={challenge} />
      <RetryText challenge={challenge} strings={strings} />
      <PrimaryButton
        title={strings.verify}
        onPress={send}
        disabled={!valid || isSubmitting}
        busy={isSubmitting}
        testID="kc-totp-submit"
      />
    </View>
  );
}

/** Shown for a type without a default screen in this version (and for `unknown` types). */
export function UnsupportedScreen({
  strings,
  cancel,
}: ChallengePresentationProps) {
  return (
    <View style={styles.screen}>
      <Text style={styles.title}>{strings.unsupportedTitle}</Text>
      <Text style={styles.body}>{strings.unsupportedMessage}</Text>
      <SecondaryButton title={strings.cancel} onPress={cancel} />
    </View>
  );
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
          title={strings.challengeName(c.wireType, c.label)}
          onPress={() => select(c)}
        />
      ))}
    </View>
  );
}

export function RedirectToWebScreen({
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
  return (
    <View style={styles.screen}>
      <Text style={styles.title}>{strings.browserTitle}</Text>
      <Text style={styles.body}>{strings.browserMessage}</Text>
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
      />
    </View>
  );
}

export const styles = StyleSheet.create({
  screen: { gap: 12 },
  title: { fontSize: 20, fontWeight: '600' },
  label: { fontSize: 15, fontWeight: '500' },
  body: { fontSize: 15 },
  caption: { fontSize: 13, color: '#6b7280' },
  error: { fontSize: 13, color: '#b91c1c' },
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
  buttonDisabled: { opacity: 0.5 },
  buttonPressed: { opacity: 0.8 },
  buttonText: { color: '#ffffff', fontSize: 16, fontWeight: '600' },
  secondaryButton: { paddingVertical: 10, alignItems: 'center' },
  secondaryButtonText: { color: '#2563eb', fontSize: 15 },
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
});
