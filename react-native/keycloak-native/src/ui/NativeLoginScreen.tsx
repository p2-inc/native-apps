import {
  useEffect,
  useRef,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from 'react';
import {
  ActivityIndicator,
  ScrollView,
  StyleSheet,
  Text,
  View,
  type StyleProp,
  type ViewStyle,
} from 'react-native';
import type { KeycloakNative, NativeLoginFlow } from '../KeycloakNative';
import type { Challenge } from '../model';
import {
  DefaultChallengeChooser,
  DefaultChallengeScreen,
  RedirectToWebScreen,
  styles,
  type ChallengeChooserProps,
  type ChallengePresentationProps,
  type ChallengePresenters,
} from './DefaultScreens';
import {
  LoginController,
  type LoginControllerOptions,
  type NativeLoginResult,
} from './LoginController';
import {
  deviceLocale,
  stringsForLocale,
  type NativeLoginStrings,
} from './strings';

export interface NativeLoginScreenProps extends LoginControllerOptions {
  kc: KeycloakNative;
  /** A flow from `authentication.startLogin(...)` or `stepUp(...)`, not yet started. */
  flow: NativeLoginFlow;
  onResult(result: NativeLoginResult): void;
  /** Replacement screens by challenge type. */
  presenters?: ChallengePresenters;
  /** A replacement "Try another way" list. */
  chooser?: React.ComponentType<ChallengeChooserProps>;
  /** Shown above every screen (a logo). */
  header?: ReactNode;
  /**
   * Replaces some or all strings of the catalogue for the device locale (English or German; pass a
   * whole catalogue for another language).
   */
  strings?: Partial<NativeLoginStrings>;
  style?: StyleProp<ViewStyle>;
}

/**
 * Drives a `NativeLoginFlow` with the default screens, the twin of the iOS `NativeLoginView` and the
 * Android `NativeLoginScreen`: `start()`, one screen per challenge (the first supported entry of each
 * set, with "Try another way" for the rest), the browser fallback, and `onResult` at the end. It does
 * not store credentials or own navigation: call `kc.credentialsManager.store(result.credentials)`.
 */
export function NativeLoginScreen({
  kc,
  flow,
  onResult,
  presenters = {},
  chooser: Chooser = DefaultChallengeChooser,
  header,
  strings: stringOverrides,
  style,
  autoSelectPasskey,
  offerSavedPasswords,
  offerToSavePassword,
  pushRegistration,
}: NativeLoginScreenProps) {
  const onResultRef = useRef(onResult);
  onResultRef.current = onResult;
  const pushRegistrationRef = useRef(pushRegistration);
  pushRegistrationRef.current = pushRegistration;
  const [controller] = useState(
    () =>
      new LoginController(kc, flow, (r) => onResultRef.current(r), {
        autoSelectPasskey,
        offerSavedPasswords,
        offerToSavePassword,
        pushRegistration:
          pushRegistration === undefined
            ? undefined
            : () => pushRegistrationRef.current!(),
      })
  );
  const state = useSyncExternalStore(
    controller.subscribe,
    controller.getSnapshot
  );
  useEffect(() => {
    controller.startIfNeeded();
  }, [controller]);

  const [baseStrings] = useState(() => stringsForLocale(deviceLocale()));
  const strings: NativeLoginStrings = { ...baseStrings, ...stringOverrides };
  const phase = state.phase;

  switch (phase.kind) {
    case 'starting':
      return (
        <View style={[layout.centered, style]}>
          {header}
          <ActivityIndicator />
          <Text style={styles.body}>{strings.contactingServer}</Text>
        </View>
      );
    case 'challenges': {
      const selected = phase.selected;
      const props: ChallengePresentationProps = {
        challenge: selected,
        challenges: phase.challenges,
        alternatives: phase.challenges.filter((c) => c.id !== selected.id),
        flowContext: phase.context,
        isSubmitting: state.isSubmitting,
        isStepUp: phase.context.stepUp,
        offersSavedPasswords: controller.offersSavedPasswords,
        strings,
        submit: (answer) => {
          controller.submit(answer, selected);
        },
        usePasskey: (prefer) => {
          controller.usePasskey(selected, prefer);
        },
        registerPasskey: (label) => {
          controller.registerPasskey(selected, label);
        },
        enrollPush: (deviceLabel) => {
          controller.enrollPush(selected, deviceLabel);
        },
        useSavedPassword: () => {
          controller.useSavedPassword(selected);
        },
        switchTo: (other: Challenge) => controller.select(other),
        cancel: () => {
          controller.cancel();
        },
      };
      const Custom = presenters[selected.type] as
        React.ComponentType<ChallengePresentationProps> | undefined;
      // Keyed by the set, so a rechallenge (wrong password) starts with empty fields.
      const key = `${selected.id}:${stepKey(phase.challenges)}`;
      return (
        <ScrollView
          style={style}
          contentContainerStyle={layout.content}
          keyboardShouldPersistTaps="handled"
        >
          {header}
          {Custom !== undefined ? (
            <Custom key={key} {...props} />
          ) : (
            <DefaultChallengeScreen key={key} {...props} />
          )}
          {state.message !== undefined && (
            <Text style={styles.error}>{state.message}</Text>
          )}
          {props.alternatives.some((c) => c.supported) && (
            <Chooser
              current={selected}
              alternatives={props.alternatives}
              strings={strings}
              select={(c) => controller.select(c)}
            />
          )}
        </ScrollView>
      );
    }
    case 'redirectToWeb':
      return (
        <View style={[layout.content, style]}>
          {header}
          <RedirectToWebScreen
            request={phase.request}
            isSubmitting={state.isSubmitting}
            message={state.message}
            strings={strings}
            open={() => {
              controller.openBrowser();
            }}
            cancel={() => {
              controller.cancel();
            }}
          />
        </View>
      );
    case 'finished':
      return (
        <View style={[layout.centered, style]}>
          <ActivityIndicator />
        </View>
      );
  }
}

/** Distinguishes consecutive sets: every response carries new descriptors (errors, retry counts). */
let stepCounter = 0;
const stepKeys = new WeakMap<Challenge[], number>();
function stepKey(challenges: Challenge[]): number {
  let key = stepKeys.get(challenges);
  if (key === undefined) {
    stepCounter += 1;
    key = stepCounter;
    stepKeys.set(challenges, key);
  }
  return key;
}

const layout = StyleSheet.create({
  centered: { padding: 24, alignItems: 'center', gap: 16 },
  content: { padding: 16, gap: 16 },
});
