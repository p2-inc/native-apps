import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import {
  FlatList,
  StyleSheet,
  Text,
  TextInput,
  View,
  type StyleProp,
  type ViewStyle,
} from 'react-native';
import type { KeycloakNative } from '../KeycloakNative';
import {
  NativeAuthError,
  NativeAuthErrorCode,
  isApprovalExpired,
  type PendingApproval,
  type PushApprovalAction,
} from '../model';
import { PrimaryButton, SecondaryButton, styles } from './DefaultScreens';
import {
  deviceLocale,
  stringsForLocale,
  type NativeLoginStrings,
} from './strings';

export interface PushApprovalsState {
  approvals: PendingApproval[];
  isLoading: boolean;
  isBusy: boolean;
  message?: string;
}

/**
 * The state behind `PushApprovalsScreen`, the twin of the native `PushApprovalsModel`: the user's
 * pending approvals (expired ones dropped, the focused one first), approve / deny, and a refresh.
 */
export class PushApprovalsController {
  private stateValue: PushApprovalsState = {
    approvals: [],
    isLoading: false,
    isBusy: false,
  };
  private readonly listeners = new Set<() => void>();

  constructor(
    readonly kc: KeycloakNative,
    private readonly focus?: string,
    private readonly onResponded?: (
      approval: PendingApproval,
      status: string
    ) => void
  ) {}

  get state(): PushApprovalsState {
    return this.stateValue;
  }

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getSnapshot = (): PushApprovalsState => this.stateValue;

  async refresh(): Promise<void> {
    this.update({ isLoading: true });
    try {
      const list = (await this.kc.push.pendingApprovals()).filter(
        (a) => !isApprovalExpired(a)
      );
      const ordered = [
        ...list.filter((a) => a.cid === this.focus),
        ...list.filter((a) => a.cid !== this.focus),
      ];
      this.update({ approvals: ordered, message: undefined });
    } catch (e) {
      this.update({ message: describe(e) });
    } finally {
      this.update({ isLoading: false });
    }
  }

  async respond(
    approval: PendingApproval,
    action: PushApprovalAction
  ): Promise<void> {
    this.update({ isBusy: true });
    try {
      const status = await this.kc.push.respond(approval, action);
      this.update({
        approvals: this.stateValue.approvals.filter(
          (a) => a.cid !== approval.cid
        ),
        message: undefined,
      });
      this.onResponded?.(approval, status);
    } catch (e) {
      this.update({ message: describe(e) });
      // A wrong number keeps the card (one more try, spec/05 §5); anything else refreshes.
      if (
        NativeAuthError.from(e).code !==
        NativeAuthErrorCode.userVerificationMismatch
      )
        await this.refresh();
    } finally {
      this.update({ isBusy: false });
    }
  }

  private update(patch: Partial<PushApprovalsState>): void {
    this.stateValue = { ...this.stateValue, ...patch };
    this.listeners.forEach((l) => l());
  }
}

function describe(e: unknown): string {
  const error = NativeAuthError.from(e);
  return error.errorDescription ?? error.code;
}

export interface PushApprovalsScreenProps {
  kc: KeycloakNative;
  /** The `cid` of the approval a notification pointed at (shown first). */
  focus?: string;
  /** Called with the server's status after each approve / deny. */
  onResponded?(approval: PendingApproval, status: string): void;
  strings?: Partial<NativeLoginStrings>;
  style?: StyleProp<ViewStyle>;
}

/**
 * The pending sign-in approvals of this device's user (spec/05 §5 "Number match UX"), the twin of the
 * iOS `PushApprovalsView` and the Android `PushApprovalsScreen`: one card per approval with Approve /
 * Deny, the number-match buttons or a PIN field when the challenge has them, and a refresh button.
 * Show it when a notification is tapped and when the app opens.
 */
export function PushApprovalsScreen({
  kc,
  focus,
  onResponded,
  strings: overrides,
  style,
}: PushApprovalsScreenProps) {
  const onRespondedRef = useRef(onResponded);
  onRespondedRef.current = onResponded;
  const [controller] = useState(
    () =>
      new PushApprovalsController(kc, focus, (a, s) =>
        onRespondedRef.current?.(a, s)
      )
  );
  const state = useSyncExternalStore(
    controller.subscribe,
    controller.getSnapshot
  );
  useEffect(() => {
    controller.refresh();
  }, [controller]);
  const [base] = useState(() => stringsForLocale(deviceLocale()));
  const strings: NativeLoginStrings = { ...base, ...overrides };

  return (
    <FlatList
      style={style}
      contentContainerStyle={local.list}
      data={state.approvals}
      keyExtractor={(a) => a.cid}
      ListHeaderComponent={
        <View style={local.header}>
          <Text style={styles.title} accessibilityRole="header">
            {strings.pushRequests}
          </Text>
          <SecondaryButton
            title={strings.refresh}
            onPress={() => {
              controller.refresh();
            }}
            disabled={state.isLoading}
            testID="kc-push-refresh"
          />
        </View>
      }
      ListEmptyComponent={
        <Text style={styles.caption} testID="kc-push-no-approvals">
          {state.isLoading ? strings.contactingServer : strings.pushNoRequests}
        </Text>
      }
      ListFooterComponent={
        state.message !== undefined ? (
          <Text style={styles.error} testID="kc-push-approvals-message">
            {state.message}
          </Text>
        ) : undefined
      }
      renderItem={({ item }) => (
        <PushApprovalCard
          approval={item}
          isBusy={state.isBusy}
          strings={strings}
          respond={(action) => {
            controller.respond(item, action);
          }}
        />
      )}
    />
  );
}

function PushApprovalCard({
  approval,
  isBusy,
  strings,
  respond,
}: {
  approval: PendingApproval;
  isBusy: boolean;
  strings: NativeLoginStrings;
  respond(action: PushApprovalAction): void;
}) {
  const [pin, setPin] = useState('');
  return (
    <View style={local.card} testID={`kc-push-approval-${approval.cid}`}>
      <Text style={styles.label}>
        {strings.pushSignInTo(approval.clientDisplayName)}
      </Text>
      {approval.username !== undefined && (
        <Text style={styles.caption}>{approval.username}</Text>
      )}
      {approval.numbers.length > 0 ? (
        <>
          <Text style={styles.caption}>{strings.pushPickNumber}</Text>
          <View style={local.numbers}>
            {approval.numbers.map((n) => (
              <View key={n} style={local.number}>
                <PrimaryButton
                  title={n}
                  onPress={() =>
                    respond({ kind: 'approve', userVerification: n })
                  }
                  disabled={isBusy}
                  testID={`kc-push-number-${n}`}
                />
              </View>
            ))}
          </View>
        </>
      ) : approval.requiresPin ? (
        <>
          <Text style={styles.caption}>{strings.pushEnterPin}</Text>
          <TextInput
            style={[styles.input, styles.code]}
            value={pin}
            onChangeText={(t) => setPin(t.replace(/\D/g, ''))}
            keyboardType="number-pad"
            secureTextEntry
            testID="kc-push-pin"
          />
          <PrimaryButton
            title={strings.approve}
            onPress={() => respond({ kind: 'approve', userVerification: pin })}
            disabled={isBusy || pin.length === 0}
            testID="kc-push-approve"
          />
        </>
      ) : (
        <PrimaryButton
          title={strings.approve}
          onPress={() => respond({ kind: 'approve' })}
          disabled={isBusy}
          testID="kc-push-approve"
        />
      )}
      <SecondaryButton
        title={strings.deny}
        onPress={() => respond({ kind: 'deny' })}
        disabled={isBusy}
        destructive
        testID="kc-push-deny"
      />
      {approval.expiresAt !== undefined && (
        <Text style={styles.caption}>
          {strings.pushExpires(
            new Date(approval.expiresAt).toLocaleTimeString(undefined, {
              hour: 'numeric',
              minute: '2-digit',
            })
          )}
        </Text>
      )}
    </View>
  );
}

const local = StyleSheet.create({
  list: { padding: 16, gap: 12 },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  card: {
    gap: 8,
    padding: 16,
    borderRadius: 12,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: '#d1d5db',
  },
  numbers: { flexDirection: 'row', gap: 12 },
  number: { flex: 1 },
});
