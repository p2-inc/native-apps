import { useEffect, useMemo, useState } from 'react';
import {
  Button,
  Image,
  Linking,
  Platform,
  Pressable,
  SafeAreaView,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  TextInput,
  useColorScheme,
  View,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import {
  KeycloakNative,
  NativeLoginScreen,
  PushApprovalsScreen,
  type Credentials,
  type NativeLoginFlow,
  type NativeLoginResult,
} from '@p2-inc/keycloak-native-react-native';

// The compose stack of keycloak-native-auth/demo: the host's localhost is 10.0.2.2 on the Android
// emulator. The demo realm's clients register demoapp://auth/callback for the browser fallback
// (spec/03 §3.4); demo-native runs username → password → (TOTP | email code | push) and the native
// required actions of the seeded users. The Server screen changes these at runtime.
const CLIENTS = [
  'demo-native',
  'demo-native-passkey',
  'demo-native-otp',
  'demo-native-pin',
];

type ServerSettings = { serverUrl: string; realm: string; clientId: string };

const DEFAULT_SETTINGS: ServerSettings = {
  serverUrl:
    Platform.OS === 'android'
      ? 'http://10.0.2.2:8080'
      : 'http://localhost:8080',
  realm: 'demo',
  clientId: CLIENTS[0]!,
};
const SETTINGS_KEY = 'serverSettings';

const issuerOf = (settings: ServerSettings) =>
  `${settings.serverUrl.replace(/\/+$/, '')}/realms/${encodeURIComponent(settings.realm)}`;

const sameSettings = (a: ServerSettings, b: ServerSettings) =>
  issuerOf(a) === issuerOf(b) && a.clientId === b.clientId;

/**
 * Plain HTTP only to the development hosts that the Android debug build (`usesCleartextTraffic`)
 * and iOS's `NSAllowsLocalNetworking` are meant for; https for everything else.
 */
const CLEARTEXT_HOSTS = ['10.0.2.2', 'localhost', '127.0.0.1'];

/** `undefined` when the settings are usable, else what is wrong. */
function settingsProblem(settings: ServerSettings): string | undefined {
  const match =
    /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#:]+|\[[^\]]+\])(:\d+)?(\/[^?#]*)?$/.exec(
      settings.serverUrl.trim()
    );
  if (!match) {
    return 'Enter a URL such as https://idp.example.com or http://10.0.2.2:8080 (no query or fragment).';
  }
  const scheme = match[1]!.toLowerCase();
  const host = match[2]!.toLowerCase();
  if ((match[4] ?? '').includes('/realms/')) {
    return 'Enter the server URL without /realms/…; the realm has its own field.';
  }
  if (scheme === 'http' && !CLEARTEXT_HOSTS.includes(host)) {
    return 'Use https for anything but 10.0.2.2 and localhost.';
  }
  if (scheme !== 'http' && scheme !== 'https') {
    return 'The URL must start with https:// (or http:// for 10.0.2.2 and localhost).';
  }
  if (settings.realm.trim() === '') return 'Enter the realm.';
  if (settings.clientId.trim() === '') return 'Enter the client ID.';
  return undefined;
}

/** Phase Two colors: neutral surfaces, the brand blue as accent. */
function usePalette() {
  const dark = useColorScheme() === 'dark';
  return {
    dark,
    background: dark ? '#10131A' : '#FFFFFF',
    text: dark ? '#E1E2EC' : '#111827',
    muted: dark ? '#A3A8B8' : '#6B7280',
    border: dark ? '#424754' : '#D1D5DB',
    accent: dark ? '#6EA8FE' : '#2563EB',
    // Filled buttons: white text on the product blue, the color of the SDK's own primary buttons.
    fill: '#2563EB',
    error: dark ? '#FFB4AB' : '#B91C1C',
  };
}

type Palette = ReturnType<typeof usePalette>;

function ActionButton({
  title,
  onPress,
  primary = false,
  disabled = false,
  palette,
  testID,
}: {
  title: string;
  onPress: () => void;
  primary?: boolean;
  disabled?: boolean;
  palette: Palette;
  testID?: string;
}) {
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ disabled }}
      disabled={disabled}
      onPress={onPress}
      testID={testID}
      style={({ pressed }) => [
        styles.button,
        primary
          ? { backgroundColor: palette.fill, borderColor: palette.fill }
          : { borderColor: palette.border },
        (pressed || disabled) && { opacity: disabled ? 0.4 : 0.7 },
      ]}
    >
      <Text
        style={[
          styles.buttonText,
          primary ? styles.onFill : { color: palette.accent },
        ]}
      >
        {title}
      </Text>
    </Pressable>
  );
}

/** The Phase Two mark and the app's name. */
function BrandHeader({ palette }: { palette: Palette }) {
  return (
    <View style={styles.brand} accessible accessibilityRole="header">
      <Image
        source={require('./assets/brand-mark.png')}
        style={styles.brandMark}
        accessibilityIgnoresInvertColors
      />
      <View>
        <Text style={[styles.brandName, { color: palette.text }]}>
          Phase Two
        </Text>
        <Text style={[styles.label, { color: palette.muted }]}>
          Keycloak native login, React Native example
        </Text>
      </View>
    </View>
  );
}

/** Server URL, realm and client ID, validated; saving signs out and rebuilds the SDK instance. */
function SettingsScreen({
  current,
  palette,
  onSave,
  onClose,
}: {
  current: ServerSettings;
  palette: Palette;
  onSave: (settings: ServerSettings) => Promise<void>;
  onClose: () => void;
}) {
  const [draft, setDraft] = useState(current);
  const [confirming, setConfirming] = useState(false);
  const problem = settingsProblem(draft);
  const trimmed: ServerSettings = {
    serverUrl: draft.serverUrl.trim(),
    realm: draft.realm.trim(),
    clientId: draft.clientId.trim(),
  };
  const field = (
    label: string,
    key: keyof ServerSettings,
    keyboardType: 'url' | 'default' = 'default'
  ) => (
    <View style={styles.field}>
      <Text style={[styles.label, { color: palette.muted }]}>{label}</Text>
      <TextInput
        style={[
          styles.input,
          { color: palette.text, borderColor: palette.border },
        ]}
        value={draft[key]}
        onChangeText={(text) => {
          setConfirming(false);
          setDraft({ ...draft, [key]: text });
        }}
        autoCapitalize="none"
        autoCorrect={false}
        keyboardType={keyboardType}
        placeholderTextColor={palette.muted}
        testID={`settings-${key}`}
      />
    </View>
  );
  return (
    <ScrollView contentContainerStyle={styles.content}>
      <Text style={[styles.title, { color: palette.text }]}>Server</Text>
      {field('Server URL', 'serverUrl', 'url')}
      {field('Realm', 'realm')}
      {field('Client ID', 'clientId')}
      <Text
        style={{ color: problem ? palette.error : palette.muted }}
        testID="settings-problem"
      >
        {problem ?? `Issuer: ${issuerOf(trimmed)}`}
      </Text>
      {confirming ? (
        <View style={styles.content}>
          <Text style={{ color: palette.text }}>
            Switching servers signs you out: the stored login and this device's
            local push enrollment are removed.
          </Text>
          <ActionButton
            title="Save and sign out"
            primary
            palette={palette}
            onPress={() => onSave(trimmed)}
            testID="settings-confirm"
          />
          <ActionButton
            title="Cancel"
            palette={palette}
            onPress={() => setConfirming(false)}
          />
        </View>
      ) : (
        <ActionButton
          title="Save and sign out"
          primary
          disabled={problem !== undefined || sameSettings(trimmed, current)}
          palette={palette}
          onPress={() => setConfirming(true)}
          testID="settings-save"
        />
      )}
      <ActionButton
        title="Reset to defaults"
        disabled={sameSettings(trimmed, DEFAULT_SETTINGS)}
        palette={palette}
        onPress={() => {
          setConfirming(false);
          setDraft(DEFAULT_SETTINGS);
        }}
        testID="settings-reset"
      />
      <Text style={[styles.label, { color: palette.muted }]}>
        Defaults: {issuerOf(DEFAULT_SETTINGS)} with {DEFAULT_SETTINGS.clientId}.
        Browser fallbacks return to demoapp://auth/callback, which the client
        must list as a redirect URI. Plain HTTP works for 10.0.2.2 and localhost
        only; use https for any other host.
      </Text>
      <ActionButton title="Back" palette={palette} onPress={onClose} />
    </ScrollView>
  );
}

type Screen = 'home' | 'login' | 'approvals' | 'settings';

export default function App() {
  const palette = usePalette();
  const [settings, setSettings] = useState<ServerSettings>();
  const [clientId, setClientId] = useState(DEFAULT_SETTINGS.clientId);
  const issuer = settings === undefined ? undefined : issuerOf(settings);
  const kc = useMemo(
    () =>
      issuer === undefined
        ? undefined
        : KeycloakNative.configure({ issuer, clientId }),
    [issuer, clientId]
  );
  const [screen, setScreen] = useState<Screen>('home');
  const [flow, setFlow] = useState<NativeLoginFlow>();
  const [credentials, setCredentials] = useState<Credentials | null>(null);
  const [enrolled, setEnrolled] = useState(false);
  const [message, setMessage] = useState<string>();

  // The saved server settings, else the defaults.
  useEffect(() => {
    AsyncStorage.getItem(SETTINGS_KEY)
      .then((json) =>
        json ? (JSON.parse(json) as ServerSettings) : DEFAULT_SETTINGS
      )
      .catch(() => DEFAULT_SETTINGS)
      .then((loaded) => {
        setSettings(loaded);
        setClientId(loaded.clientId);
      });
  }, []);

  useEffect(() => {
    if (kc === undefined) return;
    kc.credentialsManager
      .stored()
      .then(setCredentials)
      .catch((e) => setMessage(String(e.code ?? e)));
    kc.push
      .isEnrolled()
      .then(setEnrolled)
      .catch(() => setEnrolled(false));
  }, [kc]);

  const run = (work: () => Promise<void>) => async () => {
    setMessage(undefined);
    try {
      await work();
    } catch (e: any) {
      setMessage(`${e.code ?? ''} ${e.message ?? e}`);
    }
  };

  /**
   * Server screen: the stored logins and the local push enrollment belong to the old server, so they
   * are cleared (locally: the old server may be unreachable) before a new instance is configured.
   */
  const switchServer = async (next: ServerSettings) => {
    if (settings !== undefined) {
      for (const c of new Set([...CLIENTS, clientId, settings.clientId])) {
        const old = KeycloakNative.configure({
          issuer: issuerOf(settings),
          clientId: c,
        });
        await old.credentialsManager.clear().catch(() => {});
        await old.push.forgetEnrollment().catch(() => {});
      }
    }
    if (sameSettings(next, DEFAULT_SETTINGS)) {
      await AsyncStorage.removeItem(SETTINGS_KEY);
    } else {
      await AsyncStorage.setItem(SETTINGS_KEY, JSON.stringify(next));
    }
    setCredentials(null);
    setEnrolled(false);
    setSettings(next);
    setClientId(next.clientId);
    setScreen('home');
    setMessage(
      `Signed out. Now using ${issuerOf(next)} with ${next.clientId}.`
    );
  };

  const startFlow = (stepUp: boolean) =>
    run(async () => {
      const parameters = {
        scope: 'openid profile',
        deviceName: `React Native example (${Platform.OS})`,
      };
      setFlow(
        stepUp
          ? await kc!.authentication.stepUp({ ...parameters, maxAge: 0 })
          : await kc!.authentication.startLogin(parameters)
      );
      setScreen('login');
    });

  const onResult = async (result: NativeLoginResult) => {
    setScreen('home');
    switch (result.kind) {
      case 'authorized':
        try {
          await kc!.credentialsManager.store(result.credentials);
          setCredentials(result.credentials);
        } catch (e: any) {
          setMessage(`${e.code ?? ''} ${e.message ?? e}`);
        }
        break;
      case 'cancelled':
        setMessage('Cancelled');
        break;
      case 'failed':
        setMessage(`${result.error.code}: ${result.error.message}`);
        break;
    }
    flow?.release();
    setFlow(undefined);
  };

  if (kc === undefined || settings === undefined) {
    return (
      <SafeAreaView
        style={[styles.container, { backgroundColor: palette.background }]}
      />
    );
  }

  // The module's default screens are drawn on a light surface, as an integrating app gets them.
  if (screen === 'login' && flow !== undefined) {
    return (
      <SafeAreaView style={[styles.container, styles.sdkSurface]}>
        <StatusBar barStyle="dark-content" />
        <NativeLoginScreen
          kc={kc}
          flow={flow}
          onResult={onResult}
          autoSelectPasskey={clientId === 'demo-native-passkey'}
          header={<Text style={styles.title}>Demo realm</Text>}
        />
      </SafeAreaView>
    );
  }

  if (screen === 'approvals') {
    return (
      <SafeAreaView style={[styles.container, styles.sdkSurface]}>
        <StatusBar barStyle="dark-content" />
        <PushApprovalsScreen
          kc={kc}
          onResponded={(approval, status) =>
            setMessage(`${approval.clientDisplayName}: ${status}`)
          }
        />
        <Button title="Back" onPress={() => setScreen('home')} />
      </SafeAreaView>
    );
  }

  const statusBar = (
    <StatusBar barStyle={palette.dark ? 'light-content' : 'dark-content'} />
  );

  if (screen === 'settings') {
    return (
      <SafeAreaView
        style={[styles.container, { backgroundColor: palette.background }]}
      >
        {statusBar}
        <SettingsScreen
          current={settings}
          palette={palette}
          onSave={switchServer}
          onClose={() => setScreen('home')}
        />
      </SafeAreaView>
    );
  }

  const clients = CLIENTS.includes(settings.clientId)
    ? CLIENTS
    : [settings.clientId, ...CLIENTS];
  const text = { color: palette.text };

  return (
    <SafeAreaView
      style={[styles.container, { backgroundColor: palette.background }]}
    >
      {statusBar}
      <ScrollView contentContainerStyle={styles.content}>
        <BrandHeader palette={palette} />
        <Text style={[styles.label, { color: palette.muted }]}>Server</Text>
        <Text style={[styles.mono, text]} testID="issuer">
          {issuer}
        </Text>
        <ActionButton
          title="Server settings"
          palette={palette}
          onPress={() => setScreen('settings')}
          testID="server-settings"
        />
        <Text style={[styles.label, { color: palette.muted }]}>Client</Text>
        <View style={styles.row}>
          {clients.map((c) => (
            <Pressable
              key={c}
              accessibilityRole="radio"
              accessibilityState={{ selected: c === clientId }}
              onPress={() => setClientId(c)}
              style={[
                styles.chip,
                {
                  borderColor: c === clientId ? palette.accent : palette.border,
                },
              ]}
            >
              <Text
                style={{
                  color: c === clientId ? palette.accent : palette.text,
                }}
              >
                {c}
              </Text>
            </Pressable>
          ))}
        </View>
        {credentials === null ? (
          <ActionButton
            title="Sign in"
            primary
            palette={palette}
            onPress={startFlow(false)}
            testID="sign-in"
          />
        ) : (
          <View style={styles.stack}>
            <Text style={text} testID="signed-in">
              Signed in ({credentials.tokenType})
            </Text>
            <Text style={text}>
              Access token expires{' '}
              {new Date(credentials.expiresAt).toLocaleTimeString()}
            </Text>
            <ActionButton
              title="Refresh"
              primary
              palette={palette}
              onPress={run(async () =>
                setCredentials(await kc.credentialsManager.credentials(3600))
              )}
            />
            <ActionButton
              title="Userinfo headers"
              palette={palette}
              onPress={run(async () => {
                const headers = await kc.resourceRequestHeaders(
                  'GET',
                  `${kc.issuer}/protocol/openid-connect/userinfo`
                );
                setMessage(Object.keys(headers).join(', '));
              })}
            />
            <ActionButton
              title="Step up (re-authenticate)"
              palette={palette}
              onPress={startFlow(true)}
            />
            <ActionButton
              title="Create a passkey"
              palette={palette}
              onPress={run(async () => {
                const passkey = await kc.registerNewPasskey(
                  'React Native example'
                );
                setMessage(`Passkey ${passkey.credentialId} registered`);
              })}
            />
            {enrolled ? (
              <ActionButton
                title="Sign-in requests"
                palette={palette}
                onPress={() => setScreen('approvals')}
              />
            ) : (
              <ActionButton
                title="Enroll this device for push"
                palette={palette}
                onPress={run(async () => {
                  await kc.push.enroll(`React Native example (${Platform.OS})`);
                  setEnrolled(true);
                })}
              />
            )}
            <ActionButton
              title="Log out"
              palette={palette}
              onPress={run(async () => {
                await kc.credentialsManager.logout();
                setCredentials(null);
              })}
            />
          </View>
        )}
        {message !== undefined && (
          <Text style={{ color: palette.error }} testID="message">
            {message}
          </Text>
        )}
        <Pressable
          accessibilityRole="link"
          onPress={() => Linking.openURL('https://phasetwo.io')}
          style={styles.footer}
        >
          <Text style={[styles.label, { color: palette.muted }]}>
            Made by Phase Two ·{' '}
            <Text style={{ color: palette.accent }}>phasetwo.io</Text>
          </Text>
        </Pressable>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  // Android draws edge to edge and SafeAreaView only insets on iOS: keep clear of the status bar.
  container: {
    flex: 1,
    paddingTop: Platform.OS === 'android' ? StatusBar.currentHeight : 0,
  },
  sdkSurface: { backgroundColor: '#FFFFFF' },
  content: { padding: 16, gap: 12 },
  stack: { gap: 12 },
  title: { fontSize: 22, fontWeight: '600' },
  label: { fontSize: 13 },
  mono: {
    fontSize: 13,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
  field: { gap: 4 },
  input: {
    borderWidth: StyleSheet.hairlineWidth,
    borderRadius: 8,
    padding: 10,
  },
  row: { flexDirection: 'row', flexWrap: 'wrap', gap: 8 },
  chip: {
    borderWidth: 1,
    borderRadius: 16,
    paddingHorizontal: 12,
    paddingVertical: 6,
  },
  button: {
    borderWidth: 1,
    borderRadius: 8,
    paddingVertical: 12,
    paddingHorizontal: 16,
    alignItems: 'center',
  },
  buttonText: { fontSize: 16, fontWeight: '600' },
  onFill: { color: '#FFFFFF' },
  brand: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    paddingVertical: 8,
  },
  brandMark: { width: 30, height: 24, resizeMode: 'contain' },
  brandName: { fontSize: 20, fontWeight: '600' },
  footer: { paddingVertical: 16, alignItems: 'center' },
});
