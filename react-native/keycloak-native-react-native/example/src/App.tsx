import { useEffect, useMemo, useState } from 'react';
import {
  Button,
  Platform,
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import {
  KeycloakNative,
  NativeLoginScreen,
  PushApprovalsScreen,
  type Credentials,
  type NativeLoginFlow,
  type NativeLoginResult,
} from '@phasetwo.io/keycloak-native-react-native';

// The compose stack of keycloak-native-auth/demo: the host's localhost is 10.0.2.2 on the Android
// emulator. The demo realm's clients register demoapp://auth/callback for the browser fallback
// (spec/03 §3.4); demo-native runs username → password → (TOTP | email code | push) and the native
// required actions of the seeded users.
const DEFAULT_ISSUER =
  Platform.OS === 'android'
    ? 'http://10.0.2.2:8080/realms/demo'
    : 'http://localhost:8080/realms/demo';
const CLIENTS = ['demo-native', 'demo-native-passkey', 'demo-native-otp'];

type Screen = 'home' | 'login' | 'approvals';

export default function App() {
  const [issuer, setIssuer] = useState(DEFAULT_ISSUER);
  const [clientId, setClientId] = useState(CLIENTS[0]!);
  const kc = useMemo(
    () => KeycloakNative.configure({ issuer, clientId }),
    [issuer, clientId]
  );
  const [screen, setScreen] = useState<Screen>('home');
  const [flow, setFlow] = useState<NativeLoginFlow>();
  const [credentials, setCredentials] = useState<Credentials | null>(null);
  const [enrolled, setEnrolled] = useState(false);
  const [message, setMessage] = useState<string>();

  useEffect(() => {
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

  const startFlow = (stepUp: boolean) =>
    run(async () => {
      const parameters = {
        scope: 'openid profile',
        deviceName: `React Native example (${Platform.OS})`,
      };
      setFlow(
        stepUp
          ? await kc.authentication.stepUp({ ...parameters, maxAge: 0 })
          : await kc.authentication.startLogin(parameters)
      );
      setScreen('login');
    });

  const onResult = async (result: NativeLoginResult) => {
    setScreen('home');
    switch (result.kind) {
      case 'authorized':
        try {
          await kc.credentialsManager.store(result.credentials);
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

  if (screen === 'login' && flow !== undefined) {
    return (
      <SafeAreaView style={styles.container}>
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
      <SafeAreaView style={styles.container}>
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

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.title}>Keycloak native login</Text>
        <Text style={styles.label}>Issuer</Text>
        <TextInput
          style={styles.input}
          defaultValue={issuer}
          // One SDK instance per issuer + client: reconfigure when editing ends, not per keystroke.
          onEndEditing={(e) => setIssuer(e.nativeEvent.text.trim())}
          autoCapitalize="none"
          autoCorrect={false}
          testID="issuer"
        />
        <Text style={styles.label}>Client</Text>
        <View style={styles.row}>
          {CLIENTS.map((c) => (
            <Button
              key={c}
              title={c === clientId ? `[${c}]` : c}
              onPress={() => setClientId(c)}
            />
          ))}
        </View>
        {credentials === null ? (
          <Button title="Sign in" onPress={startFlow(false)} testID="sign-in" />
        ) : (
          <View style={styles.content}>
            <Text testID="signed-in">Signed in ({credentials.tokenType})</Text>
            <Text>
              Access token expires{' '}
              {new Date(credentials.expiresAt).toLocaleTimeString()}
            </Text>
            <Button
              title="Refresh"
              onPress={run(async () =>
                setCredentials(await kc.credentialsManager.credentials(3600))
              )}
            />
            <Button
              title="Userinfo headers"
              onPress={run(async () => {
                const headers = await kc.resourceRequestHeaders(
                  'GET',
                  `${kc.issuer}/protocol/openid-connect/userinfo`
                );
                setMessage(Object.keys(headers).join(', '));
              })}
            />
            <Button
              title="Step up (re-authenticate)"
              onPress={startFlow(true)}
            />
            <Button
              title="Create a passkey"
              onPress={run(async () => {
                const passkey = await kc.registerNewPasskey(
                  'React Native example'
                );
                setMessage(`Passkey ${passkey.credentialId} registered`);
              })}
            />
            {enrolled ? (
              <Button
                title="Sign-in requests"
                onPress={() => setScreen('approvals')}
              />
            ) : (
              <Button
                title="Enroll this device for push"
                onPress={run(async () => {
                  await kc.push.enroll(`React Native example (${Platform.OS})`);
                  setEnrolled(true);
                })}
              />
            )}
            <Button
              title="Log out"
              onPress={run(async () => {
                await kc.credentialsManager.logout();
                setCredentials(null);
              })}
            />
          </View>
        )}
        {message !== undefined && (
          <Text style={styles.message} testID="message">
            {message}
          </Text>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  content: { padding: 16, gap: 12 },
  title: { fontSize: 22, fontWeight: '600' },
  label: { fontSize: 13, color: '#6b7280' },
  input: {
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: '#9ca3af',
    borderRadius: 8,
    padding: 10,
  },
  row: { flexDirection: 'row', flexWrap: 'wrap', gap: 8 },
  message: { color: '#b91c1c' },
});
