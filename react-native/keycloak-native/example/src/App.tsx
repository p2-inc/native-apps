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
  type Credentials,
  type NativeLoginFlow,
  type NativeLoginResult,
} from '@phasetwo/react-native-keycloak-native';

// The compose stack of keycloak-native-auth/demo: the host's localhost is 10.0.2.2 on the Android
// emulator. The demo realm's demo-native client registers demoapp://auth/callback for the browser
// fallback (spec/03 §3.4).
const DEFAULT_ISSUER =
  Platform.OS === 'android'
    ? 'http://10.0.2.2:8080/realms/demo'
    : 'http://localhost:8080/realms/demo';

export default function App() {
  const [issuer, setIssuer] = useState(DEFAULT_ISSUER);
  const kc = useMemo(
    () => KeycloakNative.configure({ issuer, clientId: 'demo-native' }),
    [issuer]
  );
  const [flow, setFlow] = useState<NativeLoginFlow>();
  const [credentials, setCredentials] = useState<Credentials | null>(null);
  const [message, setMessage] = useState<string>();

  useEffect(() => {
    kc.credentialsManager
      .stored()
      .then(setCredentials)
      .catch((e) => setMessage(String(e.code ?? e)));
  }, [kc]);

  const signIn = async () => {
    setMessage(undefined);
    try {
      setFlow(
        await kc.authentication.startLogin({
          scope: 'openid profile',
          deviceName: `React Native example (${Platform.OS})`,
        })
      );
    } catch (e: any) {
      setMessage(e.code ?? String(e));
    }
  };

  const onResult = async (result: NativeLoginResult) => {
    flow?.release();
    setFlow(undefined);
    switch (result.kind) {
      case 'authorized':
        await kc.credentialsManager.store(result.credentials);
        setCredentials(result.credentials);
        break;
      case 'cancelled':
        setMessage('Cancelled');
        break;
      case 'failed':
        setMessage(`${result.error.code}: ${result.error.message}`);
        break;
    }
  };

  const run = (work: () => Promise<void>) => async () => {
    setMessage(undefined);
    try {
      await work();
    } catch (e: any) {
      setMessage(`${e.code ?? ''} ${e.message ?? e}`);
    }
  };

  if (flow !== undefined) {
    return (
      <SafeAreaView style={styles.container}>
        <NativeLoginScreen
          kc={kc}
          flow={flow}
          onResult={onResult}
          header={<Text style={styles.title}>Demo realm</Text>}
        />
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
        />
        {credentials === null ? (
          <Button title="Sign in" onPress={signIn} />
        ) : (
          <View style={styles.content}>
            <Text>Signed in ({credentials.tokenType})</Text>
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
              title="Log out"
              onPress={run(async () => {
                await kc.credentialsManager.logout();
                setCredentials(null);
              })}
            />
          </View>
        )}
        {message !== undefined && <Text style={styles.message}>{message}</Text>}
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
  message: { color: '#b91c1c' },
});
