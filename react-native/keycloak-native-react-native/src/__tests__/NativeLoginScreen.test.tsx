import { act, create, type ReactTestRenderer } from 'react-test-renderer';
import { Text } from 'react-native';
import { KeycloakNative, setNativeModuleForTesting } from '../KeycloakNative';
import { NativeLoginScreen } from '../ui/NativeLoginScreen';
import type { ChallengePresentationProps } from '../ui/DefaultScreens';
import type { NativeLoginResult } from '../ui/LoginController';
import { TranscriptNative } from './support/TranscriptNative';
import { loadTranscript } from './support/transcripts';

const HAPPY =
  'NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri';

async function settle() {
  // Lets the transcript-backed promises resolve and React commit.
  for (let i = 0; i < 5; i += 1) await act(async () => {});
}

async function render(presenters = {}) {
  setNativeModuleForTesting(new TranscriptNative(loadTranscript(HAPPY)));
  const kc = KeycloakNative.configure({
    issuer: 'http://localhost:8080/realms/demo',
    clientId: 'demo-native',
  });
  const flow = await kc.authentication.startLogin({
    scope: 'openid profile',
    deviceName: 'NativeAuthIT',
  });
  const results: NativeLoginResult[] = [];
  let tree: ReactTestRenderer | undefined;
  await act(async () => {
    tree = create(
      <NativeLoginScreen
        kc={kc}
        flow={flow}
        onResult={(r) => results.push(r)}
        presenters={presenters}
      />
    );
  });
  await settle();
  return { tree: tree!, results };
}

afterEach(() => setNativeModuleForTesting(undefined));

describe('NativeLoginScreen', () => {
  it('renders the default screens through to an authorized result', async () => {
    const { tree, results } = await render();
    const input = (id: string) =>
      tree.root.find(
        (n) => n.props.testID === id && n.props.onChangeText !== undefined
      );
    const button = (id: string) =>
      tree.root.find(
        (n) => n.props.testID === id && n.props.onPress !== undefined
      );

    await act(async () => input('kc-username').props.onChangeText('alice'));
    await act(async () => button('kc-username-submit').props.onPress());
    await settle();
    await act(async () => input('kc-password').props.onChangeText('secret'));
    await act(async () => button('kc-password-submit').props.onPress());
    await settle();
    await act(async () => input('kc-totp').props.onChangeText('12a3456'));
    expect(input('kc-totp').props.value).toBe('123456');
    await act(async () => button('kc-totp-submit').props.onPress());
    await settle();

    expect(results.map((r) => r.kind)).toEqual(['authorized']);
  });

  it('uses a replacement screen for its type', async () => {
    function MyUsername({
      challenge,
      submit,
    }: ChallengePresentationProps<'username'>) {
      return (
        <Text
          testID="custom"
          onPress={() => submit({ kind: 'username', username: 'alice' })}
        >
          {challenge.params.allowEmail ? 'email ok' : 'username only'}
        </Text>
      );
    }
    const { tree } = await render({ username: MyUsername });
    const custom = tree.root.find(
      (n) => n.props.testID === 'custom' && n.props.onPress !== undefined
    );
    expect(custom.props.children).toBe('email ok');
    await act(async () => custom.props.onPress());
    await settle();
    expect(
      tree.root.findAll((n) => n.props.testID === 'kc-password').length
    ).toBeGreaterThan(0);
  });
});
