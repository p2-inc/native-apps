import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:keycloak_native_flutter/keycloak_native_flutter.dart';

/// The demo realm of keycloak-native-auth/demo (docker compose up). The Android emulator reaches the
/// host as 10.0.2.2; override with --dart-define=ISSUER=….
final Uri issuer = Uri.parse(
  const String.fromEnvironment('ISSUER').isNotEmpty
      ? const String.fromEnvironment('ISSUER')
      : Platform.isAndroid
      ? 'http://10.0.2.2:8080/realms/demo'
      : 'http://localhost:8080/realms/demo',
);

/// The demo realm's native clients (docs/sample-app.md): each runs a different flow.
const Map<String, String> clients = {
  'demo-native': 'Password, then TOTP or push (S1, S3)',
  'demo-native-passkey': 'Passkey first (S2)',
  'demo-native-otp': 'Email code (S4, S5)',
  'demo-native-stepup': 'Step-up (S6)',
};

void main() => runApp(const ExampleApp());

class ExampleApp extends StatelessWidget {
  const ExampleApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'Keycloak Native',
    theme: ThemeData(colorSchemeSeed: Colors.indigo),
    home: const HomePage(),
  );
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  /// One instance per issuer and client for the life of the app.
  final Map<String, KeycloakNative> _instances = {};
  final List<FlowLogEntry> _log = [];
  String _clientId = const String.fromEnvironment('CLIENT_ID', defaultValue: 'demo-native');
  KeycloakNative? _kc;
  NativeLoginFlow? _flow;
  Credentials? _credentials;
  PushEnrollment? _enrollment;
  String? _message;

  @override
  void initState() {
    super.initState();
    _select(_clientId);
  }

  Future<void> _select(String clientId) async {
    try {
      var kc = _instances[clientId];
      if (kc == null) {
        kc = await KeycloakNative.configure(
          issuer: issuer,
          clientId: clientId,
          options: const KeycloakNativeOptions(observeFlow: true, allowRpIdMismatch: bool.fromEnvironment('ALLOW_RP_ID_MISMATCH')),
        );
        kc.flowLog.listen((entry) => setState(() => _log.insert(0, entry)));
        _instances[clientId] = kc;
      }
      final stored = await kc.credentialsManager.stored();
      final enrollment = await kc.push.enrollment();
      setState(() {
        _clientId = clientId;
        _kc = kc;
        _credentials = stored;
        _enrollment = enrollment;
        _message = null;
      });
    } on NativeAuthException catch (e) {
      setState(() => _message = e.toString());
    }
  }

  Future<void> _signIn({bool stepUp = false}) => _run(() async {
    final kc = _kc!;
    const parameters = LoginParameters(scope: 'openid profile', deviceName: 'Flutter example');
    final flow = stepUp
        ? await kc.authentication.stepUp(const LoginParameters(scope: 'openid profile', acrValues: '2'))
        : await kc.authentication.startLogin(parameters);
    setState(() => _flow = flow);
  });

  Future<void> _onResult(NativeLoginResult result) async {
    final flow = _flow;
    switch (result) {
      case NativeLoginAuthorized(:final credentials):
        try {
          await _kc!.credentialsManager.store(credentials);
          setState(() => _credentials = credentials);
        } on NativeAuthException catch (e) {
          setState(() => _message = e.code);
        }
      case NativeLoginCancelled():
        break;
      case NativeLoginFailed(:final error):
        setState(() => _message = error.code);
    }
    await flow?.dispose();
    setState(() => _flow = null);
  }

  Future<void> _run(Future<void> Function() action) async {
    try {
      setState(() => _message = null);
      await action();
    } on NativeAuthException catch (e) {
      setState(() => _message = '${e.code}${e.description == null ? '' : ': ${e.description}'}');
    }
  }

  void _open(String title, Widget body) => Navigator.of(context).push(
    MaterialPageRoute<void>(builder: (_) => Scaffold(appBar: AppBar(title: Text(title)), body: SafeArea(child: body))),
  );

  @override
  Widget build(BuildContext context) {
    final kc = _kc;
    final flow = _flow;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Keycloak Native'),
        actions: [IconButton(tooltip: 'Flow log', icon: const Icon(Icons.list_alt), onPressed: () => _open('Flow log', _FlowLog(entries: _log)))],
      ),
      body: SafeArea(
        child: switch ((kc, flow)) {
          (null, _) => Center(child: Text(_message ?? 'Configuring…')),
          (final kc?, final flow?) => NativeLoginView(
            kc: kc,
            flow: flow,
            onResult: _onResult,
            header: Text('$_clientId at $issuer', style: Theme.of(context).textTheme.labelSmall),
          ),
          (final kc?, null) => ListView(
            padding: const EdgeInsets.all(24),
            children: [
              DropdownButtonFormField<String>(
                key: const ValueKey('client'),
                initialValue: _clientId,
                isExpanded: true,
                decoration: const InputDecoration(labelText: 'Client', border: OutlineInputBorder()),
                items: [for (final e in clients.entries) DropdownMenuItem(value: e.key, child: Text('${e.key}: ${e.value}', overflow: TextOverflow.ellipsis))],
                onChanged: (value) => _select(value!),
              ),
              const SizedBox(height: 16),
              if (_credentials case final credentials?) ..._signedIn(kc, credentials) else FilledButton(onPressed: _signIn, child: const Text('Sign in')),
              if (_message case final message?) Padding(padding: const EdgeInsets.only(top: 12), child: Text(message, style: TextStyle(color: Theme.of(context).colorScheme.error))),
            ],
          ),
        },
      ),
    );
  }

  List<Widget> _signedIn(KeycloakNative kc, Credentials credentials) => [
    Text('Signed in', style: Theme.of(context).textTheme.headlineSmall),
    Text('User: ${credentials.idTokenClaims?['preferred_username'] ?? credentials.accessTokenClaims?['sub']}'),
    Text('acr: ${credentials.accessTokenClaims?['acr']}'),
    Text('Token type: ${credentials.tokenType}'),
    Text('Expires: ${credentials.expiresAt.toLocal()}'),
    Text('Push: ${_enrollment == null ? 'not enrolled' : 'enrolled as ${_enrollment!.deviceLabel}'}'),
    const SizedBox(height: 16),
    Wrap(
      spacing: 8,
      runSpacing: 8,
      children: [
        FilledButton(
          onPressed: () => _run(() async {
            final refreshed = await kc.credentialsManager.credentials(minTtl: const Duration(days: 1));
            setState(() => _credentials = refreshed);
          }),
          child: const Text('Refresh'),
        ),
        OutlinedButton(onPressed: () => _signIn(stepUp: true), child: const Text('Step up (acr 2)')),
        OutlinedButton(
          onPressed: () => _run(() async {
            final passkey = await kc.passkeys.registerNewPasskey(label: 'Flutter example');
            setState(() => _message = 'Passkey ${passkey.credentialId} registered');
          }),
          child: const Text('Register a passkey'),
        ),
        if (_enrollment == null)
          OutlinedButton(
            // No Firebase or APNs in the example: the device reads its approvals itself.
            onPressed: () => _run(() async {
              final enrollment = await kc.push.enroll('Flutter example');
              setState(() => _enrollment = enrollment);
            }),
            child: const Text('Enroll for push'),
          )
        else ...[
          OutlinedButton(onPressed: () => _open('Sign-in requests', PushApprovalsView(push: kc.push)), child: const Text('Sign-in requests')),
          OutlinedButton(
            onPressed: () => _run(() async {
              await kc.push.forgetEnrollment();
              setState(() => _enrollment = null);
            }),
            child: const Text('Forget push enrollment'),
          ),
        ],
        OutlinedButton(
          onPressed: () => _run(() async {
            await kc.credentialsManager.logout();
            setState(() => _credentials = null);
          }),
          child: const Text('Log out'),
        ),
      ],
    ),
  ];
}

/// The SDK's redacted requests and responses (KeycloakNativeOptions.observeFlow).
class _FlowLog extends StatelessWidget {
  const _FlowLog({required this.entries});

  final List<FlowLogEntry> entries;

  @override
  Widget build(BuildContext context) => ListView(
    children: [
      for (final e in entries)
        ExpansionTile(
          title: Text('${e.statusCode ?? e.errorCode ?? '-'} ${e.method} ${e.url.path}'),
          subtitle: Text('${e.duration.inMilliseconds} ms'),
          children: [
            Padding(
              padding: const EdgeInsets.all(12),
              child: SelectableText('${e.requestBody ?? ''}\n\n${e.responseBody ?? ''}', style: const TextStyle(fontFamily: 'monospace', fontSize: 11)),
            ),
          ],
        ),
    ],
  );
}
