import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:keycloak_native/keycloak_native.dart';

/// The demo realm of keycloak-native-auth/demo (docker compose up). The Android emulator reaches the
/// host as 10.0.2.2; override with --dart-define=ISSUER=… and --dart-define=CLIENT_ID=….
final Uri issuer = Uri.parse(
  const String.fromEnvironment('ISSUER').isNotEmpty
      ? const String.fromEnvironment('ISSUER')
      : Platform.isAndroid
      ? 'http://10.0.2.2:8080/realms/demo'
      : 'http://localhost:8080/realms/demo',
);
const String clientId = String.fromEnvironment('CLIENT_ID', defaultValue: 'demo-native');

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
  KeycloakNative? _kc;
  NativeLoginFlow? _flow;
  Credentials? _credentials;
  String? _message;

  @override
  void initState() {
    super.initState();
    _configure();
  }

  Future<void> _configure() async {
    try {
      // One instance per issuer and client for the life of the app.
      final kc = await KeycloakNative.configure(issuer: issuer, clientId: clientId);
      final stored = await kc.credentialsManager.stored();
      setState(() {
        _kc = kc;
        _credentials = stored;
      });
    } on NativeAuthException catch (e) {
      setState(() => _message = e.toString());
    }
  }

  Future<void> _signIn() async {
    final kc = _kc!;
    final flow = await kc.authentication.startLogin(const LoginParameters(scope: 'openid profile', deviceName: 'Flutter example'));
    setState(() {
      _message = null;
      _flow = flow;
    });
  }

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
      await action();
    } on NativeAuthException catch (e) {
      setState(() => _message = e.code);
    }
  }

  @override
  Widget build(BuildContext context) {
    final kc = _kc;
    final flow = _flow;
    final credentials = _credentials;
    return Scaffold(
      appBar: AppBar(title: const Text('Keycloak Native')),
      body: SafeArea(
        child: switch ((kc, flow, credentials)) {
          (null, _, _) => Center(child: Text(_message ?? 'Configuring…')),
          (final kc?, final flow?, _) => NativeLoginView(
            kc: kc,
            flow: flow,
            onResult: _onResult,
            header: Text(issuer.toString(), style: Theme.of(context).textTheme.labelSmall),
          ),
          (final kc?, null, final credentials?) => ListView(
            padding: const EdgeInsets.all(24),
            children: [
              Text('Signed in', style: Theme.of(context).textTheme.headlineSmall),
              const SizedBox(height: 8),
              Text('Subject: ${credentials.idTokenClaims?['preferred_username'] ?? credentials.accessTokenClaims?['sub']}'),
              Text('Token type: ${credentials.tokenType}'),
              Text('Expires: ${credentials.expiresAt.toLocal()}'),
              if (_message case final message?) Text(message, style: TextStyle(color: Theme.of(context).colorScheme.error)),
              const SizedBox(height: 16),
              FilledButton(
                onPressed: () => _run(() async {
                  final refreshed = await kc.credentialsManager.credentials(minTtl: const Duration(days: 1));
                  setState(() => _credentials = refreshed);
                }),
                child: const Text('Refresh'),
              ),
              OutlinedButton(
                onPressed: () => _run(() async {
                  await kc.credentialsManager.logout();
                  setState(() => _credentials = null);
                }),
                child: const Text('Log out'),
              ),
            ],
          ),
          (_, null, null) => Center(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                FilledButton(onPressed: _signIn, child: const Text('Sign in')),
                if (_message case final message?) Text(message, style: TextStyle(color: Theme.of(context).colorScheme.error)),
              ],
            ),
          ),
        },
      ),
    );
  }
}
