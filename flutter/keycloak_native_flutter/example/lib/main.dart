import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:keycloak_native_flutter/keycloak_native_flutter.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// The default issuer: the demo realm of keycloak-native-auth/demo (docker compose up). The Android
/// emulator reaches the host as 10.0.2.2; override with --dart-define=ISSUER=…, or at runtime on the
/// Server screen.
final Uri defaultIssuer = Uri.parse(
  const String.fromEnvironment('ISSUER').isNotEmpty
      ? const String.fromEnvironment('ISSUER')
      : Platform.isAndroid
      ? 'http://10.0.2.2:8080/realms/demo'
      : 'http://localhost:8080/realms/demo',
);

const String defaultClientId = String.fromEnvironment('CLIENT_ID', defaultValue: 'demo-native');

/// Phase Two's product blue, the seed of the Material 3 color scheme.
const Color brandBlue = Color(0xFF3B82F6);

/// The demo realm's native clients (docs/sample-app.md): each runs a different flow.
const Map<String, String> clients = {
  'demo-native': 'Password, then TOTP or push (S1, S3)',
  'demo-native-passkey': 'Passkey first (S2)',
  'demo-native-otp': 'Email code (S4, S5)',
  'demo-native-stepup': 'Step-up (S6)',
  'demo-native-pin': 'PIN (pia has one, pete sets one)',
};

void main() => runApp(const ExampleApp());

class ExampleApp extends StatelessWidget {
  const ExampleApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'Keycloak Native',
    // Seeded from the brand blue; the fidelity variant keeps the primary close to it. The SDK's
    // NativeLoginView reads the theme like any widget, as it would an integrating app's.
    theme: ThemeData(colorScheme: ColorScheme.fromSeed(seedColor: brandBlue, dynamicSchemeVariant: DynamicSchemeVariant.fidelity)),
    darkTheme: ThemeData(
      colorScheme: ColorScheme.fromSeed(seedColor: brandBlue, dynamicSchemeVariant: DynamicSchemeVariant.fidelity, brightness: Brightness.dark),
    ),
    home: const HomePage(),
  );
}

/// The server the example talks to, saved with shared_preferences (Server screen).
class ServerSettings {
  const ServerSettings({required this.serverUrl, required this.realm, required this.clientId});

  /// The defaults: --dart-define values, else the compose stack as the emulator or simulator sees it.
  factory ServerSettings.defaults() => ServerSettings.fromIssuer(defaultIssuer, defaultClientId);

  factory ServerSettings.fromIssuer(Uri issuer, String clientId) {
    final text = issuer.toString();
    final at = text.indexOf('/realms/');
    return ServerSettings(
      serverUrl: at < 0 ? text : text.substring(0, at),
      realm: at < 0 ? '' : Uri.decodeComponent(text.substring(at + '/realms/'.length).replaceAll(RegExp(r'/+$'), '')),
      clientId: clientId,
    );
  }

  final String serverUrl;
  final String realm;
  final String clientId;

  Uri get issuer => Uri.parse('${serverUrl.replaceAll(RegExp(r'/+$'), '')}/realms/${Uri.encodeComponent(realm)}');

  static const _issuerKey = 'server.issuer';
  static const _clientKey = 'server.clientId';

  static Future<ServerSettings> load() async {
    final prefs = SharedPreferencesAsync();
    final issuer = await prefs.getString(_issuerKey);
    final clientId = await prefs.getString(_clientKey);
    if (issuer == null || clientId == null) return ServerSettings.defaults();
    return ServerSettings.fromIssuer(Uri.parse(issuer), clientId);
  }

  Future<void> save() async {
    final prefs = SharedPreferencesAsync();
    if (this == ServerSettings.defaults()) {
      await prefs.remove(_issuerKey);
      await prefs.remove(_clientKey);
    } else {
      await prefs.setString(_issuerKey, issuer.toString());
      await prefs.setString(_clientKey, clientId);
    }
  }

  /// Plain HTTP only to the development hosts that the Android debug network security config and iOS's
  /// NSAllowsLocalNetworking allow; https for everything else.
  static const cleartextHosts = {'10.0.2.2', 'localhost', '127.0.0.1'};

  /// `null` when [text] is a usable base URL, else what is wrong with it.
  static String? problemWithServerUrl(String text) {
    final uri = Uri.tryParse(text.trim());
    if (uri == null || !uri.hasScheme || uri.host.isEmpty) return 'Enter a URL such as https://idp.example.com or http://10.0.2.2:8080.';
    if (uri.hasQuery || uri.hasFragment) return 'Leave out the query and fragment.';
    if (uri.path.contains('/realms/')) return 'Enter the server URL without /realms/…; the realm has its own field.';
    return switch (uri.scheme.toLowerCase()) {
      'https' => null,
      'http' when cleartextHosts.contains(uri.host.toLowerCase()) => null,
      'http' => 'Use https for anything but 10.0.2.2 and localhost.',
      _ => 'The URL must start with https:// (or http:// for 10.0.2.2 and localhost).',
    };
  }

  @override
  bool operator ==(Object other) => other is ServerSettings && other.issuer == issuer && other.clientId == clientId;

  @override
  int get hashCode => Object.hash(issuer, clientId);
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  /// One instance per client for the configured server; rebuilt when the server changes.
  final Map<String, KeycloakNative> _instances = {};
  final List<FlowLogEntry> _log = [];
  ServerSettings _settings = ServerSettings.defaults();
  String _clientId = defaultClientId;
  KeycloakNative? _kc;
  NativeLoginFlow? _flow;
  Credentials? _credentials;
  PushEnrollment? _enrollment;
  String? _message;

  @override
  void initState() {
    super.initState();
    ServerSettings.load().then((settings) {
      _settings = settings;
      _select(settings.clientId);
    });
  }

  Uri get issuer => _settings.issuer;

  /// Server screen: the stored logins and the local push enrollments belong to the old server, so they
  /// are cleared (locally: the old server may be unreachable) and the SDK instances rebuilt.
  Future<void> _switchServer(ServerSettings settings) async {
    for (final kc in _instances.values) {
      try {
        await kc.credentialsManager.clear();
        await kc.push.forgetEnrollment();
      } on NativeAuthException {
        // Nothing stored.
      }
    }
    await settings.save();
    setState(() {
      _instances.clear();
      _log.clear();
      _settings = settings;
      _kc = null;
      _flow = null;
    });
    await _select(settings.clientId);
    setState(() => _message = 'Signed out. Now using ${settings.issuer} with ${settings.clientId}.');
  }

  void _openSettings() => Navigator.of(context).push(
    MaterialPageRoute<void>(builder: (_) => ServerSettingsPage(current: _settings, onSave: _switchServer)),
  );

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
        title: const _BrandTitle(),
        actions: [
          IconButton(tooltip: 'Flow log', icon: const Icon(Icons.list_alt), onPressed: () => _open('Flow log', _FlowLog(entries: _log))),
          IconButton(key: const ValueKey('serverSettings'), tooltip: 'Server', icon: const Icon(Icons.dns_outlined), onPressed: _openSettings),
        ],
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
                items: [
                  for (final e in clients.entries) DropdownMenuItem(value: e.key, child: Text('${e.key}: ${e.value}', overflow: TextOverflow.ellipsis)),
                  if (!clients.containsKey(_clientId)) DropdownMenuItem(value: _clientId, child: Text(_clientId, overflow: TextOverflow.ellipsis)),
                ],
                onChanged: (value) => _select(value!),
              ),
              Padding(
                padding: const EdgeInsets.only(top: 8),
                child: Text('Server: $issuer', style: Theme.of(context).textTheme.bodySmall),
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

/// The Phase Two mark and the app's name in the app bar.
class _BrandTitle extends StatelessWidget {
  const _BrandTitle();

  @override
  Widget build(BuildContext context) => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      Image.asset('assets/brand_mark.png', height: 18, excludeFromSemantics: true),
      const SizedBox(width: 12),
      const Text('Keycloak Native'),
    ],
  );
}

/// Server URL, realm and client ID, validated; saving signs out and rebuilds the SDK instances.
class ServerSettingsPage extends StatefulWidget {
  const ServerSettingsPage({super.key, required this.current, required this.onSave});

  final ServerSettings current;
  final Future<void> Function(ServerSettings) onSave;

  @override
  State<ServerSettingsPage> createState() => _ServerSettingsPageState();
}

class _ServerSettingsPageState extends State<ServerSettingsPage> {
  late final _serverUrl = TextEditingController(text: widget.current.serverUrl);
  late final _realm = TextEditingController(text: widget.current.realm);
  late final _clientId = TextEditingController(text: widget.current.clientId);
  bool _saving = false;

  @override
  void dispose() {
    _serverUrl.dispose();
    _realm.dispose();
    _clientId.dispose();
    super.dispose();
  }

  String? get _problem =>
      ServerSettings.problemWithServerUrl(_serverUrl.text) ??
      (_realm.text.trim().isEmpty ? 'Enter the realm.' : null) ??
      (_clientId.text.trim().isEmpty ? 'Enter the client ID.' : null);

  ServerSettings? get _edited => _problem != null
      ? null
      : ServerSettings(serverUrl: _serverUrl.text.trim(), realm: _realm.text.trim(), clientId: _clientId.text.trim());

  void _fill(ServerSettings settings) => setState(() {
    _serverUrl.text = settings.serverUrl;
    _realm.text = settings.realm;
    _clientId.text = settings.clientId;
  });

  Future<void> _save(ServerSettings settings) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Switch servers?'),
        content: const Text('The stored logins and this device\'s local push enrollments are removed.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(context, true), child: const Text('Save and sign out')),
        ],
      ),
    );
    if (confirmed != true) return;
    setState(() => _saving = true);
    await widget.onSave(settings);
    if (mounted) Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final problem = _problem;
    final edited = _edited;
    final defaults = ServerSettings.defaults();
    Widget field(String label, TextEditingController controller, String key, {TextInputType? type}) => Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: TextField(
        key: ValueKey(key),
        controller: controller,
        keyboardType: type,
        autocorrect: false,
        decoration: InputDecoration(labelText: label, border: const OutlineInputBorder()),
        onChanged: (_) => setState(() {}),
      ),
    );
    return Scaffold(
      appBar: AppBar(title: const Text('Server')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(24),
          children: [
            field('Server URL', _serverUrl, 'settingsServerUrl', type: TextInputType.url),
            field('Realm', _realm, 'settingsRealm'),
            field('Client ID', _clientId, 'settingsClientId'),
            Text(
              problem ?? 'Issuer: ${edited!.issuer}',
              key: const ValueKey('settingsProblem'),
              style: theme.textTheme.bodySmall?.copyWith(color: problem == null ? theme.colorScheme.onSurfaceVariant : theme.colorScheme.error),
            ),
            const SizedBox(height: 16),
            FilledButton(
              key: const ValueKey('settingsSave'),
              onPressed: edited == null || edited == widget.current || _saving ? null : () => _save(edited),
              child: const Text('Save and sign out'),
            ),
            const SizedBox(height: 8),
            OutlinedButton(
              key: const ValueKey('settingsReset'),
              onPressed: edited == defaults ? null : () => _fill(defaults),
              child: const Text('Reset to defaults'),
            ),
            const SizedBox(height: 16),
            Text(
              'Defaults: ${defaults.issuer} with ${defaults.clientId}. Browser fallbacks return to demoapp://auth/callback, which the client must list as a redirect URI. Plain HTTP works for 10.0.2.2 and localhost only; use https for any other host.',
              style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
            ),
            const Divider(height: 48),
            Row(
              children: [
                Image.asset('assets/brand_mark.png', height: 14, excludeFromSemantics: true),
                const SizedBox(width: 12),
                Expanded(child: Text('Made by Phase Two', style: theme.textTheme.bodyMedium)),
                SelectableText('phasetwo.io', style: theme.textTheme.bodyMedium?.copyWith(color: theme.colorScheme.primary)),
              ],
            ),
          ],
        ),
      ),
    );
  }
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
