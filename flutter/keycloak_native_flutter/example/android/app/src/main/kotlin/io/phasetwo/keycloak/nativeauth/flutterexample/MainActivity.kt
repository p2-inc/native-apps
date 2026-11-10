package io.phasetwo.keycloak.nativeauth.flutterexample

import io.flutter.embedding.android.FlutterFragmentActivity

/**
 * A FlutterFragmentActivity, not a FlutterActivity: the plugin's browser fallback (Auth Tab) needs a
 * ComponentActivity to register its activity result launcher with (spec/18 §6).
 */
class MainActivity : FlutterFragmentActivity()
