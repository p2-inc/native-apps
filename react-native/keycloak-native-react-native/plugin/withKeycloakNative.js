// Expo config plugin (spec/19 §3 "Expo"): the native setup the module cannot do at runtime, applied by
// `npx expo prebuild` and EAS Build. Expo Go cannot load the module; use a development build.
//
//   // app.json
//   { "expo": { "plugins": [["@phasetwo/keycloak-native-react-native", {
//       "redirectUri": "demoapp://auth/callback",
//       "associatedDomains": ["idp.example.com"]
//   }]] } }
//
// Android: `KeycloakNativeActivity.register(this)` in `MainActivity.onCreate` (the browser fallback's
// activity result launcher), the SDK's `NativeAuthRedirectActivity` with an intent filter for the
// `redirectUri`, and minSdk 28 / compileSdk 36 / Kotlin 2.2 as floors in gradle.properties.
// iOS: the iOS 17 deployment target, and the Associated Domains `webcredentials:` entries passkeys and
// saved passwords need.

const {
  AndroidConfig,
  createRunOncePlugin,
  withAndroidManifest,
  withEntitlementsPlist,
  withGradleProperties,
  withMainActivity,
  withPodfileProperties,
  withXcodeProject,
} = require('@expo/config-plugins');

const pkg = require('../package.json');

const REDIRECT_ACTIVITY =
  'io.phasetwo.keycloak.nativeauth.sdk.android.NativeAuthRedirectActivity';
const IMPORT =
  'import io.phasetwo.keycloak.nativeauth.reactnative.KeycloakNativeActivity';
const REGISTER = 'KeycloakNativeActivity.register(this)';

const FLOORS = {
  'android.minSdkVersion': '28',
  'android.compileSdkVersion': '36',
  'android.kotlinVersion': '2.2.0',
};
const IOS_DEPLOYMENT_TARGET = '17.0';

/** Numeric comparison of dotted versions (`2.2.0` < `2.10.1`). */
function compareVersions(a, b) {
  const pa = String(a)
    .split('.')
    .map((n) => parseInt(n, 10) || 0);
  const pb = String(b)
    .split('.')
    .map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

/**
 * Adds the import and the `register` call to a Kotlin or Java `MainActivity`. The call goes right after
 * `super.onCreate(...)`; an activity without `onCreate` gets one. Idempotent.
 */
function addRegisterCall(contents, language) {
  if (contents.includes(REGISTER)) return contents;
  const kotlin = language !== 'java';
  const importLine = kotlin ? IMPORT : `${IMPORT};`;
  const call = kotlin ? REGISTER : `${REGISTER};`;
  let src = contents;
  if (!src.includes(IMPORT)) {
    src = src.replace(/^(package [^\n]+\n)/m, `$1\n${importLine}\n`);
  }
  const superCall = /^([ \t]*)super\.onCreate\([^)]*\)\s*;?[ \t]*$/m;
  const match = src.match(superCall);
  if (match) {
    const indent = match[1];
    return src.replace(
      superCall,
      (line) =>
        `${line}\n${indent}// The browser fallback registers its activity result launcher before the activity starts.\n${indent}${call}`
    );
  }
  // No onCreate: add one after the class header.
  const header = kotlin
    ? /class\s+MainActivity\s*:[^{]*\{/
    : /class\s+MainActivity\s+extends[^{]*\{/;
  const method = kotlin
    ? `\n  override fun onCreate(savedInstanceState: android.os.Bundle?) {\n    super.onCreate(savedInstanceState)\n    ${call}\n  }\n`
    : `\n  @Override\n  protected void onCreate(android.os.Bundle savedInstanceState) {\n    super.onCreate(savedInstanceState);\n    ${call}\n  }\n`;
  if (!header.test(src)) {
    throw new Error(
      'keycloak-native: MainActivity has an unexpected shape; add KeycloakNativeActivity.register(this) to its onCreate by hand'
    );
  }
  return src.replace(header, (h) => `${h}${method}`);
}

/** Splits `demoapp://auth/callback` into the intent filter's scheme, host and path. */
function parseRedirectUri(redirectUri) {
  const m = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]*)([^?#]*)/.exec(
    redirectUri
  );
  if (!m) {
    throw new Error(
      `keycloak-native: redirectUri '${redirectUri}' is not a URI like demoapp://auth/callback`
    );
  }
  return { scheme: m[1], host: m[2] || undefined, path: m[3] || undefined };
}

/** Adds (or replaces) the redirect activity in a parsed AndroidManifest. */
function addRedirectActivity(manifest, redirectUri) {
  const application =
    AndroidConfig.Manifest.getMainApplicationOrThrow(manifest);
  const { scheme, host, path } = parseRedirectUri(redirectUri);
  const data = { $: { 'android:scheme': scheme } };
  if (host) data.$['android:host'] = host;
  if (path) data.$['android:path'] = path;
  const activity = {
    '$': {
      'android:name': REDIRECT_ACTIVITY,
      'android:exported': 'true',
      'android:theme': '@android:style/Theme.Translucent.NoTitleBar',
    },
    'intent-filter': [
      {
        action: [{ $: { 'android:name': 'android.intent.action.VIEW' } }],
        category: [
          { $: { 'android:name': 'android.intent.category.DEFAULT' } },
          { $: { 'android:name': 'android.intent.category.BROWSABLE' } },
        ],
        data: [data],
      },
    ],
  };
  application.activity = (application.activity || []).filter(
    (a) => a.$['android:name'] !== REDIRECT_ACTIVITY
  );
  application.activity.push(activity);
  return manifest;
}

/** Raises gradle.properties entries to the SDK's floors; higher values are kept. */
function applyGradleFloors(properties) {
  for (const [key, floor] of Object.entries(FLOORS)) {
    const existing = properties.find(
      (p) => p.type === 'property' && p.key === key
    );
    if (existing === undefined) {
      properties.push({ type: 'property', key, value: floor });
    } else if (compareVersions(existing.value, floor) < 0) {
      existing.value = floor;
    }
  }
  return properties;
}

/** Adds `webcredentials:<domain>` for each domain to the entitlements. */
function addAssociatedDomains(entitlements, domains) {
  const key = 'com.apple.developer.associated-domains';
  const entries = new Set(entitlements[key] || []);
  for (const domain of domains) {
    entries.add(domain.includes(':') ? domain : `webcredentials:${domain}`);
  }
  entitlements[key] = [...entries];
  return entitlements;
}

const withKeycloakNative = (config, props = {}) => {
  const { redirectUri, associatedDomains = [] } = props;

  config = withMainActivity(config, (c) => {
    c.modResults.contents = addRegisterCall(
      c.modResults.contents,
      c.modResults.language
    );
    return c;
  });

  if (redirectUri) {
    config = withAndroidManifest(config, (c) => {
      c.modResults = addRedirectActivity(c.modResults, redirectUri);
      return c;
    });
  }

  config = withGradleProperties(config, (c) => {
    c.modResults = applyGradleFloors(c.modResults);
    return c;
  });

  config = withPodfileProperties(config, (c) => {
    const current = c.modResults['ios.deploymentTarget'];
    if (
      current === undefined ||
      compareVersions(current, IOS_DEPLOYMENT_TARGET) < 0
    ) {
      c.modResults['ios.deploymentTarget'] = IOS_DEPLOYMENT_TARGET;
    }
    return c;
  });

  config = withXcodeProject(config, (c) => {
    const configurations = c.modResults.pbxXCBuildConfigurationSection();
    for (const entry of Object.values(configurations)) {
      const settings = entry && entry.buildSettings;
      if (settings && settings.IPHONEOS_DEPLOYMENT_TARGET !== undefined) {
        if (
          compareVersions(
            settings.IPHONEOS_DEPLOYMENT_TARGET,
            IOS_DEPLOYMENT_TARGET
          ) < 0
        ) {
          settings.IPHONEOS_DEPLOYMENT_TARGET = IOS_DEPLOYMENT_TARGET;
        }
      }
    }
    return c;
  });

  if (associatedDomains.length > 0) {
    config = withEntitlementsPlist(config, (c) => {
      c.modResults = addAssociatedDomains(c.modResults, associatedDomains);
      return c;
    });
  }

  return config;
};

module.exports = createRunOncePlugin(withKeycloakNative, pkg.name, pkg.version);
module.exports.withKeycloakNative = withKeycloakNative;
module.exports._internal = {
  addRegisterCall,
  addRedirectActivity,
  applyGradleFloors,
  addAssociatedDomains,
  parseRedirectUri,
  compareVersions,
};
