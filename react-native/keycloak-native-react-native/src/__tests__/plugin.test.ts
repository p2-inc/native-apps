// The Expo config plugin's transforms, on the shapes of Expo's and React Native's templates.
export {};
const plugin = require('../../app.plugin.js');
const {
  addRegisterCall,
  addRedirectActivity,
  applyGradleFloors,
  addAssociatedDomains,
  compareVersions,
} = plugin._internal;

const EXPO_MAIN_ACTIVITY = `package com.example.app

import android.os.Build
import android.os.Bundle

import com.facebook.react.ReactActivity

class MainActivity : ReactActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    setTheme(R.style.AppTheme);
    super.onCreate(null)
  }

  override fun getMainComponentName(): String = "main"
}
`;

const RN_MAIN_ACTIVITY = `package com.example.app

import com.facebook.react.ReactActivity

class MainActivity : ReactActivity() {
  override fun getMainComponentName(): String = "Example"
}
`;

describe('Expo config plugin', () => {
  it('registers the browser fallback after super.onCreate, once', () => {
    const once = addRegisterCall(EXPO_MAIN_ACTIVITY, 'kt');
    expect(once).toContain(
      'import io.phasetwo.keycloak.nativeauth.reactnative.KeycloakNativeActivity'
    );
    expect(once).toMatch(
      /super\.onCreate\(null\)\n.*\n\s+KeycloakNativeActivity\.register\(this\)/
    );
    expect(addRegisterCall(once, 'kt')).toBe(once);
  });

  it('adds onCreate to an activity without one', () => {
    const out = addRegisterCall(RN_MAIN_ACTIVITY, 'kt');
    expect(out).toContain(
      'override fun onCreate(savedInstanceState: android.os.Bundle?)'
    );
    expect(out).toContain('KeycloakNativeActivity.register(this)');
  });

  it('declares the redirect activity for the redirect URI, replacing an earlier one', () => {
    const manifest = {
      manifest: {
        $: {},
        application: [
          { $: { 'android:name': '.MainApplication' }, activity: [] },
        ],
      },
    };
    addRedirectActivity(manifest, 'demoapp://auth/callback');
    addRedirectActivity(manifest, 'demoapp://auth/callback');
    const activities = manifest.manifest.application[0]!.activity as any[];
    expect(activities).toHaveLength(1);
    expect(activities[0].$['android:name']).toBe(
      'io.phasetwo.keycloak.nativeauth.sdk.android.NativeAuthRedirectActivity'
    );
    expect(activities[0]['intent-filter'][0].data[0].$).toEqual({
      'android:scheme': 'demoapp',
      'android:host': 'auth',
      'android:path': '/callback',
    });
    expect(() => addRedirectActivity(manifest, 'not a uri')).toThrow(
      /redirectUri/
    );
  });

  it('raises gradle.properties to the floors and keeps higher values', () => {
    const props = applyGradleFloors([
      { type: 'property', key: 'android.minSdkVersion', value: '24' },
      { type: 'property', key: 'android.kotlinVersion', value: '2.10.0' },
    ]);
    const value = (key: string) => props.find((p: any) => p.key === key)?.value;
    expect(value('android.minSdkVersion')).toBe('28');
    expect(value('android.compileSdkVersion')).toBe('36');
    expect(value('android.kotlinVersion')).toBe('2.10.0');
    expect(compareVersions('2.2.0', '2.10.1')).toBe(-1);
  });

  it('adds webcredentials entries', () => {
    const out = addAssociatedDomains(
      { 'com.apple.developer.associated-domains': ['applinks:example.com'] },
      ['idp.example.com', 'webcredentials:idp.example.com']
    );
    expect(out['com.apple.developer.associated-domains']).toEqual([
      'applinks:example.com',
      'webcredentials:idp.example.com',
    ]);
  });

  it('registers its mods on an Expo config', () => {
    const config = plugin(
      { name: 'demo', slug: 'demo' },
      {
        redirectUri: 'demoapp://auth/callback',
        associatedDomains: ['idp.example.com'],
      }
    );
    expect(Object.keys(config.mods.android).sort()).toEqual([
      'gradleProperties',
      'mainActivity',
      'manifest',
    ]);
    expect(Object.keys(config.mods.ios).sort()).toEqual([
      'entitlements',
      'podfileProperties',
      'xcodeproj',
    ]);
  });
});
