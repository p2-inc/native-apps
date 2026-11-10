#!/usr/bin/env bash
# Builds the example app's screens on the oldest supported React Native release (spec/19 §8 "Floor"):
# a fresh app from that release's template, the module installed from `npm pack` (as from npm), the
# Android SDK from a local Maven repository and the Swift package from this checkout.
#
#   scripts/floor-build.sh [android|ios|all] [work-dir]
#
# Needs Node and Yarn (as for the module), JDK 21, the Android SDK (ANDROID_HOME) for android, and
# Xcode with CocoaPods for ios. Exits non-zero when a build fails.
set -euo pipefail

RN_VERSION="${RN_VERSION:-0.84.1}"
CLI_VERSION="${CLI_VERSION:-20.1.3}"
PLATFORM="${1:-all}"
MODULE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$MODULE_DIR/../.." && pwd)"
WORK="${2:-$(mktemp -d)}"
APP=RNFloor
mkdir -p "$WORK"
echo "React Native $RN_VERSION in $WORK/$APP"

# The module as npm users get it.
(cd "$MODULE_DIR" && yarn install --immutable && yarn prepare && npm pack --pack-destination "$WORK")
TARBALL="$(ls "$WORK"/*keycloak-native-react-native-*.tgz | head -1)"

# The SDK artifacts: this checkout's SDK published to a local Maven repository, or KEYCLOAK_NATIVE_MAVEN_REPO.
if [ -z "${KEYCLOAK_NATIVE_MAVEN_REPO:-}" ]; then
  (cd "$REPO_ROOT/android" && ./gradlew --no-daemon --console=plain :core:publishAllPublicationsToReleaseRepository :android:publishAllPublicationsToReleaseRepository)
fi
MAVEN_REPO="${KEYCLOAK_NATIVE_MAVEN_REPO:-$REPO_ROOT/android/build/maven-repo}"
SDK_VERSION="$(ls "$MAVEN_REPO/io/phasetwo/keycloak/nativeauth/keycloak-native-android" | grep -v '^maven-metadata' | head -1)"

cd "$WORK"
rm -rf "$APP"
npx -y "@react-native-community/cli@$CLI_VERSION" init "$APP" --version "$RN_VERSION" --skip-git-init --install-pods false --pm npm
cd "$APP"
npm install "$TARBALL"
cp "$MODULE_DIR/example/src/App.tsx" App.tsx

python3 - "$MAVEN_REPO" "$SDK_VERSION" <<'EOF'
import re, sys
repo, version = sys.argv[1], sys.argv[2]
p = 'android/build.gradle'
s = open(p).read()
# The SDK's floors: minSdk 28 and Kotlin 2.2 (the template has 24 and, before 0.87, Kotlin 2.1).
s = re.sub(r'minSdkVersion = \d+', 'minSdkVersion = 28', s)
s = re.sub(r'kotlinVersion = "[^"]+"', 'kotlinVersion = "2.2.20"', s)
s = s.replace('classpath("org.jetbrains.kotlin:kotlin-gradle-plugin")', 'classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlinVersion")')
s = s.replace('    }\n    repositories {', f'        keycloakNativeVersion = "{version}"\n    }}\n    repositories {{', 1)
s += f'\nallprojects {{\n    repositories {{\n        maven {{ url = uri("{repo}") }}\n    }}\n}}\n'
open(p, 'w').write(s)
# The browser fallback: register in MainActivity, declare the redirect activity.
import glob
p = glob.glob('android/app/src/main/java/**/MainActivity.kt', recursive=True)[0]
s = open(p).read()
s = s.replace('import com.facebook.react.ReactActivity\n', 'import android.os.Bundle\nimport com.facebook.react.ReactActivity\nimport io.phasetwo.keycloak.nativeauth.reactnative.KeycloakNativeActivity\n')
s = re.sub(r'(class MainActivity : ReactActivity\(\) \{\n)', r'\1  override fun onCreate(savedInstanceState: Bundle?) {\n    super.onCreate(savedInstanceState)\n    KeycloakNativeActivity.register(this)\n  }\n', s)
open(p, 'w').write(s)
p = 'android/app/src/main/AndroidManifest.xml'
s = open(p).read()
s = s.replace('    </application>', '''      <activity android:name="io.phasetwo.keycloak.nativeauth.sdk.android.NativeAuthRedirectActivity" android:exported="true" android:theme="@android:style/Theme.Translucent.NoTitleBar">
        <intent-filter>
          <action android:name="android.intent.action.VIEW" />
          <category android:name="android.intent.category.DEFAULT" />
          <category android:name="android.intent.category.BROWSABLE" />
          <data android:scheme="demoapp" android:host="auth" android:path="/callback" />
        </intent-filter>
      </activity>
    </application>''')
open(p, 'w').write(s)
# iOS 17.
p = 'ios/Podfile'
s = open(p).read()
s = s.replace('platform :ios, min_ios_version_supported', "platform :ios, '17.0'")
open(p, 'w').write(s)
for p in glob.glob('ios/*.xcodeproj/project.pbxproj'):
    s = open(p).read()
    s = re.sub(r'IPHONEOS_DEPLOYMENT_TARGET = [\d.]+;', 'IPHONEOS_DEPLOYMENT_TARGET = 17.0;', s)
    open(p, 'w').write(s)
EOF

if [ "$PLATFORM" = android ] || [ "$PLATFORM" = all ]; then
  (cd android && ./gradlew --no-daemon --console=plain :app:assembleDebug -PreactNativeArchitectures=arm64-v8a)
fi
if [ "$PLATFORM" = ios ] || [ "$PLATFORM" = all ]; then
  (cd ios && KEYCLOAK_NATIVE_SPM_PATH="$REPO_ROOT" LANG=en_US.UTF-8 pod install)
  (cd ios && xcodebuild -workspace "$APP.xcworkspace" -scheme "$APP" -configuration Debug -sdk iphonesimulator \
    -destination 'generic/platform=iOS Simulator' -derivedDataPath build/dd build CODE_SIGNING_ALLOWED=NO)
fi
echo "Floor build on React Native $RN_VERSION succeeded"
