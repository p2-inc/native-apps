#!/usr/bin/env bash
# Stamps a release version into the React Native module and the Flutter plugin before they are published
# (CONTRIBUTING "Releases"). Between releases the sources carry development versions (0.4.0-dev, 0.4.0-SNAPSHOT)
# and the Flutter plugin is marked publish_to: none, so nothing is published from main by accident. The publish
# workflow runs this on the release tag; it can also be run by hand for a first or manual publish.
#
#   scripts/set-wrapper-versions.sh 0.3.0
set -euo pipefail

version="${1:?usage: $0 <version>}"
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "not a semantic version: $version" >&2
  exit 1
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
flutter="$root/flutter/keycloak_native_flutter"
rn="$root/react-native/keycloak-native-react-native"

# Flutter: the package version, the publish guard, the Android SDK it builds against, and the Swift package it resolves.
sed -i.bak -E "s/^version: .*/version: $version/" "$flutter/pubspec.yaml"
sed -i.bak -E '/^# Not on pub.dev before/d; /^publish_to: none$/d' "$flutter/pubspec.yaml"
sed -i.bak -E "s/^version = \".*\"/version = \"$version\"/; s/^val keycloakNativeVersion = \".*\"/val keycloakNativeVersion = \"$version\"/" \
  "$flutter/android/build.gradle.kts"
sed -i.bak -E "s/^let sdkVersion = \".*\"/let sdkVersion = \"$version\"/" "$flutter/ios/keycloak_native_flutter/Package.swift"
sed -i.bak -E "s/^## .*-dev$/## $version/" "$flutter/CHANGELOG.md"

# React Native: the package version and the SDK release its podspec and Gradle build depend on.
tmp="$(mktemp)"
jq --arg v "$version" '.version = $v | .keycloakNativeSdkVersion = $v' "$rn/package.json" > "$tmp"
mv "$tmp" "$rn/package.json"

find "$flutter" -name '*.bak' -maxdepth 4 -delete

grep -q "^version: $version$" "$flutter/pubspec.yaml"
! grep -q '^publish_to:' "$flutter/pubspec.yaml"
grep -q "val keycloakNativeVersion = \"$version\"" "$flutter/android/build.gradle.kts"
grep -q "let sdkVersion = \"$version\"" "$flutter/ios/keycloak_native_flutter/Package.swift"
echo "Stamped $version into the Flutter plugin and the React Native module."
