# Contributing

Issues and pull requests are welcome. For a larger change, open an issue first so we can agree on the approach before you write the code. Phase Two customers with a support agreement can also raise questions through support.

## Licensing of contributions

The repository has two licenses (see the [README](README.md#-license)). A contribution is licensed under the license that covers the files it changes: Apache 2.0 for the SDKs, `spec/`, `docs/` and the recorded transcripts, and the Elastic License 2.0 for the Keycloak extensions in `keycloak-native-auth/`. By opening a pull request you confirm that you have the right to contribute the code under that license.

## Making a change

- Builds, tests and the local Keycloak stack are described in [Development and troubleshooting](docs/development-and-troubleshooting.md). CI runs the jobs for the parts a pull request changes: the extension integration tests on Keycloak 26.4, 26.6 and 26.8, the Swift package tests on macOS, the Android builds and tests, and the Flutter and React Native tests and example builds. A change to the recorded transcripts or to the workflow runs everything. The required check is `CI passed`.
- The wire protocol is the contract between the server and both SDKs. A change to it updates `spec/03-protocol-spec.md` and the recorded transcripts in `keycloak-native-auth/demo/transcripts/`, which every SDK replays in its tests.
- A behavior that exists on both platforms changes on both, or the pull request says which platform follows.
- Use American English, and keep prose in Markdown files unwrapped (one line per paragraph).

## Releases

One version line covers the server extensions and every SDK, because SwiftPM reads versions from plain tags on this repository. Releases are tags without a prefix (`0.3.0`, not `v0.3.0`), marked as pre-releases while the version is below 1.0. Below 1.0 any release may change the protocol or the API ([semantic versioning](https://semver.org/#spec-item-4)), so consumers pin exact versions.

To cut a release from `main`, run `gh release create <version> --target main --prerelease --generate-notes`. Publishing the release starts the [release workflow](.github/workflows/release.yml), which builds the tag and:

- attaches `keycloak-native-auth-providers-<version>.zip`, the provider jars for Keycloak's `providers/` directory;
- attaches `keycloak-native-android-<version>-maven-repo.zip`, the Android SDK as a Maven repository (group `io.phasetwo.keycloak.nativeauth`, artifacts `keycloak-native-core`, `-android`, `-ui` and `-push`);
- signs the Android libraries with the org's release key and publishes them to Maven Central. Central keeps every version permanently, so a published version can only be superseded, never replaced.

The tag push also starts the [wrapper publish workflow](.github/workflows/publish-wrappers.yml), which stamps the version into the React Native module and the Flutter plugin with `scripts/set-wrapper-versions.sh` and publishes them to npm (`@phasetwo.io/keycloak-native-react-native`) and pub.dev (`keycloak_native_flutter`, under the phasetwo.io publisher). Both registries trust the workflow through GitHub's OIDC token, so there are no registry secrets. The script turns the `-dev` heading of `flutter/keycloak_native_flutter/CHANGELOG.md` into the release version, so fill in that section before tagging.

Then open a pull request that sets the next development version: in `keycloak-native-auth` (`mvn -f keycloak-native-auth versions:set -DnewVersion=<next>-SNAPSHOT -DgenerateBackupPoms=false`), `android/build.gradle.kts`, `flutter/keycloak_native_flutter/android/build.gradle.kts` (`<next>-SNAPSHOT`), `flutter/keycloak_native_flutter/pubspec.yaml` and `react-native/keycloak-native-react-native/package.json` (`<next>-dev`), with a new `<next>-dev` heading in the Flutter changelog. The Keycloak provider modules aren't published to a Maven repository.
