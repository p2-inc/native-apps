# Contributing

Issues and pull requests are welcome. For a larger change, open an issue first so we can agree on the approach before you write the code. Phase Two customers with a support agreement can also raise questions through support.

## Licensing of contributions

The repository has two licenses (see the [README](README.md#license)). A contribution is licensed under the license that covers the files it changes: Apache 2.0 for the SDKs, `spec/`, `docs/` and the recorded transcripts, and the Elastic License 2.0 for the Keycloak extensions in `keycloak-native-auth/`. By opening a pull request you confirm that you have the right to contribute the code under that license.

## Making a change

- Builds, tests and the local Keycloak stack are described in [Development and troubleshooting](docs/development-and-troubleshooting.md). CI runs the extension integration tests on Keycloak 26.4, 26.6 and 26.8, the Swift package tests on macOS and the Android builds and tests; a pull request needs all of them to pass.
- The wire protocol is the contract between the server and both SDKs. A change to it updates `spec/03-protocol-spec.md` and the recorded transcripts in `keycloak-native-auth/demo/transcripts/`, which both SDKs replay in their tests.
- A behavior that exists on both platforms changes on both, or the pull request says which platform follows.
- Use American English, and keep prose in Markdown files unwrapped (one line per paragraph).
