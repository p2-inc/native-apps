# Example app

A React Native app that signs in to the demo realm of `keycloak-native-auth/demo` with the module's default screens, then shows the token, refreshes it, builds resource request headers and logs out.

Start the compose stack (`cd keycloak-native-auth/demo && docker compose up --wait`), then from `react-native/keycloak-native`: `yarn example start` and `yarn example android` or `yarn example ios`. The issuer defaults to `http://10.0.2.2:8080/realms/demo` on the Android emulator and `http://localhost:8080/realms/demo` on the iOS simulator; the client is `demo-native`.

Inside this repository the native SDKs are built from source: `android/settings.gradle` includes `../../../../android` as a composite build (which pins the example to the SDK's Android Gradle plugin 9.5.0 and Kotlin 2.4.21, and to Gradle 9.6.1, the line that runs both AGP 9.5 and React Native's Gradle plugin), and the pod resolves `KeycloakNativeCore` from the Swift package at the repository root.
