// React Native module for native authentication with Keycloak (spec/19). The native SDKs do the
// protocol, storage and platform ceremonies; this package exposes them to JavaScript with a typed
// challenge model and default React screens.

export {
  KeycloakNative,
  NativeLoginFlow,
  setNativeModuleForTesting,
  type DPoPMode,
  type FlowState,
  type KeycloakNativeConfig,
  type LoginParameters,
} from './KeycloakNative';
export * from './model';
export {
  LoginController,
  type LoginPhase,
  type LoginState,
  type NativeLoginResult,
} from './ui/LoginController';
export {
  NativeLoginScreen,
  type NativeLoginScreenProps,
} from './ui/NativeLoginScreen';
export {
  DefaultChallengeChooser,
  DefaultChallengeScreen,
  PasswordScreen,
  RedirectToWebScreen,
  TotpScreen,
  UnsupportedScreen,
  UsernameScreen,
  type ChallengeChooserProps,
  type ChallengePresentationProps,
  type ChallengePresenters,
} from './ui/DefaultScreens';
export { defaultStrings, type NativeLoginStrings } from './ui/strings';
export type { Spec as NativeKeycloakNativeSpec } from './NativeKeycloakNative';
