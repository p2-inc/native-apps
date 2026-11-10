#import <KeycloakNativeSpec/KeycloakNativeSpec.h>

/// The TurboModule (spec/19 §4): conforms to the protocol Codegen generates from
/// src/NativeKeycloakNative.ts and forwards every call to the Swift KeycloakNativeBridge.
@interface KeycloakNativeModule : NSObject <NativeKeycloakNativeSpec>

@end
