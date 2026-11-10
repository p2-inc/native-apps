#import "KeycloakNativeModule.h"

// The Swift half of the module (KeycloakNativeBridge.swift), through the pod's generated header.
#if __has_include("KeycloakNativeReactNative/KeycloakNativeReactNative-Swift.h")
#import "KeycloakNativeReactNative/KeycloakNativeReactNative-Swift.h"
#else
#import "KeycloakNativeReactNative-Swift.h"
#endif

@implementation KeycloakNativeModule {
  KeycloakNativeBridge *_bridge;
}

- (instancetype)init
{
  if (self = [super init]) {
    _bridge = [KeycloakNativeBridge new];
  }
  return self;
}

+ (NSString *)moduleName
{
  return @"KeycloakNative";
}

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
  return std::make_shared<facebook::react::NativeKeycloakNativeSpecJSI>(params);
}

- (void)configure:(NSString *)instanceId config:(NSString *)config resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge configure:instanceId config:config resolve:resolve reject:reject];
}

- (void)createFlow:(NSString *)instanceId parameters:(NSString *)parameters stepUp:(BOOL)stepUp resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge createFlow:instanceId parameters:parameters stepUp:stepUp resolve:resolve reject:reject];
}

- (void)start:(NSString *)flowId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge start:flowId resolve:resolve reject:reject];
}

- (void)respond:(NSString *)flowId challengeId:(NSString *)challengeId challengeType:(NSString *)challengeType answer:(NSString *)answer additionalFields:(NSString *)additionalFields resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge respond:flowId challengeId:challengeId challengeType:challengeType answer:answer additionalFields:additionalFields resolve:resolve reject:reject];
}

- (void)respondWithPasskey:(NSString *)flowId challengeId:(NSString *)challengeId preferImmediatelyAvailableCredentials:(BOOL)preferImmediatelyAvailableCredentials resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge respondWithPasskey:flowId challengeId:challengeId preferImmediatelyAvailableCredentials:preferImmediatelyAvailableCredentials resolve:resolve reject:reject];
}

- (void)respondWithPasskeyRegistration:(NSString *)flowId challengeId:(NSString *)challengeId label:(NSString *)label resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge respondWithPasskeyRegistration:flowId challengeId:challengeId label:label resolve:resolve reject:reject];
}

- (void)respondWithPushEnrollment:(NSString *)flowId challengeId:(NSString *)challengeId deviceLabel:(NSString *)deviceLabel pushProviderType:(NSString *)pushProviderType pushProviderId:(NSString *)pushProviderId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge respondWithPushEnrollment:flowId challengeId:challengeId deviceLabel:deviceLabel pushProviderType:pushProviderType pushProviderId:pushProviderId resolve:resolve reject:reject];
}

- (void)cancel:(NSString *)flowId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge cancel:flowId resolve:resolve reject:reject];
}

- (void)completeWebFallback:(NSString *)flowId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge completeWebFallback:flowId resolve:resolve reject:reject];
}

- (void)storeCredentials:(NSString *)flowId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge storeCredentials:flowId resolve:resolve reject:reject];
}

- (void)releaseFlow:(NSString *)flowId
{
  [_bridge releaseFlow:flowId];
}

- (void)credentials:(NSString *)instanceId minTtlSeconds:(double)minTtlSeconds resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge credentials:instanceId minTtlSeconds:minTtlSeconds resolve:resolve reject:reject];
}

- (void)storedCredentials:(NSString *)instanceId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge storedCredentials:instanceId resolve:resolve reject:reject];
}

- (void)hasValidCredentials:(NSString *)instanceId minTtlSeconds:(double)minTtlSeconds resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge hasValidCredentials:instanceId minTtlSeconds:minTtlSeconds resolve:resolve reject:reject];
}

- (void)resourceRequestHeaders:(NSString *)instanceId method:(NSString *)method url:(NSString *)url resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge resourceRequestHeaders:instanceId method:method url:url resolve:resolve reject:reject];
}

- (void)logout:(NSString *)instanceId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge logout:instanceId resolve:resolve reject:reject];
}

- (void)clearCredentials:(NSString *)instanceId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge clearCredentials:instanceId resolve:resolve reject:reject];
}

- (void)metadata:(NSString *)instanceId forceRefresh:(BOOL)forceRefresh resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge metadata:instanceId forceRefresh:forceRefresh resolve:resolve reject:reject];
}

- (void)dpopKeyThumbprint:(NSString *)instanceId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge dpopKeyThumbprint:instanceId resolve:resolve reject:reject];
}

- (void)pickSavedPassword:(NSString *)instanceId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge pickSavedPassword:instanceId resolve:resolve reject:reject];
}

- (void)savePassword:(NSString *)instanceId username:(NSString *)username password:(NSString *)password resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge savePassword:instanceId username:username password:password resolve:resolve reject:reject];
}

- (void)registerNewPasskey:(NSString *)instanceId label:(NSString *)label resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge registerNewPasskey:instanceId label:label resolve:resolve reject:reject];
}

- (void)pushEnrollment:(NSString *)instanceId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge pushEnrollment:instanceId resolve:resolve reject:reject];
}

- (void)pushEnroll:(NSString *)instanceId deviceLabel:(NSString *)deviceLabel pushProviderType:(NSString *)pushProviderType pushProviderId:(NSString *)pushProviderId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge pushEnroll:instanceId deviceLabel:deviceLabel pushProviderType:pushProviderType pushProviderId:pushProviderId resolve:resolve reject:reject];
}

- (void)pushForgetEnrollment:(NSString *)instanceId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge pushForgetEnrollment:instanceId resolve:resolve reject:reject];
}

- (void)pushPendingApprovals:(NSString *)instanceId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge pushPendingApprovals:instanceId resolve:resolve reject:reject];
}

- (void)pushRespond:(NSString *)instanceId cid:(NSString *)cid action:(NSString *)action userVerification:(NSString *)userVerification resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge pushRespond:instanceId cid:cid action:action userVerification:userVerification resolve:resolve reject:reject];
}

- (void)pushHandleMessage:(NSString *)instanceId data:(NSString *)data resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge pushHandleMessage:instanceId data:data resolve:resolve reject:reject];
}

- (void)pushUpdateProvider:(NSString *)instanceId pushProviderType:(NSString *)pushProviderType pushProviderId:(NSString *)pushProviderId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge pushUpdateProvider:instanceId pushProviderType:pushProviderType pushProviderId:pushProviderId resolve:resolve reject:reject];
}

- (void)pushRotateKey:(NSString *)instanceId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge pushRotateKey:instanceId resolve:resolve reject:reject];
}

- (void)pushLockout:(NSString *)instanceId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge pushLockout:instanceId resolve:resolve reject:reject];
}

@end
