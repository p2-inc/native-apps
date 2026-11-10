import 'dart:convert';

/// Tokens from the realm's token endpoint (spec/05 §6). The refresh token and the post-login
/// `auth_session` stay in the native SDK; [hasRefreshToken] says whether there is one.
final class Credentials {
  const Credentials({
    required this.accessToken,
    required this.tokenType,
    required this.expiresAt,
    required this.issuedAt,
    this.idToken,
    this.scope,
    this.refreshExpiresAt,
    this.hasRefreshToken = false,
    this.handle,
  });

  final String accessToken;

  /// `Bearer`, or `DPoP` when the server bound the token to the SDK's key.
  final String tokenType;
  final String? idToken;
  final String? scope;
  final DateTime expiresAt;
  final DateTime? refreshExpiresAt;
  final DateTime issuedAt;
  final bool hasRefreshToken;

  /// Names the native credentials a flow produced, until `CredentialsManager.store` keeps them;
  /// `null` for credentials read from the store.
  final String? handle;

  bool isExpired({DateTime? at, Duration leeway = Duration.zero}) => !(at ?? DateTime.now()).add(leeway).isBefore(expiresAt);

  /// Scheme for the `Authorization` header of resource requests; `CredentialsManager.resourceRequestHeaders`
  /// adds the DPoP proof a bound token needs.
  String get authorizationScheme => tokenType.toLowerCase() == 'dpop' ? 'DPoP' : 'Bearer';

  bool get isDPoPBound => authorizationScheme == 'DPoP';

  /// Unverified claims, for display only.
  Map<String, Object?>? get idTokenClaims => idToken == null ? null : decodeJwtPayload(idToken!);
  Map<String, Object?>? get accessTokenClaims => decodeJwtPayload(accessToken);

  /// Never prints a token.
  @override
  String toString() => 'Credentials(tokenType=$tokenType, expiresAt=$expiresAt, scope=$scope)';
}

/// The payload of a JWT without verifying it; `null` when it is not a JWT.
Map<String, Object?>? decodeJwtPayload(String jwt) {
  final parts = jwt.split('.');
  if (parts.length < 2) return null;
  try {
    final decoded = jsonDecode(utf8.decode(base64Url.decode(base64Url.normalize(parts[1]))));
    return decoded is Map ? decoded.cast<String, Object?>() : null;
  } on FormatException {
    return null;
  }
}
