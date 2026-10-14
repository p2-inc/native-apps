// Tiny resource server for the example app's step-up scenario (spec/06 S6, spec/13 D1).
// Validates the realm's access tokens (RS256 via JWKS, Bearer or DPoP-bound) and answers
//   GET /me        -> the token's claims
//   GET /transfer  -> 200 when acr >= 2, otherwise 401 insufficient_user_authentication (RFC 9470)
// No dependencies: Node 22's WebCrypto. Configure with ISSUER (as seen from this process) and
// ISSUER_PUBLIC (the iss the tokens carry, as seen by the app), PORT, REQUIRED_ACR.
import { createServer } from "node:http";
import { createHash, createPublicKey, verify as cryptoVerify, webcrypto } from "node:crypto";

const PORT = Number(process.env.PORT || 8091);
const ISSUER = process.env.ISSUER || "http://localhost:8089/realms/demo";
const ISSUER_PUBLIC = (process.env.ISSUER_PUBLIC || ISSUER).split(",");
const REQUIRED_ACR = Number(process.env.REQUIRED_ACR || 2);

const b64url = (buf) => Buffer.from(buf).toString("base64url");
const decode = (s) => JSON.parse(Buffer.from(s, "base64url").toString("utf8"));

let jwks = { keys: [], fetchedAt: 0 };
async function keyFor(kid) {
  if (!jwks.keys.find((k) => k.kid === kid) || Date.now() - jwks.fetchedAt > 300_000) {
    const res = await fetch(`${ISSUER}/protocol/openid-connect/certs`);
    jwks = { ...(await res.json()), fetchedAt: Date.now() };
  }
  const jwk = jwks.keys.find((k) => k.kid === kid);
  return jwk ? createPublicKey({ key: jwk, format: "jwk" }) : null;
}

async function verifyJwt(token) {
  const [h, p, s] = token.split(".");
  if (!s) throw new Error("not a JWT");
  const header = decode(h);
  const payload = decode(p);
  const key = await keyFor(header.kid);
  if (!key) throw new Error("unknown kid");
  const algo = { RS256: "sha256", RS384: "sha384", RS512: "sha512" }[header.alg];
  if (!algo) throw new Error(`unsupported alg ${header.alg}`);
  if (!cryptoVerify(algo, Buffer.from(`${h}.${p}`), key, Buffer.from(s, "base64url"))) throw new Error("bad signature");
  if (!ISSUER_PUBLIC.includes(payload.iss)) throw new Error(`unexpected iss ${payload.iss}`);
  if (payload.exp * 1000 < Date.now()) throw new Error("expired");
  return payload;
}

// RFC 9449 §4.3 for a resource server: typ, alg, jwk, htm, htu, iat, ath, and jwk thumbprint == cnf.jkt.
async function verifyDPoP(proof, method, url, accessToken, jkt) {
  const [h, p, s] = proof.split(".");
  const header = decode(h);
  const payload = decode(p);
  if (header.typ !== "dpop+jwt") throw new Error("typ");
  if (header.alg !== "ES256" || !header.jwk) throw new Error("alg/jwk");
  const key = await webcrypto.subtle.importKey("jwk", header.jwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
  const ok = await webcrypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, Buffer.from(s, "base64url"), Buffer.from(`${h}.${p}`));
  if (!ok) throw new Error("proof signature");
  if (payload.htm !== method) throw new Error("htm");
  if (payload.htu !== url) throw new Error(`htu ${payload.htu} != ${url}`);
  if (Math.abs(Date.now() / 1000 - payload.iat) > 300) throw new Error("iat");
  if (payload.ath !== b64url(createHash("sha256").update(accessToken).digest())) throw new Error("ath");
  const canonical = JSON.stringify({ crv: header.jwk.crv, kty: header.jwk.kty, x: header.jwk.x, y: header.jwk.y });
  if (b64url(createHash("sha256").update(canonical).digest()) !== jkt) throw new Error("jkt");
}

function json(res, status, body, headers = {}) {
  res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers });
  res.end(JSON.stringify(body));
}

createServer(async (req, res) => {
  const url = `${process.env.PUBLIC_BASE || `http://localhost:${PORT}`}${req.url.split("?")[0]}`;
  try {
    const auth = req.headers.authorization || "";
    const [scheme, token] = auth.split(" ");
    if (!token) return json(res, 401, { error: "invalid_token", error_description: "missing token" }, { "WWW-Authenticate": 'Bearer realm="demo"' });
    const claims = await verifyJwt(token);
    if (claims.cnf?.jkt) {
      if (scheme !== "DPoP") throw new Error("DPoP-bound token sent with Bearer");
      await verifyDPoP(req.headers.dpop || "", req.method, url, token, claims.cnf.jkt);
    } else if (scheme !== "Bearer") {
      throw new Error("unexpected scheme");
    }
    if (req.url.startsWith("/me")) return json(res, 200, { sub: claims.sub, preferred_username: claims.preferred_username, acr: claims.acr, auth_time: claims.auth_time, sid: claims.sid, bound: !!claims.cnf?.jkt });
    if (req.url.startsWith("/transfer")) {
      const acr = Number(claims.acr || 0);
      if (!(acr >= REQUIRED_ACR)) {
        // RFC 9470 step-up challenge: the app answers with Authentication.stepUp(acrValues: "2").
        return json(res, 401, { error: "insufficient_user_authentication", error_description: `acr ${claims.acr ?? "none"} < ${REQUIRED_ACR}`, acr_values: String(REQUIRED_ACR) },
          { "WWW-Authenticate": `${scheme} error="insufficient_user_authentication", error_description="A stronger authentication is required", acr_values="${REQUIRED_ACR}"` });
      }
      return json(res, 200, { status: "transferred", amount: 42, acr: claims.acr, preferred_username: claims.preferred_username });
    }
    json(res, 404, { error: "not_found" });
  } catch (e) {
    json(res, 401, { error: "invalid_token", error_description: String(e.message || e) }, { "WWW-Authenticate": `Bearer error="invalid_token", error_description="${String(e.message || e).replace(/"/g, "'")}"` });
  }
}).listen(PORT, () => console.log(`resource server on :${PORT}, issuer ${ISSUER}, /transfer requires acr>=${REQUIRED_ACR}`));
