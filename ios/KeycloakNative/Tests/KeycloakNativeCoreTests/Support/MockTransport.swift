import Foundation
@testable import KeycloakNativeCore

/// Replays transcript exchanges in order. Every request the SDK sends must match the next recorded
/// request: same method and path, the same form field names, and the same values except for masked
/// (`***`) and per-run fields. Mismatches are thrown as `Mismatch` so the test fails with a message.
final class MockTransport: Transport, @unchecked Sendable {
  struct Mismatch: Error, CustomStringConvertible {
    let description: String
  }

  /// Fields whose value legitimately differs per run (PKCE, device ids) — presence is still required.
  static let volatileFormFields: Set<String> = ["code_challenge", "device_id", "nonce"]

  private let lock = NSLock()
  private var queue: [Transcript.Exchange]
  private(set) var sent: [HTTPRequest] = []

  init(_ exchanges: [Transcript.Exchange]) {
    queue = exchanges
  }

  convenience init(transcripts: [Transcript]) {
    self.init(transcripts.flatMap(\.exchanges))
  }

  var remaining: Int { lock.withLock { queue.count } }

  func send(_ request: HTTPRequest) async throws -> HTTPResponse {
    let expected: Transcript.Exchange? = lock.withLock {
      sent.append(request)
      return queue.isEmpty ? nil : queue.removeFirst()
    }
    guard let expected else {
      throw Mismatch(description: "unexpected request \(request.method) \(request.url.path): transcript exhausted")
    }
    try MockTransport.match(request, against: expected.request, seq: expected.seq)
    return expected.response.httpResponse
  }

  static func match(_ actual: HTTPRequest, against expected: Transcript.Request, seq: Int) throws {
    let prefix = "exchange #\(seq) \(expected.method) \(expected.path): "
    guard actual.method == expected.method, actual.url.path == expected.path else {
      throw Mismatch(description: prefix + "SDK sent \(actual.method) \(actual.url.path)")
    }
    if let authorization = expected.headers?["Authorization"] {
      let scheme = authorization.split(separator: " ").first.map(String.init) ?? ""
      guard let sent = actual.header("Authorization"), sent.hasPrefix(scheme + " ") else {
        throw Mismatch(description: prefix + "expected an Authorization header with scheme \(scheme)")
      }
    }
    if let form = expected.form {
      guard let fields = actual.formFields else {
        throw Mismatch(description: prefix + "expected a form body")
      }
      let actualForm = Dictionary(fields.map { ($0.name, $0.value) }, uniquingKeysWith: { a, _ in a })
      for (name, value) in form {
        guard let sent = actualForm[name] else {
          throw Mismatch(description: prefix + "missing form field \(name)")
        }
        if value == "***" || volatileFormFields.contains(name) { continue }
        guard sent == value else {
          throw Mismatch(description: prefix + "field \(name): SDK sent '\(Redactor.isSensitive(name) ? "***" : sent)', recorded '\(Redactor.isSensitive(name) ? "***" : value)'")
        }
      }
      let extra = Set(actualForm.keys).subtracting(form.keys)
      guard extra.isEmpty else {
        throw Mismatch(description: prefix + "SDK sent fields the test did not: \(extra.sorted())")
      }
    }
    if let json = expected.json?.objectValue {
      guard let body = actual.body, let actualJSON = JSONValue(jsonData: body)?.objectValue else {
        throw Mismatch(description: prefix + "expected a JSON body")
      }
      for (key, value) in json {
        guard let sent = actualJSON[key] else {
          throw Mismatch(description: prefix + "missing JSON field \(key)")
        }
        if key == "transports", let recorded = value.stringValue, let sentArray = sent.stringArray {
          guard sentArray.joined(separator: ",") == recorded else {
            throw Mismatch(description: prefix + "transports differ")
          }
          continue
        }
        guard sent == value else {
          throw Mismatch(description: prefix + "JSON field \(key) differs")
        }
      }
    }
  }
}

/// Closure-driven transport for hand-written cases.
final class ScriptedTransport: Transport, @unchecked Sendable {
  private let lock = NSLock()
  private var handlers: [(HTTPRequest) throws -> HTTPResponse]
  private(set) var sent: [HTTPRequest] = []

  init(_ handlers: [(HTTPRequest) throws -> HTTPResponse]) {
    self.handlers = handlers
  }

  convenience init(_ handler: @escaping (HTTPRequest) throws -> HTTPResponse) {
    self.init([handler])
  }

  func send(_ request: HTTPRequest) async throws -> HTTPResponse {
    let handler: ((HTTPRequest) throws -> HTTPResponse)? = lock.withLock {
      sent.append(request)
      if handlers.count > 1 { return handlers.removeFirst() }
      return handlers.first
    }
    guard let handler else {
      throw MockTransport.Mismatch(description: "no handler for \(request.method) \(request.url)")
    }
    return try handler(request)
  }

  static func json(_ status: Int, _ json: JSONValue, headers: [String: String] = [:]) -> HTTPResponse {
    var h = headers
    h["Content-Type"] = "application/json"
    return HTTPResponse(statusCode: status, headers: h, body: Data(json.serialized().utf8))
  }
}

final class CapturingObserver: FlowObserver, @unchecked Sendable {
  private let lock = NSLock()
  private var items: [FlowLogEntry] = []
  func record(_ entry: FlowLogEntry) { lock.withLock { items.append(entry) } }
  var entries: [FlowLogEntry] { lock.withLock { items } }
}

final class CapturingLogger: NativeAuthLogger, @unchecked Sendable {
  private let lock = NSLock()
  private var items: [(LogLevel, String)] = []
  func log(_ level: LogLevel, _ message: @autoclosure () -> String) {
    let text = message()
    lock.withLock { items.append((level, text)) }
  }
  var lines: [String] { lock.withLock { items.map(\.1) } }
}
