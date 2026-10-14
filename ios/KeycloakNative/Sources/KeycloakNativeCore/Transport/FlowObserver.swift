import Foundation

/// A redacted record of one exchange, for the example app's Diagnostics flow log (spec/06 §1) and
/// for apps that want to show "what happened". Values are masked by `Redactor` before this is built.
public struct FlowLogEntry: Sendable, Identifiable, Equatable {
  public let id: UUID
  public let timestamp: Date
  public let method: String
  public let url: URL
  public let requestHeaders: [String: String]
  /// Redacted form fields (`name=value`) or JSON for JSON bodies.
  public let requestBody: String?
  public let statusCode: Int?
  public let responseHeaders: [String: String]
  /// Redacted response JSON (pretty-printed) or a size note.
  public let responseBody: String?
  public let durationMilliseconds: Int
  /// `NativeAuthError.code` when the transport failed.
  public let errorCode: String?
}

/// Receives every exchange the SDK makes. Called off the main actor.
public protocol FlowObserver: Sendable {
  func record(_ entry: FlowLogEntry)
}

/// Wraps a transport, feeds the logger (debug) and the observer with redacted entries.
struct ObservingTransport: Transport {
  let base: any Transport
  let logger: any NativeAuthLogger
  let observer: (any FlowObserver)?

  func send(_ request: HTTPRequest) async throws -> HTTPResponse {
    let started = Date()
    logger.log(.debug, "→ \(Redactor.describe(request))")
    do {
      let response = try await base.send(request)
      logger.log(.debug, "← \(Redactor.describe(response))")
      observer?.record(entry(for: request, response: response, error: nil, started: started))
      return response
    } catch let error as NativeAuthError {
      logger.log(.warning, "✗ \(request.method) \(request.url.absoluteString): \(error.code)")
      observer?.record(entry(for: request, response: nil, error: error, started: started))
      throw error
    }
  }

  private func entry(for request: HTTPRequest, response: HTTPResponse?, error: NativeAuthError?, started: Date) -> FlowLogEntry {
    var requestBody: String?
    if let fields = request.formFields {
      requestBody = Redactor.redact(form: fields).map { "\($0.name)=\($0.value)" }.joined(separator: "\n")
    } else if let body = request.body {
      requestBody = JSONValue(jsonData: body).map { Redactor.redact(json: $0).serialized(prettyPrinted: true) } ?? "(\(body.count) bytes)"
    }
    var responseBody: String?
    if let response {
      responseBody = response.json.map { Redactor.redact(json: $0).serialized(prettyPrinted: true) }
        ?? (response.body.isEmpty ? nil : "(\(response.body.count) bytes)")
    }
    return FlowLogEntry(
      id: UUID(),
      timestamp: started,
      method: request.method,
      url: request.url,
      requestHeaders: Redactor.redact(headers: request.headers),
      requestBody: requestBody,
      statusCode: response?.statusCode,
      responseHeaders: response.map { Redactor.redact(headers: $0.headers) } ?? [:],
      responseBody: responseBody,
      durationMilliseconds: Int(Date().timeIntervalSince(started) * 1000),
      errorCode: error?.code)
  }
}
