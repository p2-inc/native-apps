import Foundation

/// One HTTP request as the SDK builds it. `headers` are sent verbatim; `body` is already encoded.
public struct HTTPRequest: Sendable, Equatable {
  public var method: String
  public var url: URL
  public var headers: [String: String]
  public var body: Data?

  public init(method: String, url: URL, headers: [String: String] = [:], body: Data? = nil) {
    self.method = method
    self.url = url
    self.headers = headers
    self.body = body
  }

  /// The URL-encoded form fields when `body` is `application/x-www-form-urlencoded` (used by the
  /// logger and tests).
  public var formFields: [(name: String, value: String)]? {
    guard let body, (header("Content-Type") ?? "").lowercased().hasPrefix("application/x-www-form-urlencoded") else {
      return nil
    }
    return FormEncoding.decode(body)
  }

  public func header(_ name: String) -> String? {
    headers.first { $0.key.caseInsensitiveCompare(name) == .orderedSame }?.value
  }
}

/// One HTTP response. Header names are matched case-insensitively through `header(_:)`.
public struct HTTPResponse: Sendable, Equatable {
  public var statusCode: Int
  public var headers: [String: String]
  public var body: Data

  public init(statusCode: Int, headers: [String: String] = [:], body: Data = Data()) {
    self.statusCode = statusCode
    self.headers = headers
    self.body = body
  }

  public func header(_ name: String) -> String? {
    headers.first { $0.key.caseInsensitiveCompare(name) == .orderedSame }?.value
  }

  public var json: JSONValue? { JSONValue(jsonData: body) }

  /// RFC 9449 §8: the server wants a fresh nonce in the proof (`400`/`401 use_dpop_nonce` with a
  /// `DPoP-Nonce` header). Modules outside Core retry the request with it.
  public var dpopNonceChallenge: String? {
    guard statusCode == 400 || statusCode == 401, json?["error"]?.stringValue == "use_dpop_nonce" else { return nil }
    return header("DPoP-Nonce")
  }
}

/// Transport abstraction: production uses `URLSessionTransport`; tests replay recorded transcripts.
public protocol Transport: Sendable {
  func send(_ request: HTTPRequest) async throws -> HTTPResponse
}

/// `URLSession`-backed transport. Network failures become `NativeAuthError` with `code ==
/// network_error`; HTTP status codes are never turned into errors here.
public struct URLSessionTransport: Transport {
  private let session: URLSession

  public init(session: URLSession = URLSessionTransport.defaultSession()) {
    self.session = session
  }

  /// Ephemeral configuration: no cookies, no cache, nothing persisted to disk.
  public static func defaultSession() -> URLSession {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.httpCookieAcceptPolicy = .never
    configuration.httpShouldSetCookies = false
    configuration.urlCache = nil
    configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
    configuration.timeoutIntervalForRequest = 30
    configuration.waitsForConnectivity = false
    return URLSession(configuration: configuration)
  }

  public func send(_ request: HTTPRequest) async throws -> HTTPResponse {
    var urlRequest = URLRequest(url: request.url)
    urlRequest.httpMethod = request.method
    urlRequest.httpBody = request.body
    for (name, value) in request.headers {
      urlRequest.setValue(value, forHTTPHeaderField: name)
    }
    let data: Data
    let response: URLResponse
    do {
      (data, response) = try await session.data(for: urlRequest)
    } catch {
      throw NativeAuthError.network(error)
    }
    guard let http = response as? HTTPURLResponse else {
      throw NativeAuthError(code: NativeAuthError.Code.invalidResponse, description: "Not an HTTP response")
    }
    var headers: [String: String] = [:]
    for (name, value) in http.allHeaderFields {
      if let name = name as? String, let value = value as? String { headers[name] = value }
    }
    return HTTPResponse(statusCode: http.statusCode, headers: headers, body: data)
  }
}

/// `application/x-www-form-urlencoded` encoding with the RFC 3986 unreserved set (space → `%20`).
public enum FormEncoding {
  public static let contentType = "application/x-www-form-urlencoded; charset=utf-8"

  private static let unreserved: CharacterSet = {
    var set = CharacterSet.alphanumerics
    set.insert(charactersIn: "-._~")
    return set
  }()

  public static func encode(_ fields: [(name: String, value: String)]) -> Data {
    let text = fields.map { "\(escape($0.name))=\(escape($0.value))" }.joined(separator: "&")
    return Data(text.utf8)
  }

  public static func escape(_ value: String) -> String {
    value.addingPercentEncoding(withAllowedCharacters: unreserved) ?? value
  }

  public static func decode(_ data: Data) -> [(name: String, value: String)] {
    guard let text = String(data: data, encoding: .utf8), !text.isEmpty else { return [] }
    return text.split(separator: "&", omittingEmptySubsequences: true).map { pair in
      let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
      let name = unescape(String(parts[0]))
      let value = parts.count > 1 ? unescape(String(parts[1])) : ""
      return (name, value)
    }
  }

  private static func unescape(_ value: String) -> String {
    value.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? value
  }
}
