import KeycloakNativeCore
import SwiftUI

/// Redacted request/response log (spec/06 §1 FlowLogView): what the SDK sent and received, with
/// secrets masked by the SDK before the entries reach the app.
struct DiagnosticsView: View {
  @Environment(DemoModel.self) private var model

  var body: some View {
    List {
      Section("Server") {
        if let metadata = model.metadata {
          LabeledContent("protocol_version", value: metadata.protocolVersion)
          LabeledContent("challenge_types_supported", value: metadata.challengeTypesSupported.joined(separator: ", "))
          LabeledContent("passkey.rp_id", value: metadata.passkey?.rpId ?? "—")
          LabeledContent("redirect_uri_required", value: metadata.codeExchange.redirectUriRequired ? "true" : "false")
          LabeledContent("dpop_signing_alg_values_supported", value: metadata.dpopSigningAlgValuesSupported.isEmpty ? "[] (server does not bind auth_session yet)" : metadata.dpopSigningAlgValuesSupported.joined(separator: ", "))
        }
        LabeledContent("DPoP key (jkt)", value: model.dpopThumbprint ?? "—").font(.footnote.monospaced())
          .accessibilityIdentifier("dpopJkt")
        Button("Load metadata") { Task { await model.loadDiagnostics() } }
      }
      Section {
        HStack {
          Text("Flow log (\(model.flowLog.count))")
          Spacer()
          Button("Copy") { copy(model.flowLog.map(describe).joined(separator: "\n\n")) }
          Button("Clear") { model.clearLog() }
        }
        ForEach(model.flowLog.reversed()) { entry in
          DisclosureGroup {
            Text(describe(entry)).font(.caption.monospaced()).textSelection(.enabled)
          } label: {
            HStack {
              Text("\(entry.method) \(entry.url.path)").font(.footnote.monospaced()).lineLimit(1)
              Spacer()
              Text(entry.statusCode.map(String.init) ?? entry.errorCode ?? "?")
                .font(.footnote.bold())
                .foregroundStyle((entry.statusCode ?? 500) < 400 ? Color.green : Color.orange)
              Text("\(entry.durationMilliseconds) ms").font(.caption2).foregroundStyle(.secondary)
            }
          }
        }
      }
    }
    .navigationTitle("Diagnostics")
    .task { if model.metadata == nil { await model.loadDiagnostics() } }
  }

  private func describe(_ entry: FlowLogEntry) -> String {
    var lines = ["\(entry.timestamp.formatted(date: .omitted, time: .standard))  \(entry.method) \(entry.url.absoluteString)"]
    lines += entry.requestHeaders.sorted { $0.key < $1.key }.map { "  \($0.key): \($0.value)" }
    if let body = entry.requestBody { lines.append("  " + body.replacingOccurrences(of: "\n", with: "\n  ")) }
    lines.append("→ \(entry.statusCode.map { "HTTP \($0)" } ?? entry.errorCode ?? "no response") (\(entry.durationMilliseconds) ms)")
    if let body = entry.responseBody { lines.append("  " + body.replacingOccurrences(of: "\n", with: "\n  ")) }
    return lines.joined(separator: "\n")
  }

  private func copy(_ text: String) {
    #if canImport(UIKit)
    UIPasteboard.general.string = text
    #elseif canImport(AppKit)
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(text, forType: .string)
    #endif
  }
}
