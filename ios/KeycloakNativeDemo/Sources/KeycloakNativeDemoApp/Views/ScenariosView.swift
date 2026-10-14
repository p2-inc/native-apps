import SwiftUI

struct ScenariosView: View {
  @Environment(DemoModel.self) private var model

  var body: some View {
    List {
      Section("Issuer") {
        Text(model.config.issuer.absoluteString).font(.footnote.monospaced())
        Text("Clients: \(model.config.clientId), \(model.config.passkeyClientId)").font(.footnote)
      }
      Section("Scenarios (spec/06 §2)") {
        ForEach(Scenario.allCases) { scenario in
          Button {
            model.select(scenario)
          } label: {
            VStack(alignment: .leading, spacing: 4) {
              HStack {
                Text(scenario.title).font(.headline)
                Spacer()
                if model.scenario == scenario { Image(systemName: "checkmark.circle.fill").foregroundStyle(.tint) }
              }
              Text(scenario.details).font(.footnote).foregroundStyle(.secondary)
            }
          }
          .buttonStyle(.plain)
          .accessibilityIdentifier("scenario-\(scenario.rawValue)")
        }
      }
      if model.scenario == .s14BruteForce {
        Section {
          Button("Run S14 now (locks user erin for a minute)") { Task { await model.runBruteForce() } }
            .disabled(model.isBusy)
          StatusBar()
        }
      }
    }
    .navigationTitle("Scenarios")
  }
}
