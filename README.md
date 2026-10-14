# native-apps — browserless native authentication for Keycloak

| Directory | What |
|---|---|
| `spec/` | Investigation, protocol specification (`03`), architecture and plans. Read `spec/00-README.md` first, then `spec/10-status-and-task-list.md` for the current state and open tasks. |
| `keycloak-native-auth/` | Keycloak extensions (Maven multi-module): the FiPA-style challenge endpoint, native authenticators, demo realm, docker-compose, integration tests. See its `README.md`. |
| `.github/workflows/ci.yml` | Build + unit + integration tests; docker compose + curl walkthrough. |

Planned next to the extensions: an iOS SDK (`spec/05`) and an example iOS app (`spec/06`).

Quick start:

```bash
cd keycloak-native-auth
mvn verify                                  # needs Docker
mvn -DskipTests -DskipITs package && cd demo && docker compose up --wait && ./scripts/walkthrough.sh
```
