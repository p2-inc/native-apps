# Example app branding

The example and demo apps are framed with Phase Two's brand, lightly: a launch screen with the slash mark, the mark and name at the top of the first screen, the brand blue as accent, and a "Made by Phase Two" line with a link to phasetwo.io. The SDK's default login screens are not restyled. Where a platform's SDK screens read the app theme (Compose `MaterialTheme`, Flutter `Theme`, SwiftUI tint), they take the app's colors the way they would in an integrating app.

| Token | Value | Used for |
|---|---|---|
| Slash blue | `#3FA1E3` | The mark (`mark.svg`) |
| Product blue | `#3B82F6` (`oklch(0.6231 0.188 259.8145)`) | Seed of the Material 3 schemes (Android, Flutter); iOS `AccentColor` in light mode |
| Accent, dark | `#6EA8FE` | iOS `AccentColor` and React Native accent in dark mode |
| Filled buttons (React Native) | `#2563EB` | White text on it; the same blue as the module's own primary buttons |
| Magenta | `#C03DA3` | The app icon badges (`../app-icons`) |

Android and Flutter use the Material 3 "fidelity" scheme seeded from `#3B82F6` (light primary `#0058BE`, dark primary `#ADC6FF`); the Android values are in `android/demo/src/main/kotlin/io/phasetwo/keycloak/nativedemo/DemoTheme.kt`, Flutter computes them with `ColorScheme.fromSeed`. The apps use the platform system fonts; Inter is the product typeface but is not bundled.

Launch screen backgrounds match each app's first screen so the hand-over does not flash:

| App | Light | Dark | Mechanism |
|---|---|---|---|
| ios/KeycloakNativeDemo | `#F2F2F7` | `#000000` | `UILaunchScreen` in Info.plist (`UIColorName` + `UIImageName`), no storyboard |
| android/demo | `#F9F9FF` | `#10131A` | `androidx.core:core-splashscreen` (`Theme.Demo.Starting`) |
| React Native example | `#FFFFFF` | `#10131A` | The template's `LaunchScreen.storyboard` (iOS); `LaunchTheme` with the Android 12 `windowSplashScreen*` attributes on API 31+ and a layer-list before (Android); no dependency |
| Flutter example | `#F9F9FF` | `#10131A` | The template's `LaunchScreen.storyboard` (iOS); `LaunchTheme` with `windowSplashScreen*` on API 31+ and `launch_background.xml` before (Android); no `flutter_native_splash` |

## Files

- `mark.svg`: the slash mark alone, in slash blue, cropped to its bounds (the same paths as the icons in `../app-icons`).
- `render.sh`: renders `mark.svg` to the PNGs the apps use (iOS asset catalogs at 88 pt, the React Native and Flutter header image at 30 dp). Run `sh design/brand/render.sh` from the repository root; it needs `rsvg-convert` (librsvg).

The Android apps use vector drawables instead of PNGs, with the same path data: `res/drawable/brand_mark.xml` (the header mark, viewport cropped to the mark) and `res/drawable/splash_mark.xml` (the launch icon: the mark 104 dp wide, centered on the 288 dp canvas so it stays inside the 192 dp circle the system keeps). Edit them by hand if `mark.svg` changes. The iOS color sets (`AccentColor`, `LaunchBackground`) are JSON in each asset catalog.
