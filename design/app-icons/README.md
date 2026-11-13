# Demo app icons

Source SVGs for the demo and example app icons: the Phase Two slashes on the brand-blue tile (`#3FA1E3`) with a magenta badge (`#C03DA3`) in the bottom right that names the app, a key for the native demos, the React mark for the React Native example and the Flutter mark for the Flutter example.

| File | Used for |
|---|---|
| `<app>-ios.svg` | iOS app icon, rendered at 1024 × 1024 without alpha into the app's `AppIcon.appiconset` (single-size catalog). |
| `<app>-foreground.svg` | Android adaptive icon foreground (108dp canvas, art in the central 72dp), rendered to `mipmap-*/ic_launcher_foreground.png`. The background is the color resource `ic_launcher_background`. |
| `<app>-monochrome.svg` | Android 13+ themed icon layer, rendered to `mipmap-*/ic_launcher_monochrome.png`. |

`<app>` is `native` (android/demo, ios/KeycloakNativeDemo), `rn` (React Native example) or `flutter` (Flutter example).

To regenerate the PNGs (needs `rsvg-convert` and ImageMagick):

```sh
# Android, per density: mdpi 108, hdpi 162, xhdpi 216, xxhdpi 324, xxxhdpi 432
rsvg-convert -w 432 rn-foreground.svg -o .../mipmap-xxxhdpi/ic_launcher_foreground.png
rsvg-convert -w 432 rn-monochrome.svg -o .../mipmap-xxxhdpi/ic_launcher_monochrome.png
# iOS
rsvg-convert -w 1024 rn-ios.svg | magick - -alpha off PNG24:.../AppIcon.appiconset/AppIcon.png
```
