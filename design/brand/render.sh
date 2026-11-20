#!/bin/sh
# Renders the Phase Two slash mark (mark.svg) into the example apps. Needs rsvg-convert (librsvg).
# Run from anywhere: sh design/brand/render.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
mark="$here/mark.svg"

# iOS launch screen and header image, 88 pt wide (asset catalog @1x/@2x/@3x).
ios_imageset() {
  dir=$1; name=$2
  mkdir -p "$dir"
  rsvg-convert -w 88 "$mark" -o "$dir/$name.png"
  rsvg-convert -w 176 "$mark" -o "$dir/$name@2x.png"
  rsvg-convert -w 264 "$mark" -o "$dir/$name@3x.png"
}
ios_imageset "$root/ios/KeycloakNativeDemo/App/Assets.xcassets/BrandMark.imageset" BrandMark
ios_imageset "$root/react-native/keycloak-native-react-native/example/ios/ReactNativeKeycloakNativeExample/Images.xcassets/BrandMark.imageset" BrandMark
ios_imageset "$root/flutter/keycloak_native_flutter/example/ios/Runner/Assets.xcassets/LaunchImage.imageset" LaunchImage

# In-app header mark, 30 dp/pt wide: React Native (@2x/@3x suffixes) and Flutter (2.0x/3.0x folders).
rn="$root/react-native/keycloak-native-react-native/example/src/assets"
mkdir -p "$rn"
rsvg-convert -w 30 "$mark" -o "$rn/brand-mark.png"
rsvg-convert -w 60 "$mark" -o "$rn/brand-mark@2x.png"
rsvg-convert -w 90 "$mark" -o "$rn/brand-mark@3x.png"
fl="$root/flutter/keycloak_native_flutter/example/assets"
mkdir -p "$fl/2.0x" "$fl/3.0x"
rsvg-convert -w 30 "$mark" -o "$fl/brand_mark.png"
rsvg-convert -w 60 "$mark" -o "$fl/2.0x/brand_mark.png"
rsvg-convert -w 90 "$mark" -o "$fl/3.0x/brand_mark.png"
