package io.phasetwo.keycloak.nativedemo

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/**
 * Material 3 color schemes seeded from Phase Two's product blue (#3B82F6, the "fidelity" variant of
 * the Material color utilities, which keeps the primary close to the seed). Neutral surfaces, the
 * blue as accent. The SDK's default screens (`NativeLoginScreen`) read `MaterialTheme`, so they take
 * these colors the way they would take an integrating app's theme.
 */
private val LightColors = lightColorScheme(
  primary = Color(0xFF0058BE),
  onPrimary = Color(0xFFFFFFFF),
  primaryContainer = Color(0xFF2170E4),
  onPrimaryContainer = Color(0xFFFEFCFF),
  inversePrimary = Color(0xFFADC6FF),
  secondary = Color(0xFF495E8A),
  onSecondary = Color(0xFFFFFFFF),
  secondaryContainer = Color(0xFFB6CCFF),
  onSecondaryContainer = Color(0xFF405682),
  error = Color(0xFFBA1A1A),
  onError = Color(0xFFFFFFFF),
  errorContainer = Color(0xFFFFDAD6),
  onErrorContainer = Color(0xFF93000A),
  background = Color(0xFFF9F9FF),
  onBackground = Color(0xFF191B23),
  surface = Color(0xFFF9F9FF),
  onSurface = Color(0xFF191B23),
  surfaceVariant = Color(0xFFE1E2EC),
  onSurfaceVariant = Color(0xFF424754),
  surfaceTint = Color(0xFF0058BE),
  inverseSurface = Color(0xFF2E3038),
  inverseOnSurface = Color(0xFFEFF0FA),
  outline = Color(0xFF727785),
  outlineVariant = Color(0xFFC2C6D6),
  surfaceDim = Color(0xFFD8D9E3),
  surfaceBright = Color(0xFFF9F9FF),
  surfaceContainerLowest = Color(0xFFFFFFFF),
  surfaceContainerLow = Color(0xFFF2F3FD),
  surfaceContainer = Color(0xFFECEDF7),
  surfaceContainerHigh = Color(0xFFE6E7F2),
  surfaceContainerHighest = Color(0xFFE1E2EC),
)

private val DarkColors = darkColorScheme(
  primary = Color(0xFFADC6FF),
  onPrimary = Color(0xFF002E6A),
  primaryContainer = Color(0xFF4D8EFF),
  onPrimaryContainer = Color(0xFF001C46),
  inversePrimary = Color(0xFF005AC2),
  secondary = Color(0xFFB1C6F9),
  onSecondary = Color(0xFF182F59),
  secondaryContainer = Color(0xFF304671),
  onSecondaryContainer = Color(0xFF9FB5E7),
  error = Color(0xFFFFB4AB),
  onError = Color(0xFF690005),
  errorContainer = Color(0xFF93000A),
  onErrorContainer = Color(0xFFFFDAD6),
  background = Color(0xFF10131A),
  onBackground = Color(0xFFE1E2EC),
  surface = Color(0xFF10131A),
  onSurface = Color(0xFFE1E2EC),
  surfaceVariant = Color(0xFF32353C),
  onSurfaceVariant = Color(0xFFC2C6D6),
  surfaceTint = Color(0xFFADC6FF),
  inverseSurface = Color(0xFFE1E2EC),
  inverseOnSurface = Color(0xFF2E3038),
  outline = Color(0xFF8C909F),
  outlineVariant = Color(0xFF424754),
  surfaceDim = Color(0xFF10131A),
  surfaceBright = Color(0xFF363941),
  surfaceContainerLowest = Color(0xFF0B0E15),
  surfaceContainerLow = Color(0xFF191B23),
  surfaceContainer = Color(0xFF1D2027),
  surfaceContainerHigh = Color(0xFF272A31),
  surfaceContainerHighest = Color(0xFF32353C),
)

/** The Phase Two slash blue of the mark (design/brand). */
val BrandSlash = Color(0xFF3FA1E3)

@Composable
fun DemoTheme(content: @Composable () -> Unit) {
  MaterialTheme(colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors, content = content)
}
