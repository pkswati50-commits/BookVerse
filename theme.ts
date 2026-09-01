import { useColorScheme } from "react-native";

export type ThemeMode = "light" | "dark";

export const palette = {
  light: {
    surface: "#FDFBF7",
    onSurface: "#121212",
    surfaceSecondary: "#F2EFE9",
    onSurfaceSecondary: "#595959",
    surfaceTertiary: "#E8E4DB",
    onSurfaceTertiary: "#737373",
    brand: "#B89020",
    brandPrimary: "#9E7B1A",
    onBrandPrimary: "#FFFFFF",
    brandTertiary: "#F0E5C6",
    onBrandTertiary: "#9E7B1A",
    success: "#2D5A27",
    warning: "#8A6300",
    error: "#8B2A2A",
    border: "#E8E4DB",
    borderStrong: "#D6C494",
    divider: "#EFEBE0",
  },
  dark: {
    surface: "#0F0F0F",
    onSurface: "#F7F5F0",
    surfaceSecondary: "#1A1A1A",
    onSurfaceSecondary: "#B3B1AD",
    surfaceTertiary: "#262626",
    onSurfaceTertiary: "#8C8B87",
    brand: "#D4AF37",
    brandPrimary: "#C5A028",
    onBrandPrimary: "#0A0A0A",
    brandTertiary: "#403511",
    onBrandTertiary: "#E1C15A",
    success: "#44813D",
    warning: "#CBA426",
    error: "#C75050",
    border: "#262626",
    borderStrong: "#403511",
    divider: "#1F1F1F",
  },
};

export const spacing = { xs: 4, sm: 8, md: 12, lg: 16, xl: 24, xxl: 32, xxxl: 48 };
export const radius = { sm: 6, md: 12, lg: 20, pill: 999 };
export const font = {
  display: "serif" as const, // system serif fallback (Cormorant would need loading)
  body: "System" as const,
};

export function useTheme() {
  const scheme = useColorScheme();
  const mode: ThemeMode = scheme === "light" ? "light" : "dark";
  return { mode, c: palette[mode], spacing, radius, font };
}

export type Theme = ReturnType<typeof useTheme>;
