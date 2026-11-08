// Disc artwork per vault colour. Only the red embroidery differs; the logo,
// case and animation are shared. Rendered by src/scripts/tint-discs.py.
import crimson from "./assets/disc.png";
import amber from "./assets/disc-amber.png";
import teal from "./assets/disc-teal.png";
import cobalt from "./assets/disc-cobalt.png";
import violet from "./assets/disc-violet.png";
import chrome from "./assets/disc-chrome.png";
import type { VaultColor } from "./tauri-bridge";

export const VAULT_COLORS: Record<VaultColor, { disc: string; glow: string; label: string }> = {
  crimson: { disc: crimson, glow: "225 29 72", label: "Crimson" },
  amber: { disc: amber, glow: "245 158 11", label: "Amber" },
  teal: { disc: teal, glow: "20 184 166", label: "Teal" },
  cobalt: { disc: cobalt, glow: "59 130 246", label: "Cobalt" },
  violet: { disc: violet, glow: "168 85 247", label: "Violet" },
  chrome: { disc: chrome, glow: "212 212 216", label: "Chrome" },
};

export function vaultColor(c: string | null | undefined) {
  return VAULT_COLORS[(c ?? "crimson") as VaultColor] ?? VAULT_COLORS.crimson;
}
