// A vault's icon and color, chosen by its owner (stored by name in the
// vault's encrypted details).

import {
  Briefcase,
  Building2,
  Car,
  Code,
  Gamepad2,
  GraduationCap,
  Heart,
  House,
  Landmark,
  LockKeyhole,
  PiggyBank,
  Plane,
  Server,
  Shield,
  ShoppingCart,
  Star,
  Stethoscope,
  Users,
  type LucideIcon,
} from "lucide-react";

import { cx } from "../components/ui";

export const VAULT_ICONS: Record<string, LucideIcon> = {
  lock: LockKeyhole,
  home: House,
  family: Users,
  work: Briefcase,
  company: Building2,
  bank: Landmark,
  savings: PiggyBank,
  shopping: ShoppingCart,
  travel: Plane,
  car: Car,
  health: Stethoscope,
  school: GraduationCap,
  games: Gamepad2,
  code: Code,
  server: Server,
  shield: Shield,
  heart: Heart,
  star: Star,
};

/** Colors by name: the icon's, and a soft background for the picker. */
export const VAULT_COLORS: Record<string, { text: string; soft: string; swatch: string }> = {
  default: { text: "", soft: "bg-panel-3", swatch: "bg-muted" },
  teal: { text: "text-teal-500", soft: "bg-teal-500/15", swatch: "bg-teal-500" },
  blue: { text: "text-blue-500", soft: "bg-blue-500/15", swatch: "bg-blue-500" },
  violet: { text: "text-violet-500", soft: "bg-violet-500/15", swatch: "bg-violet-500" },
  pink: { text: "text-pink-500", soft: "bg-pink-500/15", swatch: "bg-pink-500" },
  red: { text: "text-red-500", soft: "bg-red-500/15", swatch: "bg-red-500" },
  orange: { text: "text-orange-500", soft: "bg-orange-500/15", swatch: "bg-orange-500" },
  amber: { text: "text-amber-500", soft: "bg-amber-500/15", swatch: "bg-amber-500" },
  green: { text: "text-green-500", soft: "bg-green-500/15", swatch: "bg-green-500" },
};

/** A vault's icon in its color (the lock, uncolored, when none was chosen
 * or it is one this version does not know). */
export function VaultGlyph({ vault, className }: { vault: { icon: string; color: string }; className?: string }) {
  const Icon = VAULT_ICONS[vault.icon] ?? LockKeyhole;
  return <Icon className={cx(className, VAULT_COLORS[vault.color]?.text)} />;
}
