import {
  Asterisk,
  Award,
  BadgeCheck,
  BookUser,
  Box,
  Braces,
  Car,
  CreditCard,
  Database,
  FileText,
  HeartPulse,
  IdCard,
  KeyRound,
  Landmark,
  Mail,
  Server,
  StickyNote,
  Terminal,
  Wallet,
  Wifi,
  type LucideIcon,
} from "lucide-react";

import i18n from "../i18n";
import type { Category, Field, FieldKind, FieldPurpose } from "./api";

interface TemplateField {
  label: string;
  kind: FieldKind;
  purpose?: FieldPurpose;
}

export interface CategoryInfo {
  id: Category;
  icon: LucideIcon;
  /** Tailwind classes for the icon tile. */
  tint: string;
  fields: TemplateField[];
  hasWebsite?: boolean;
  /** Hidden from the "New item" picker. */
  hidden?: boolean;
}

const t = (label: string, kind: FieldKind = "text", purpose?: FieldPurpose): TemplateField => ({ label, kind, purpose });

export const CATEGORIES: CategoryInfo[] = [
  {
    id: "login",
    icon: KeyRound,
    tint: "bg-sky-500/15 text-sky-600 dark:text-sky-300",
    fields: [t("username", "text", "username"), t("password", "concealed", "password")],
    hasWebsite: true,
  },
  {
    id: "password",
    icon: Asterisk,
    tint: "bg-violet-500/15 text-violet-600 dark:text-violet-300",
    fields: [t("password", "concealed", "password")],
  },
  {
    id: "secure_note",
    icon: StickyNote,
    tint: "bg-amber-500/15 text-amber-600 dark:text-amber-300",
    fields: [],
  },
  {
    id: "credit_card",
    icon: CreditCard,
    tint: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-300",
    fields: [
      t("cardholder name"),
      t("number", "card_number"),
      t("expiry date", "month_year"),
      t("verification number", "pin"),
      t("PIN", "pin"),
      t("type"),
    ],
  },
  {
    id: "identity",
    icon: IdCard,
    tint: "bg-indigo-500/15 text-indigo-600 dark:text-indigo-300",
    fields: [
      t("first name"),
      t("last name"),
      t("birth date", "date"),
      t("email", "email"),
      t("phone", "phone"),
      t("address"),
      t("city"),
      t("state"),
      t("zip code"),
      t("country"),
      t("document number"),
    ],
  },
  {
    id: "bank_account",
    icon: Landmark,
    tint: "bg-teal-500/15 text-teal-600 dark:text-teal-300",
    fields: [
      t("bank name"),
      t("name on account"),
      t("branch"),
      t("account number", "concealed"),
      t("IBAN"),
      t("SWIFT"),
      t("PIN", "pin"),
    ],
  },
  {
    id: "api_credential",
    icon: Braces,
    tint: "bg-fuchsia-500/15 text-fuchsia-600 dark:text-fuchsia-300",
    fields: [t("username", "text", "username"), t("credential", "concealed", "password"), t("hostname", "url"), t("expires", "date")],
  },
  {
    id: "database",
    icon: Database,
    tint: "bg-orange-500/15 text-orange-600 dark:text-orange-300",
    fields: [
      t("type"),
      t("server"),
      t("port"),
      t("database"),
      t("username", "text", "username"),
      t("password", "concealed", "password"),
    ],
  },
  {
    id: "server",
    icon: Server,
    tint: "bg-slate-500/15 text-slate-600 dark:text-slate-300",
    fields: [t("URL", "url"), t("username", "text", "username"), t("password", "concealed", "password")],
  },
  {
    id: "ssh_key",
    icon: Terminal,
    tint: "bg-zinc-500/15 text-zinc-700 dark:text-zinc-300",
    fields: [t("private key", "concealed"), t("public key", "multiline"), t("fingerprint")],
  },
  {
    id: "software_license",
    icon: Award,
    tint: "bg-yellow-500/15 text-yellow-700 dark:text-yellow-300",
    fields: [t("license key", "concealed"), t("version"), t("licensed to"), t("registered email", "email"), t("purchase date", "date")],
  },
  {
    id: "wireless_router",
    icon: Wifi,
    tint: "bg-cyan-500/15 text-cyan-600 dark:text-cyan-300",
    fields: [t("network name"), t("wireless password", "concealed", "password"), t("security"), t("admin password", "concealed")],
  },
  {
    id: "email_account",
    icon: Mail,
    tint: "bg-rose-500/15 text-rose-600 dark:text-rose-300",
    fields: [
      t("username", "text", "username"),
      t("password", "concealed", "password"),
      t("IMAP server"),
      t("SMTP server"),
    ],
  },
  {
    id: "passport",
    icon: BookUser,
    tint: "bg-blue-500/15 text-blue-600 dark:text-blue-300",
    fields: [
      t("full name"),
      t("number"),
      t("issuing country"),
      t("nationality"),
      t("birth date", "date"),
      t("issued on", "date"),
      t("expiry date", "date"),
    ],
  },
  {
    id: "driver_license",
    icon: Car,
    tint: "bg-lime-500/15 text-lime-700 dark:text-lime-300",
    fields: [t("full name"), t("number"), t("category"), t("birth date", "date"), t("expiry date", "date")],
  },
  {
    id: "membership",
    icon: BadgeCheck,
    tint: "bg-pink-500/15 text-pink-600 dark:text-pink-300",
    fields: [t("group"), t("member name"), t("member ID"), t("expiry date", "date"), t("PIN", "pin")],
  },
  {
    id: "crypto_wallet",
    icon: Wallet,
    tint: "bg-amber-600/15 text-amber-700 dark:text-amber-300",
    fields: [t("recovery phrase", "concealed"), t("password", "concealed", "password"), t("wallet address")],
  },
  {
    id: "medical_record",
    icon: HeartPulse,
    tint: "bg-red-500/15 text-red-600 dark:text-red-300",
    fields: [t("patient"), t("healthcare professional"), t("location"), t("date", "date")],
  },
  {
    id: "document",
    icon: FileText,
    tint: "bg-stone-500/15 text-stone-600 dark:text-stone-300",
    fields: [],
    hidden: true,
  },
  {
    id: "other",
    icon: Box,
    tint: "bg-gray-500/15 text-gray-600 dark:text-gray-300",
    fields: [],
    hidden: true,
  },
];

export const CATEGORY_BY_ID: Record<Category, CategoryInfo> = Object.fromEntries(
  CATEGORIES.map((c) => [c.id, c]),
) as Record<Category, CategoryInfo>;

export function categoryInfo(category: Category): CategoryInfo {
  return CATEGORY_BY_ID[category] ?? CATEGORY_BY_ID.other;
}

export function newFieldId(): string {
  return crypto.randomUUID().replace(/-/g, "").slice(0, 12);
}

export function categoryLabel(category: Category, plural = false): string {
  return i18n.t(`${plural ? "categoriesPlural" : "categories"}.${category}`);
}

/** Template fields, labelled in the current language. */
export function templateFields(category: Category): Field[] {
  return categoryInfo(category).fields.map((f) => ({
    id: newFieldId(),
    label: i18n.exists(`fieldLabels.${f.label}`) ? i18n.t(`fieldLabels.${f.label}`) : f.label,
    kind: f.kind,
    value: "",
    purpose: f.purpose ?? null,
  }));
}

export const FIELD_KINDS: FieldKind[] = [
  "text",
  "concealed",
  "email",
  "url",
  "phone",
  "totp",
  "date",
  "month_year",
  "card_number",
  "pin",
  "multiline",
];

export function fieldKindLabel(kind: FieldKind): string {
  return i18n.t(`fieldKinds.${kind}`);
}

export function isSecretKind(field: { kind: FieldKind; purpose?: FieldPurpose | null }): boolean {
  return (
    field.kind === "concealed" ||
    field.kind === "pin" ||
    field.kind === "card_number" ||
    field.kind === "totp" ||
    field.purpose === "password"
  );
}
