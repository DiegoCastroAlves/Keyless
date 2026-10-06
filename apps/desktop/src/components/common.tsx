import { Check, CircleAlert, Eye, EyeOff, Info } from "lucide-react";
import { forwardRef, useEffect, useId, useState, type InputHTMLAttributes } from "react";
import { useTranslation } from "react-i18next";

import { api, type Category, type Strength } from "../lib/api";
import { categoryInfo } from "../lib/categories";
import { avatarColor, hostOf } from "../lib/format";
import { useToasts } from "../lib/toast";
import { cx } from "./ui";

export function Logo({ className = "size-10" }: { className?: string }) {
  const id = useId().replace(/:/g, "");
  return (
    <svg viewBox="0 0 1024 1024" className={className} aria-hidden>
      <defs>
        <linearGradient id={`${id}r`} x1="0.18" y1="0.08" x2="0.82" y2="0.96">
          <stop offset="0" stopColor="#7AF0DD" />
          <stop offset="0.45" stopColor="#14B8A6" />
          <stop offset="1" stopColor="#0B5F58" />
        </linearGradient>
        <radialGradient id={`${id}c`} cx="0.5" cy="0.32" r="0.75">
          <stop offset="0" stopColor="#16524D" />
          <stop offset="1" stopColor="#062523" />
        </radialGradient>
      </defs>
      <circle cx="512" cy="512" r="452" fill={`url(#${id}r)`} />
      <circle cx="512" cy="512" r="318" fill={`url(#${id}c)`} />
      <g fill="#F2FFFC">
        <circle cx="512" cy="438" r="94" />
        <path d="M470 486 H554 L586 676 Q590 702 564 702 H460 Q434 702 438 676 Z" />
      </g>
    </svg>
  );
}

export function ItemIcon({
  title,
  category,
  url,
  size = "md",
}: {
  title: string;
  category: Category;
  url?: string;
  size?: "sm" | "md" | "lg";
}) {
  const info = categoryInfo(category);
  const sizes = { sm: "size-8 rounded-lg text-sm", md: "size-9 rounded-[10px] text-[15px]", lg: "size-14 rounded-2xl text-2xl" };
  const iconSizes = { sm: "size-4", md: "size-[18px]", lg: "size-7" };
  if ((category === "login" || category === "password") && (url || title)) {
    const seed = url ? hostOf(url) : title;
    const letter = ((title || seed).match(/[\p{L}\p{N}]/u)?.[0] ?? "?").toUpperCase();
    return (
      <div className={cx("flex shrink-0 items-center justify-center font-semibold text-white shadow-sm", sizes[size], avatarColor(seed))}>
        {letter}
      </div>
    );
  }
  const Icon = info.icon;
  return (
    <div className={cx("flex shrink-0 items-center justify-center", sizes[size], info.tint)}>
      <Icon className={iconSizes[size]} />
    </div>
  );
}

/** Renders a password with digits and symbols colored, like 1Password does. */
export function PasswordText({ value, className }: { value: string; className?: string }) {
  return (
    <span className={cx("selectable break-all font-mono", className)}>
      {Array.from(value).map((ch, i) => (
        <span key={i} className={/[0-9]/.test(ch) ? "text-digit" : /[^\p{L}\p{N}\s]/u.test(ch) ? "text-symbol" : undefined}>
          {ch}
        </span>
      ))}
    </span>
  );
}

export const PasswordInput = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement> & { invalid?: boolean }>(
  function PasswordInput({ className, invalid, ...props }, ref) {
    const [visible, setVisible] = useState(false);
    const { t } = useTranslation();
    return (
      <div className="relative">
        <input
          ref={ref}
          type={visible ? "text" : "password"}
          spellCheck={false}
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="off"
          className={cx(
            "h-10 w-full rounded-lg border border-line bg-panel pl-3 pr-10 text-sm text-fg shadow-xs outline-none transition-colors placeholder:text-subtle focus:border-accent focus:ring-3 focus:ring-accent-soft",
            visible && "font-mono",
            invalid && "border-danger focus:border-danger focus:ring-danger-soft",
            className,
          )}
          {...props}
        />
        <button
          type="button"
          tabIndex={-1}
          onClick={() => setVisible((v) => !v)}
          aria-label={visible ? t("common.hide") : t("common.show")}
          className="absolute right-1.5 top-1/2 flex size-7 -translate-y-1/2 items-center justify-center rounded-md text-subtle hover:bg-panel-3 hover:text-fg"
        >
          {visible ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
        </button>
      </div>
    );
  },
);

const STRENGTH_COLORS = ["bg-danger", "bg-danger", "bg-warning", "bg-accent", "bg-success"];

export function useStrength(password: string, email?: string): Strength | null {
  const [strength, setStrength] = useState<Strength | null>(null);
  useEffect(() => {
    if (!password) {
      setStrength(null);
      return;
    }
    const handle = setTimeout(() => {
      api.passwordStrength(password, email).then(setStrength).catch(() => setStrength(null));
    }, 150);
    return () => clearTimeout(handle);
  }, [password, email]);
  return strength;
}

export function StrengthMeter({ strength }: { strength: Strength | null }) {
  const { t } = useTranslation();
  const score = strength?.score ?? -1;
  return (
    <div className="mt-2">
      <div className="flex gap-1">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="h-1 flex-1 overflow-hidden rounded-full bg-panel-3">
            <div
              className={cx("h-full rounded-full transition-all duration-300", score > i ? STRENGTH_COLORS[score] : "w-0")}
              style={{ width: score > i ? "100%" : "0%" }}
            />
          </div>
        ))}
      </div>
      {strength && (
        <div className="mt-1.5 flex justify-end text-xs">
          <span className={cx("font-medium", score >= 3 ? "text-success" : score === 2 ? "text-warning" : "text-danger")}>
            {t(`strength.${score}`)}
          </span>
        </div>
      )}
    </div>
  );
}

export function Toaster() {
  const toasts = useToasts((s) => s.toasts);
  return (
    <div className="pointer-events-none fixed inset-x-0 bottom-5 z-[60] flex flex-col items-center gap-2">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={cx(
            "pointer-events-auto flex max-w-md items-center gap-2 rounded-full px-4 py-2 text-[13px] font-medium shadow-lg animate-toast",
            t.tone === "error" ? "bg-danger text-white" : "bg-fg text-panel",
          )}
        >
          {t.tone === "success" ? <Check className="size-4" /> : t.tone === "error" ? <CircleAlert className="size-4" /> : <Info className="size-4" />}
          <span>{t.message}</span>
        </div>
      ))}
    </div>
  );
}

/** Full-window centered layout used by onboarding and the lock screen. */
export function AuthShell({ children, wide }: { children: React.ReactNode; wide?: boolean }) {
  return (
    <div className="relative flex h-full items-center justify-center overflow-y-auto bg-app p-6">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-70 dark:opacity-100"
        style={{
          background:
            "radial-gradient(60% 50% at 50% 0%, var(--accent-soft), transparent 70%), radial-gradient(40% 40% at 90% 100%, var(--accent-soft), transparent 70%)",
        }}
      />
      <div className={cx("relative w-full animate-pop", wide ? "max-w-xl" : "max-w-sm")}>{children}</div>
    </div>
  );
}
