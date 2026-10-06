import { Copy, RefreshCw } from "lucide-react";
import { Slider } from "radix-ui";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { PasswordText } from "../../components/common";
import { Button, Combobox, Dialog, IconButton, Switch, cx } from "../../components/ui";
import { api, errorMessage, type GeneratedPassword, type GeneratorOptions } from "../../lib/api";
import { toast } from "../../lib/toast";

type Mode = GeneratorOptions["kind"];

const STORAGE_KEY = "keyless.generator";

interface Prefs {
  mode: Mode;
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  digits: boolean;
  symbols: boolean;
  avoid_ambiguous: boolean;
  words: number;
  separator: string;
  capitalize: boolean;
  include_number: boolean;
  pinLength: number;
}

const DEFAULT_PREFS: Prefs = {
  mode: "random",
  length: 24,
  uppercase: true,
  lowercase: true,
  digits: true,
  symbols: true,
  avoid_ambiguous: false,
  words: 5,
  separator: "-",
  capitalize: true,
  include_number: true,
  pinLength: 6,
};

function loadPrefs(): Prefs {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? { ...DEFAULT_PREFS, ...JSON.parse(raw) } : DEFAULT_PREFS;
  } catch {
    return DEFAULT_PREFS;
  }
}

function toOptions(p: Prefs): GeneratorOptions {
  switch (p.mode) {
    case "random":
      return {
        kind: "random",
        length: p.length,
        uppercase: p.uppercase,
        lowercase: p.lowercase,
        digits: p.digits,
        symbols: p.symbols,
        avoid_ambiguous: p.avoid_ambiguous,
      };
    case "memorable":
      return { kind: "memorable", words: p.words, separator: p.separator, capitalize: p.capitalize, include_number: p.include_number };
    case "pin":
      return { kind: "pin", length: p.pinLength };
  }
}

export function GeneratorPanel({ onUse, compact }: { onUse?: (password: string) => void; compact?: boolean }) {
  const { t } = useTranslation();
  const [prefs, setPrefs] = useState<Prefs>(loadPrefs);
  const [result, setResult] = useState<GeneratedPassword | null>(null);
  const [error, setError] = useState<string | null>(null);

  const regenerate = useCallback(async (p: Prefs) => {
    try {
      setResult(await api.generatePassword(toOptions(p)));
      setError(null);
    } catch (err) {
      setError(errorMessage(err));
    }
  }, []);

  useEffect(() => {
    void regenerate(prefs);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs));
    } catch {
      // Storage unavailable: preferences just won't persist.
    }
  }, [prefs, regenerate]);

  const update = (patch: Partial<Prefs>) => setPrefs((p) => ({ ...p, ...patch }));

  const copy = async () => {
    if (!result) return;
    try {
      const r = await api.copyText(result.password);
      toast.copied(t("item.password"), r.clearAfterSeconds);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  const bits = Math.round(result?.entropy_bits ?? 0);
  const quality = bits >= 100 ? "bg-success" : bits >= 70 ? "bg-accent" : bits >= 45 ? "bg-warning" : "bg-danger";

  const separators = [
    { value: "-", label: t("generator.sepHyphen") },
    { value: " ", label: t("generator.sepSpace") },
    { value: ".", label: t("generator.sepPeriod") },
    { value: "_", label: t("generator.sepUnderscore") },
    { value: ",", label: t("generator.sepComma") },
    { value: "none", label: t("generator.sepNone") },
  ];

  return (
    <div className={cx("space-y-4", compact && "w-[360px]")}>
      <div className="rounded-xl border border-line bg-panel-2 p-4">
        <div className="flex items-start gap-2">
          <div className="min-h-12 flex-1 text-[17px] leading-relaxed">
            {result ? <PasswordText value={result.password} /> : <span className="text-danger">{error}</span>}
          </div>
          <IconButton label={t("generator.regenerate")} onClick={() => regenerate(prefs)}>
            <RefreshCw className="size-4" />
          </IconButton>
          <IconButton label={t("common.copy")} onClick={copy}>
            <Copy className="size-4" />
          </IconButton>
        </div>
        <div className="mt-3 flex items-center gap-2">
          <div className="h-1 flex-1 overflow-hidden rounded-full bg-panel-3">
            <div className={cx("h-full rounded-full transition-all", quality)} style={{ width: `${Math.min(100, (bits / 128) * 100)}%` }} />
          </div>
          <span className="text-[11px] tabular-nums text-subtle">{t("generator.bits", { bits })}</span>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-1 rounded-lg bg-panel-3 p-1">
        {(["random", "memorable", "pin"] as Mode[]).map((mode) => (
          <button
            key={mode}
            onClick={() => update({ mode })}
            className={cx(
              "h-7 rounded-md text-[13px] font-medium transition-colors",
              prefs.mode === mode ? "bg-panel text-fg shadow-sm" : "text-muted hover:text-fg",
            )}
          >
            {t(`generator.${mode}`)}
          </button>
        ))}
      </div>

      {prefs.mode === "random" && (
        <div className="space-y-3">
          <LengthSlider label={t("generator.length")} value={prefs.length} min={8} max={64} onChange={(length) => update({ length })} />
          <Toggle label={t("generator.uppercase")} checked={prefs.uppercase} onChange={(uppercase) => update({ uppercase })} />
          <Toggle label={t("generator.lowercase")} checked={prefs.lowercase} onChange={(lowercase) => update({ lowercase })} />
          <Toggle label={t("generator.digits")} checked={prefs.digits} onChange={(digits) => update({ digits })} />
          <Toggle label={t("generator.symbols")} checked={prefs.symbols} onChange={(symbols) => update({ symbols })} />
          <Toggle label={t("generator.avoidAmbiguous")} checked={prefs.avoid_ambiguous} onChange={(avoid_ambiguous) => update({ avoid_ambiguous })} />
        </div>
      )}
      {prefs.mode === "memorable" && (
        <div className="space-y-3">
          <LengthSlider label={t("generator.words")} value={prefs.words} min={3} max={12} onChange={(words) => update({ words })} />
          <div className="flex items-center justify-between gap-4">
            <span className="text-[13px]">{t("generator.separator")}</span>
            <div className="w-44">
              <Combobox
                value={prefs.separator === "" ? "none" : prefs.separator}
                onChange={(v) => update({ separator: v === "none" ? "" : v })}
                options={separators}
                searchPlaceholder={t("common.searchPlaceholder")}
              />
            </div>
          </div>
          <Toggle label={t("generator.capitalize")} checked={prefs.capitalize} onChange={(capitalize) => update({ capitalize })} />
          <Toggle label={t("generator.includeNumber")} checked={prefs.include_number} onChange={(include_number) => update({ include_number })} />
        </div>
      )}
      {prefs.mode === "pin" && (
        <LengthSlider label={t("generator.length")} value={prefs.pinLength} min={4} max={12} onChange={(pinLength) => update({ pinLength })} />
      )}

      {onUse && result && (
        <Button variant="primary" className="w-full" onClick={() => onUse(result.password)}>
          {t("generator.use")}
        </Button>
      )}
    </div>
  );
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex cursor-pointer items-center justify-between gap-4 text-[13px]">
      {label}
      <Switch checked={checked} onChange={onChange} label={label} />
    </label>
  );
}

function LengthSlider({ label, value, min, max, onChange }: { label: string; value: number; min: number; max: number; onChange: (v: number) => void }) {
  return (
    <div>
      <div className="mb-2 flex items-center justify-between text-[13px]">
        <span>{label}</span>
        <span className="rounded-md bg-panel-3 px-2 py-0.5 font-mono text-xs tabular-nums">{value}</span>
      </div>
      <Slider.Root
        value={[value]}
        min={min}
        max={max}
        step={1}
        onValueChange={([v]) => onChange(v)}
        className="relative flex h-5 w-full touch-none select-none items-center"
      >
        <Slider.Track className="relative h-1.5 grow overflow-hidden rounded-full bg-panel-3">
          <Slider.Range className="absolute h-full rounded-full bg-accent" />
        </Slider.Track>
        <Slider.Thumb aria-label={label} className="block size-4 rounded-full border-2 border-accent bg-panel shadow outline-none focus-visible:ring-4 focus-visible:ring-accent-soft" />
      </Slider.Root>
    </div>
  );
}

export function GeneratorDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation();
  return (
    <Dialog open={open} onOpenChange={onOpenChange} title={t("generator.title")}>
      <GeneratorPanel />
    </Dialog>
  );
}
