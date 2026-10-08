import { ArrowLeft, Copy, Eye, EyeOff, History, RefreshCw, Trash, WandSparkles } from "lucide-react";
import { Popover, Slider } from "radix-ui";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { PasswordText, StrengthBadge, useStrength } from "../../components/common";
import { Button, Dialog, IconButton, Switch, cx } from "../../components/ui";
import { api, errorMessage, type GeneratedEntry, type GeneratedPassword, type GeneratorOptions } from "../../lib/api";
import { relativeTime } from "../../lib/format";
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

/** The wand next to a password field: opens the generator, and fills the
 * field with what it makes. */
export function GeneratorButton({ onUse, className }: { onUse: (password: string) => void; className?: string }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  // Modal, so it scrolls even inside a dialog (which blocks scrolling
  // outside itself).
  return (
    <Popover.Root open={open} onOpenChange={setOpen} modal>
      <Popover.Trigger asChild>
        <IconButton label={t("editor.generate")} className={className}>
          <WandSparkles className="size-4" />
        </IconButton>
      </Popover.Trigger>
      <Popover.Portal>
        {/* Scrolls when the window is too short for it. */}
        <Popover.Content
          align="end"
          sideOffset={6}
          collisionPadding={8}
          className="z-50 max-h-[var(--radix-popover-content-available-height)] overflow-y-auto rounded-xl border border-line bg-panel p-3 shadow-2xl animate-pop"
        >
          <GeneratorPanel
            compact
            onUse={(password) => {
              onUse(password);
              setOpen(false);
            }}
          />
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
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
      remember(result.password);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  const bits = Math.round(result?.entropy_bits ?? 0);
  // The same measure as the editor and the item, so they agree.
  const strength = useStrength(result?.password ?? "");

  const separators = [
    { value: "-", label: "-", title: t("generator.sepHyphen") },
    { value: " ", label: "␣", title: t("generator.sepSpace") },
    { value: ".", label: ".", title: t("generator.sepPeriod") },
    { value: "_", label: "_", title: t("generator.sepUnderscore") },
    { value: ",", label: ",", title: t("generator.sepComma") },
    { value: "", label: "∅", title: t("generator.sepNone") },
  ];

  return (
    <div className={cx("space-y-3", compact && "w-[300px]")}>
      <div className="rounded-lg border border-line bg-panel-2 px-3 py-2.5">
        <div className="flex items-start gap-0.5">
          <div className="min-h-10 flex-1 pt-0.5 text-[14px] leading-snug">
            {result ? <PasswordText value={result.password} /> : <span className="text-danger">{error}</span>}
          </div>
          <IconButton label={t("generator.regenerate")} onClick={() => regenerate(prefs)}>
            <RefreshCw className="size-4" />
          </IconButton>
          <IconButton label={t("common.copy")} onClick={copy}>
            <Copy className="size-4" />
          </IconButton>
        </div>
        <div className="mt-2 flex min-h-4 items-center justify-between gap-2">
          {strength ? <StrengthBadge level={strength.level} className="text-[11px]" /> : <span />}
          <span className="text-[10px] tabular-nums text-subtle">{t("generator.bits", { bits })}</span>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-1 rounded-lg bg-panel-3 p-0.5">
        {(["random", "memorable", "pin"] as Mode[]).map((mode) => (
          <button
            key={mode}
            onClick={() => update({ mode })}
            className={cx(
              "h-6 rounded-md text-xs font-medium transition-colors",
              prefs.mode === mode ? "bg-panel text-fg shadow-sm" : "text-muted hover:text-fg",
            )}
          >
            {t(`generator.${mode}`)}
          </button>
        ))}
      </div>

      {prefs.mode === "random" && (
        <div className="space-y-2.5">
          <LengthSlider label={t("generator.length")} value={prefs.length} min={8} max={64} onChange={(length) => update({ length })} />
          <div className="grid grid-cols-4 gap-1">
            <Chip label="A-Z" title={t("generator.uppercase")} pressed={prefs.uppercase} onToggle={(uppercase) => update({ uppercase })} />
            <Chip label="a-z" title={t("generator.lowercase")} pressed={prefs.lowercase} onToggle={(lowercase) => update({ lowercase })} />
            <Chip label="0-9" title={t("generator.digits")} pressed={prefs.digits} onToggle={(digits) => update({ digits })} />
            <Chip label="!@#" title={t("generator.symbols")} pressed={prefs.symbols} onToggle={(symbols) => update({ symbols })} />
          </div>
          <Toggle label={t("generator.avoidAmbiguous")} checked={prefs.avoid_ambiguous} onChange={(avoid_ambiguous) => update({ avoid_ambiguous })} />
        </div>
      )}
      {prefs.mode === "memorable" && (
        <div className="space-y-2.5">
          <LengthSlider label={t("generator.words")} value={prefs.words} min={3} max={12} onChange={(words) => update({ words })} />
          <div className="flex items-center gap-3">
            <span className="w-16 shrink-0 text-xs text-muted">{t("generator.separator")}</span>
            <div className="grid flex-1 grid-cols-6 gap-1">
              {separators.map((sep) => (
                <Chip key={sep.title} label={sep.label} title={sep.title} pressed={prefs.separator === sep.value} onToggle={() => update({ separator: sep.value })} />
              ))}
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
        <Button
          variant="primary"
          size="sm"
          className="w-full"
          onClick={() => {
            remember(result.password);
            onUse(result.password);
          }}
        >
          {t("generator.use")}
        </Button>
      )}
    </div>
  );
}

/** A character set or separator: short, with its name as a tooltip. */
function Chip({ label, title, pressed, onToggle }: { label: string; title: string; pressed: boolean; onToggle: (pressed: boolean) => void }) {
  return (
    <button
      type="button"
      aria-pressed={pressed}
      aria-label={title}
      title={title}
      onClick={() => onToggle(!pressed)}
      className={cx(
        "h-7 rounded-md border font-mono text-xs transition-colors",
        pressed ? "border-accent/40 bg-accent-soft font-semibold text-accent" : "border-line text-muted hover:bg-panel-2 hover:text-fg",
      )}
    >
      {label}
    </button>
  );
}

/** Kept in the generator history once the password is actually used. */
function remember(password: string) {
  void api.rememberGenerated(password).catch(() => undefined);
}

function GeneratorHistory() {
  const { t } = useTranslation();
  const [entries, setEntries] = useState<GeneratedEntry[] | null>(null);
  const [visible, setVisible] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);

  const load = useCallback(() => {
    api.generatorHistory().then(setEntries).catch((err) => toast.error(errorMessage(err)));
  }, []);
  useEffect(load, [load]);

  const copy = async (value: string) => {
    try {
      const result = await api.copyText(value);
      toast.copied(t("item.password"), result.clearAfterSeconds);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };
  const remove = async (id?: string) => {
    try {
      await api.deleteGenerated(id);
      setConfirming(false);
      load();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  return (
    <div className="space-y-3">
      <p className="text-[13px] text-muted">{t("generator.historyNote")}</p>
      {entries && entries.length === 0 && <p className="text-sm text-subtle">{t("generator.historyEmpty")}</p>}
      {entries && entries.length > 0 && (
        <div className="max-h-[50vh] divide-y divide-line overflow-y-auto rounded-xl border border-line">
          {entries.map((entry) => (
            <div key={entry.id} className="group flex items-center gap-2 px-3 py-2">
              <div className="min-w-0 flex-1">
                {visible === entry.id ? (
                  <PasswordText value={entry.password} className="break-all text-sm" />
                ) : (
                  <span className="tracking-[0.2em] text-muted">••••••••••</span>
                )}
                <div className="truncate text-xs text-subtle">
                  {relativeTime(entry.createdAt)}
                  {entry.site && ` · ${t("generator.filledOn", { site: entry.site })}`}
                </div>
              </div>
              <IconButton label={visible === entry.id ? t("item.conceal") : t("item.reveal")} onClick={() => setVisible(visible === entry.id ? null : entry.id)}>
                {visible === entry.id ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
              </IconButton>
              <IconButton label={t("common.copy")} onClick={() => copy(entry.password)}>
                <Copy className="size-4" />
              </IconButton>
              <IconButton label={t("common.delete")} onClick={() => remove(entry.id)} className="opacity-0 group-hover:opacity-100 focus:opacity-100">
                <Trash className="size-4" />
              </IconButton>
            </div>
          ))}
        </div>
      )}
      {entries && entries.length > 0 &&
        (confirming ? (
          <div className="flex items-center justify-end gap-2">
            <span className="mr-auto text-[13px]">{t("generator.clearHistoryConfirm")}</span>
            <Button variant="ghost" size="sm" onClick={() => setConfirming(false)}>
              {t("common.cancel")}
            </Button>
            <Button variant="danger" size="sm" onClick={() => remove()}>
              {t("generator.clearHistory")}
            </Button>
          </div>
        ) : (
          <Button variant="ghost" size="sm" onClick={() => setConfirming(true)}>
            <Trash className="size-4" /> {t("generator.clearHistory")}
          </Button>
        ))}
    </div>
  );
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex cursor-pointer items-center justify-between gap-4 text-xs text-muted">
      {label}
      <Switch checked={checked} onChange={onChange} label={label} />
    </label>
  );
}

function LengthSlider({ label, value, min, max, onChange }: { label: string; value: number; min: number; max: number; onChange: (v: number) => void }) {
  return (
    <div className="flex items-center gap-3">
      <span className="w-16 shrink-0 text-xs text-muted">{label}</span>
      <Slider.Root
        value={[value]}
        min={min}
        max={max}
        step={1}
        onValueChange={([v]) => onChange(v)}
        className="relative flex h-5 flex-1 touch-none select-none items-center"
      >
        <Slider.Track className="relative h-1.5 grow overflow-hidden rounded-full bg-panel-3">
          <Slider.Range className="absolute h-full rounded-full bg-accent" />
        </Slider.Track>
        <Slider.Thumb aria-label={label} className="block size-4 rounded-full border-2 border-accent bg-panel shadow outline-none focus-visible:ring-4 focus-visible:ring-accent-soft" />
      </Slider.Root>
      <span className="w-7 text-right font-mono text-xs tabular-nums">{value}</span>
    </div>
  );
}

export function GeneratorDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation();
  const [history, setHistory] = useState(false);
  useEffect(() => {
    if (!open) setHistory(false);
  }, [open]);
  return (
    <Dialog open={open} onOpenChange={onOpenChange} title={history ? t("generator.historyTitle") : t("generator.title")}>
      {history ? (
        <div className="space-y-3">
          <GeneratorHistory />
          <Button variant="ghost" size="sm" onClick={() => setHistory(false)}>
            <ArrowLeft className="size-4" /> {t("common.back")}
          </Button>
        </div>
      ) : (
        <div className="space-y-3">
          <GeneratorPanel />
          <Button variant="ghost" size="sm" onClick={() => setHistory(true)}>
            <History className="size-4" /> {t("generator.history")}
          </Button>
        </div>
      )}
    </Dialog>
  );
}
