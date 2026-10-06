import { clsx } from "clsx";
import { Command } from "cmdk";
import { Check, ChevronDown, Search, X } from "lucide-react";
import { Dialog as RDialog, DropdownMenu, Popover, Switch as RSwitch, Tooltip as RTooltip } from "radix-ui";
import {
  forwardRef,
  useState,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type TextareaHTMLAttributes,
} from "react";

export { clsx as cx };

// ----- Button -------------------------------------------------------------

type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "subtle";
type ButtonSize = "sm" | "md" | "lg";

const buttonBase =
  "inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:pointer-events-none whitespace-nowrap";
const buttonVariants: Record<ButtonVariant, string> = {
  primary: "bg-accent text-accent-fg hover:bg-accent-hover shadow-sm",
  secondary: "bg-panel border border-line text-fg hover:bg-panel-2 shadow-sm",
  ghost: "text-muted hover:text-fg hover:bg-panel-3",
  subtle: "bg-panel-3 text-fg hover:bg-line",
  danger: "bg-danger text-white hover:opacity-90 shadow-sm",
};
const buttonSizes: Record<ButtonSize, string> = {
  sm: "h-7 px-2.5 text-[13px]",
  md: "h-9 px-3.5 text-sm",
  lg: "h-11 px-5 text-[15px]",
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "secondary", size = "md", loading, className, children, disabled, ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      className={clsx(buttonBase, buttonVariants[variant], buttonSizes[size], className)}
      disabled={disabled || loading}
      {...props}
    >
      {loading && <Spinner className="size-4" />}
      {children}
    </button>
  );
});

export const IconButton = forwardRef<HTMLButtonElement, ButtonHTMLAttributes<HTMLButtonElement> & { label: string; active?: boolean }>(
  function IconButton({ label, active, className, children, ...props }, ref) {
    return (
      <button
        ref={ref}
        aria-label={label}
        title={label}
        className={clsx(
          "inline-flex size-8 shrink-0 items-center justify-center rounded-lg transition-colors disabled:opacity-40",
          active ? "bg-accent-soft text-accent" : "text-muted hover:bg-panel-3 hover:text-fg",
          className,
        )}
        {...props}
      >
        {children}
      </button>
    );
  },
);

export function Spinner({ className }: { className?: string }) {
  return (
    <svg className={clsx("animate-spin", className)} viewBox="0 0 24 24" fill="none" aria-hidden>
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.25" strokeWidth="3" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

// ----- Inputs -------------------------------------------------------------

const inputBase =
  "w-full rounded-lg border border-line bg-panel px-3 text-sm text-fg placeholder:text-subtle shadow-xs outline-none transition-colors focus:border-accent focus:ring-3 focus:ring-accent-soft disabled:opacity-60";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement> & { invalid?: boolean }>(
  function Input({ className, invalid, ...props }, ref) {
    return (
      <input
        ref={ref}
        spellCheck={false}
        autoComplete="off"
        className={clsx(inputBase, "h-9", invalid && "border-danger focus:border-danger focus:ring-danger-soft", className)}
        {...props}
      />
    );
  },
);

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(function Textarea(
  { className, ...props },
  ref,
) {
  return <textarea ref={ref} spellCheck={false} className={clsx(inputBase, "min-h-24 py-2 leading-relaxed", className)} {...props} />;
});

export function Label({ children, htmlFor, className }: { children: ReactNode; htmlFor?: string; className?: string }) {
  return (
    <label htmlFor={htmlFor} className={clsx("mb-1.5 block text-[13px] font-medium text-muted", className)}>
      {children}
    </label>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return (
    <kbd className="rounded border border-line bg-panel-2 px-1.5 py-0.5 font-sans text-[11px] font-medium text-subtle">
      {children}
    </kbd>
  );
}

// ----- Switch -------------------------------------------------------------

export function Switch({
  checked,
  onChange,
  label,
  disabled,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label?: string;
  disabled?: boolean;
}) {
  return (
    <RSwitch.Root
      checked={checked}
      onCheckedChange={onChange}
      aria-label={label}
      disabled={disabled}
      className="relative h-5 w-9 shrink-0 rounded-full bg-line-strong transition-colors disabled:opacity-40 data-[state=checked]:bg-accent"
    >
      <RSwitch.Thumb className="block size-4 translate-x-0.5 rounded-full bg-white shadow transition-transform data-[state=checked]:translate-x-[18px]" />
    </RSwitch.Root>
  );
}

// ----- Tooltip ------------------------------------------------------------

export function Tooltip({ content, children, side = "top" }: { content: ReactNode; children: ReactNode; side?: "top" | "bottom" | "left" | "right" }) {
  return (
    <RTooltip.Root delayDuration={350}>
      <RTooltip.Trigger asChild>{children}</RTooltip.Trigger>
      <RTooltip.Portal>
        <RTooltip.Content
          side={side}
          sideOffset={6}
          className="z-50 rounded-md bg-fg px-2 py-1 text-xs font-medium text-panel shadow-lg animate-fade"
        >
          {content}
        </RTooltip.Content>
      </RTooltip.Portal>
    </RTooltip.Root>
  );
}

export const TooltipProvider = RTooltip.Provider;

// ----- Dialog -------------------------------------------------------------

export function Dialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  width = "max-w-md",
  hideClose,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  children: ReactNode;
  width?: string;
  hideClose?: boolean;
}) {
  return (
    <RDialog.Root open={open} onOpenChange={onOpenChange}>
      <RDialog.Portal>
        <RDialog.Overlay className="fixed inset-0 z-40 bg-black/40 backdrop-blur-[2px] animate-fade" />
        <RDialog.Content
          className={clsx(
            "fixed left-1/2 top-1/2 z-50 max-h-[88vh] w-[calc(100vw-2rem)] -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-2xl border border-line bg-panel p-6 shadow-2xl outline-none animate-pop",
            width,
          )}
        >
          <div className="mb-4 flex items-start justify-between gap-4">
            <div>
              <RDialog.Title className="text-lg font-semibold text-fg">{title}</RDialog.Title>
              {description ? (
                <RDialog.Description className="mt-1 text-sm text-muted">{description}</RDialog.Description>
              ) : (
                <RDialog.Description className="sr-only">{title}</RDialog.Description>
              )}
            </div>
            {!hideClose && (
              <RDialog.Close asChild>
                <IconButton label="Close" className="-mr-2 -mt-1">
                  <X className="size-4" />
                </IconButton>
              </RDialog.Close>
            )}
          </div>
          {children}
        </RDialog.Content>
      </RDialog.Portal>
    </RDialog.Root>
  );
}

// ----- Dropdown menu ------------------------------------------------------

export const Menu = DropdownMenu.Root;
export const MenuTrigger = DropdownMenu.Trigger;

export function MenuContent({ children, align = "end" }: { children: ReactNode; align?: "start" | "end" | "center" }) {
  return (
    <DropdownMenu.Portal>
      <DropdownMenu.Content
        align={align}
        sideOffset={6}
        className="z-50 min-w-48 rounded-xl border border-line bg-panel p-1 shadow-xl animate-pop"
      >
        {children}
      </DropdownMenu.Content>
    </DropdownMenu.Portal>
  );
}

export function MenuItem({
  children,
  onSelect,
  icon,
  danger,
  shortcut,
  disabled,
}: {
  children: ReactNode;
  onSelect: () => void;
  icon?: ReactNode;
  danger?: boolean;
  shortcut?: string;
  disabled?: boolean;
}) {
  return (
    <DropdownMenu.Item
      disabled={disabled}
      onSelect={onSelect}
      className={clsx(
        "flex cursor-default items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-sm outline-none data-[disabled]:opacity-40",
        danger ? "text-danger data-[highlighted]:bg-danger-soft" : "text-fg data-[highlighted]:bg-panel-3",
      )}
    >
      {icon && <span className={clsx("flex size-4 items-center justify-center", danger ? "text-danger" : "text-muted")}>{icon}</span>}
      <span className="flex-1">{children}</span>
      {shortcut && <span className="text-xs text-subtle">{shortcut}</span>}
    </DropdownMenu.Item>
  );
}

export function MenuSeparator() {
  return <DropdownMenu.Separator className="my-1 h-px bg-line" />;
}

export function MenuLabel({ children }: { children: ReactNode }) {
  return <DropdownMenu.Label className="px-2.5 pb-1 pt-1.5 text-xs text-subtle">{children}</DropdownMenu.Label>;
}

// ----- Combobox (searchable select) -------------------------------------

export interface ComboOption<T extends string> {
  value: T;
  label: string;
  icon?: ReactNode;
  hint?: string;
  keywords?: string[];
}

export function Combobox<T extends string>({
  value,
  onChange,
  options,
  placeholder = "Select…",
  searchPlaceholder = "Search…",
  className,
  disabled,
  triggerClassName,
  trigger,
  align = "start",
}: {
  value: T | null;
  onChange: (value: T) => void;
  options: ComboOption<T>[];
  placeholder?: string;
  searchPlaceholder?: string;
  className?: string;
  disabled?: boolean;
  triggerClassName?: string;
  /** Custom trigger element (must accept a ref, e.g. a <button>). */
  trigger?: ReactNode;
  align?: "start" | "end";
}) {
  const [open, setOpen] = useState(false);
  const selected = options.find((o) => o.value === value) ?? null;
  return (
    <Popover.Root open={open} onOpenChange={setOpen}>
      <Popover.Trigger asChild disabled={disabled}>
        {trigger ?? (
        <button
          type="button"
          className={clsx(
            "flex h-9 w-full items-center gap-2 rounded-lg border border-line bg-panel px-3 text-left text-sm shadow-xs outline-none transition-colors hover:bg-panel-2 focus-visible:border-accent disabled:opacity-60",
            triggerClassName,
          )}
        >
          {selected?.icon && <span className="flex size-4 items-center justify-center text-muted">{selected.icon}</span>}
          <span className={clsx("flex-1 truncate", !selected && "text-subtle")}>{selected?.label ?? placeholder}</span>
          <ChevronDown className="size-4 text-subtle" />
        </button>
        )}
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          align={align}
          sideOffset={6}
          className={clsx(
            "z-50 overflow-hidden rounded-xl border border-line bg-panel shadow-xl animate-pop",
            trigger ? "w-64" : "w-[var(--radix-popover-trigger-width)] min-w-56",
            className,
          )}
        >
          <Command loop>
            <div className="flex items-center gap-2 border-b border-line px-3">
              <Search className="size-4 shrink-0 text-subtle" />
              <Command.Input autoFocus placeholder={searchPlaceholder} className="h-10 flex-1 bg-transparent text-sm outline-none placeholder:text-subtle" />
            </div>
            <Command.List className="max-h-64 overflow-y-auto p-1">
              <Command.Empty className="px-3 py-6 text-center text-sm text-subtle">No results</Command.Empty>
              {options.map((o) => (
                <Command.Item
                  key={o.value}
                  value={`${o.label} ${o.value}`}
                  keywords={o.keywords}
                  onSelect={() => {
                    onChange(o.value);
                    setOpen(false);
                  }}
                  className="flex cursor-default items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm text-fg data-[selected=true]:bg-panel-3"
                >
                  {o.icon && <span className="flex size-4 items-center justify-center text-muted">{o.icon}</span>}
                  <span className="flex-1 truncate">{o.label}</span>
                  {o.hint && <span className="text-xs text-subtle">{o.hint}</span>}
                  {o.value === value && <Check className="size-4 text-accent" />}
                </Command.Item>
              ))}
            </Command.List>
          </Command>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}

// ----- Misc ---------------------------------------------------------------

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={clsx("rounded-xl border border-line bg-panel", className)}>{children}</div>;
}

export function Badge({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "accent" | "danger" | "warning" }) {
  const tones = {
    neutral: "bg-panel-3 text-muted",
    accent: "bg-accent-soft text-accent",
    danger: "bg-danger-soft text-danger",
    warning: "bg-warning-soft text-warning",
  };
  return <span className={clsx("inline-flex items-center rounded-md px-1.5 py-0.5 text-xs font-medium", tones[tone])}>{children}</span>;
}

export function ErrorText({ children }: { children: ReactNode }) {
  if (!children) return null;
  return <p className="mt-2 text-[13px] text-danger animate-fade">{children}</p>;
}
