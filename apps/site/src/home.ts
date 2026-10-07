// The home page (keyless.diegoalves.dev): its texts in the visitor's
// language, the "what leaves your computer" specimen, and the downloads of
// the newest release, read from GitHub. Everything is set as text; the only
// HTML used comes from the dictionary below.

type Lang = "pt-BR" | "en" | "es";
const LANGS: Lang[] = ["pt-BR", "en", "es"];
const REPO = "DiegoCastroAlves/Keyless";

const TEXT: Record<Lang, Record<string, string>> = {
  "pt-BR": {
    docTitle: "Keyless: suas senhas, só suas",
    docDescription:
      "Gerenciador de senhas de código aberto para Windows e Linux. Tudo é criptografado no seu dispositivo; o servidor só guarda o que não consegue ler.",
    skip: "Pular para o conteúdo",
    nav: "Seções",
    navHow: "Como funciona",
    navTools: "Ferramentas",
    navDownload: "Baixar",
    language: "Idioma",
    eyebrow: "Gerenciador de senhas · Windows e Linux · Código aberto",
    title: "A chave fica <em>com você.</em>",
    lede: "Senhas, cartões, chaves de acesso e arquivos, criptografados no seu computador antes de sair dele. O servidor guarda só o que não consegue ler, e nem nós temos como abrir.",
    youType: "Você digita",
    leaves: "Sai do computador",
    specimenCaption: "XChaCha20-Poly1305 com uma chave que nasce da sua senha mestra e da sua Chave Secreta.",
    download: "Baixar o Keyless",
    downloadFor: "Baixar para {os}",
    otherVersions: "Outras versões",
    howTitle: "Como funciona",
    step1Title: "Duas coisas que só você tem",
    step1: "Sua senha mestra, que fica na sua cabeça, e a Chave Secreta, gerada no seu dispositivo e guardada no Kit de Emergência. As duas juntas viram a chave da sua conta.",
    step2Title: "Tudo é cifrado aqui",
    step2: "Cada item é criptografado no seu computador, amarrado ao cofre e ao item a que pertence. Mudar ou trocar algo no caminho faz a decriptação falhar, em vez de te enganar.",
    step3Title: "O servidor só sincroniza",
    step3: "Seus dispositivos trocam texto cifrado. Funciona sem internet, e um conflito entre dois dispositivos nunca apaga nada: as duas versões ficam.",
    ledgerTitle: "O que o servidor vê",
    sees: "Vê",
    sees1: "Seu e-mail",
    sees2: "Quantos cofres e itens você tem",
    sees3: "Quando algo muda",
    sees4: "O tamanho aproximado de cada coisa",
    never: "Nunca vê",
    never1: "Suas senhas",
    never2: "Os nomes dos sites e dos itens",
    never3: "Suas notas e seus arquivos",
    never4: "Sua senha mestra e sua Chave Secreta",
    ledgerNote:
      'Não dá para recuperar a senha mestra por e-mail. É isso que garante que ninguém, nem quem cuida do servidor, consiga abrir a sua conta. <a href="https://github.com/DiegoCastroAlves/Keyless/blob/main/docs/SECURITY.md">Leia o desenho de segurança.</a>',
    toolsTitle: "Ferramentas",
    t1: "Preenchimento",
    d1: "Logins, cartões e endereços no Chrome, Edge, Brave e Firefox, e oferece salvar o que você digita.",
    t2: "Chaves de acesso",
    d2: "Passkeys criadas e usadas pelo Keyless, em qualquer navegador onde ele estiver.",
    t3: "Watchtower",
    d3: "Senhas fracas, repetidas ou vazadas, sites sem HTTPS e cartões perto de vencer.",
    t4: "Anexos",
    d4: "Documentos dentro dos itens, criptografados em pedaços antes de subir.",
    t5: "Compartilhar",
    d5: "Um link para alguém sem Keyless ver um item, por tempo limitado ou uma vez só.",
    t6: "Agente SSH",
    d6: "Chaves SSH para o terminal e para assinar commits, com aprovação a cada uso.",
    t7: "Gerador",
    d7: "Senhas e frases aleatórias, com histórico do que foi gerado.",
    t8: "Importar",
    d8: "Do 1Password, Bitwarden, Chrome, Edge e Firefox.",
    t9: "Desbloqueio",
    d9: "Com a senha mestra, a senha do computador no Linux ou o Windows Hello.",
    downloadTitle: "Baixar",
    releaseLoading: "Procurando a versão mais recente…",
    releaseLine: "Versão {version}, publicada em {date}. Prévia: ainda em desenvolvimento.",
    releaseError: "Não foi possível consultar o GitHub agora. As versões estão no link abaixo.",
    extension: "Extensão do navegador",
    allReleases: "Todas as versões no GitHub",
    noFiles: "Nada nesta versão",
    source: "Código-fonte",
    security: "Segurança",
    madeBy: "Feito por Diego Castro Alves",
    fileExe: "Instalador",
    fileAppImage: "AppImage (qualquer distribuição)",
    fileDeb: "Debian, Ubuntu (.deb)",
    fileRpm: "Fedora, openSUSE (.rpm)",
    fileArch: "Arch, CachyOS (.pkg.tar.zst)",
    fileChrome: "Chrome, Edge, Brave (.zip)",
    fileFirefox: "Firefox (.zip)",
  },
  en: {
    docTitle: "Keyless: your passwords, only yours",
    docDescription: "Open-source password manager for Windows and Linux. Everything is encrypted on your device; the server keeps only what it cannot read.",
    skip: "Skip to content",
    nav: "Sections",
    navHow: "How it works",
    navTools: "Tools",
    navDownload: "Download",
    language: "Language",
    eyebrow: "Password manager · Windows and Linux · Open source",
    title: "The key stays <em>with you.</em>",
    lede: "Passwords, cards, passkeys and files, encrypted on your computer before they leave it. The server keeps only what it cannot read, and not even we can open it.",
    youType: "You type",
    leaves: "Leaves your computer",
    specimenCaption: "XChaCha20-Poly1305 with a key born from your master password and your Secret Key.",
    download: "Download Keyless",
    downloadFor: "Download for {os}",
    otherVersions: "Other versions",
    howTitle: "How it works",
    step1Title: "Two things only you have",
    step1: "Your master password, which stays in your head, and the Secret Key, made on your device and kept in your Emergency Kit. Together they become your account's key.",
    step2Title: "Everything is encrypted here",
    step2: "Each item is encrypted on your computer, bound to its vault and item. Changing or swapping anything on the way makes decryption fail instead of fooling you.",
    step3Title: "The server only syncs",
    step3: "Your devices exchange ciphertext. It works offline, and a conflict between two devices never loses anything: both versions stay.",
    ledgerTitle: "What the server sees",
    sees: "Sees",
    sees1: "Your email",
    sees2: "How many vaults and items you have",
    sees3: "When something changes",
    sees4: "The rough size of each thing",
    never: "Never sees",
    never1: "Your passwords",
    never2: "The names of your sites and items",
    never3: "Your notes and your files",
    never4: "Your master password and Secret Key",
    ledgerNote:
      'There is no recovering the master password by email. That is what makes sure nobody, not even whoever runs the server, can open your account. <a href="https://github.com/DiegoCastroAlves/Keyless/blob/main/docs/SECURITY.md">Read the security design.</a>',
    toolsTitle: "Tools",
    t1: "Autofill",
    d1: "Logins, cards and addresses in Chrome, Edge, Brave and Firefox, and offers to save what you type.",
    t2: "Passkeys",
    d2: "Passkeys created and used by Keyless, in any browser it is in.",
    t3: "Watchtower",
    d3: "Weak, reused or breached passwords, sites without HTTPS and cards about to expire.",
    t4: "Attachments",
    d4: "Documents inside items, encrypted in chunks before upload.",
    t5: "Sharing",
    d5: "A link for someone without Keyless to see an item, for a limited time or just once.",
    t6: "SSH agent",
    d6: "SSH keys for the terminal and for signing commits, approved on each use.",
    t7: "Generator",
    d7: "Random passwords and passphrases, with a history of what was generated.",
    t8: "Import",
    d8: "From 1Password, Bitwarden, Chrome, Edge and Firefox.",
    t9: "Unlock",
    d9: "With the master password, the computer's password on Linux, or Windows Hello.",
    downloadTitle: "Download",
    releaseLoading: "Looking for the newest version…",
    releaseLine: "Version {version}, published {date}. Preview: still in development.",
    releaseError: "Could not reach GitHub right now. The versions are at the link below.",
    extension: "Browser extension",
    allReleases: "All versions on GitHub",
    noFiles: "Nothing in this version",
    source: "Source code",
    security: "Security",
    madeBy: "Made by Diego Castro Alves",
    fileExe: "Installer",
    fileAppImage: "AppImage (any distribution)",
    fileDeb: "Debian, Ubuntu (.deb)",
    fileRpm: "Fedora, openSUSE (.rpm)",
    fileArch: "Arch, CachyOS (.pkg.tar.zst)",
    fileChrome: "Chrome, Edge, Brave (.zip)",
    fileFirefox: "Firefox (.zip)",
  },
  es: {
    docTitle: "Keyless: tus contraseñas, solo tuyas",
    docDescription:
      "Gestor de contraseñas de código abierto para Windows y Linux. Todo se cifra en tu dispositivo; el servidor solo guarda lo que no puede leer.",
    skip: "Saltar al contenido",
    nav: "Secciones",
    navHow: "Cómo funciona",
    navTools: "Herramientas",
    navDownload: "Descargar",
    language: "Idioma",
    eyebrow: "Gestor de contraseñas · Windows y Linux · Código abierto",
    title: "La llave se queda <em>contigo.</em>",
    lede: "Contraseñas, tarjetas, llaves de acceso y archivos, cifrados en tu ordenador antes de salir de él. El servidor guarda solo lo que no puede leer, y ni nosotros podemos abrirlo.",
    youType: "Tú escribes",
    leaves: "Sale de tu ordenador",
    specimenCaption: "XChaCha20-Poly1305 con una clave que nace de tu contraseña maestra y tu Clave Secreta.",
    download: "Descargar Keyless",
    downloadFor: "Descargar para {os}",
    otherVersions: "Otras versiones",
    howTitle: "Cómo funciona",
    step1Title: "Dos cosas que solo tú tienes",
    step1: "Tu contraseña maestra, que está en tu cabeza, y la Clave Secreta, creada en tu dispositivo y guardada en el Kit de emergencia. Juntas forman la llave de tu cuenta.",
    step2Title: "Todo se cifra aquí",
    step2: "Cada elemento se cifra en tu ordenador, ligado a su bóveda y a sí mismo. Cambiar o intercambiar algo por el camino hace fallar el descifrado en vez de engañarte.",
    step3Title: "El servidor solo sincroniza",
    step3: "Tus dispositivos intercambian texto cifrado. Funciona sin internet, y un conflicto entre dos dispositivos nunca pierde nada: quedan las dos versiones.",
    ledgerTitle: "Lo que ve el servidor",
    sees: "Ve",
    sees1: "Tu correo",
    sees2: "Cuántas bóvedas y elementos tienes",
    sees3: "Cuándo cambia algo",
    sees4: "El tamaño aproximado de cada cosa",
    never: "Nunca ve",
    never1: "Tus contraseñas",
    never2: "Los nombres de tus sitios y elementos",
    never3: "Tus notas y tus archivos",
    never4: "Tu contraseña maestra y tu Clave Secreta",
    ledgerNote:
      'No hay forma de recuperar la contraseña maestra por correo. Eso es lo que garantiza que nadie, ni quien gestiona el servidor, pueda abrir tu cuenta. <a href="https://github.com/DiegoCastroAlves/Keyless/blob/main/docs/SECURITY.md">Lee el diseño de seguridad.</a>',
    toolsTitle: "Herramientas",
    t1: "Autocompletar",
    d1: "Inicios de sesión, tarjetas y direcciones en Chrome, Edge, Brave y Firefox, y ofrece guardar lo que escribes.",
    t2: "Llaves de acceso",
    d2: "Passkeys creadas y usadas por Keyless, en cualquier navegador donde esté.",
    t3: "Watchtower",
    d3: "Contraseñas débiles, repetidas o filtradas, sitios sin HTTPS y tarjetas a punto de caducar.",
    t4: "Adjuntos",
    d4: "Documentos dentro de los elementos, cifrados por partes antes de subir.",
    t5: "Compartir",
    d5: "Un enlace para que alguien sin Keyless vea un elemento, por tiempo limitado o una sola vez.",
    t6: "Agente SSH",
    d6: "Claves SSH para la terminal y para firmar commits, con aprobación en cada uso.",
    t7: "Generador",
    d7: "Contraseñas y frases aleatorias, con historial de lo generado.",
    t8: "Importar",
    d8: "Desde 1Password, Bitwarden, Chrome, Edge y Firefox.",
    t9: "Desbloqueo",
    d9: "Con la contraseña maestra, la contraseña del ordenador en Linux o Windows Hello.",
    downloadTitle: "Descargar",
    releaseLoading: "Buscando la versión más reciente…",
    releaseLine: "Versión {version}, publicada el {date}. Vista previa: aún en desarrollo.",
    releaseError: "No se pudo consultar GitHub ahora. Las versiones están en el enlace de abajo.",
    extension: "Extensión del navegador",
    allReleases: "Todas las versiones en GitHub",
    noFiles: "Nada en esta versión",
    source: "Código fuente",
    security: "Seguridad",
    madeBy: "Hecho por Diego Castro Alves",
    fileExe: "Instalador",
    fileAppImage: "AppImage (cualquier distribución)",
    fileDeb: "Debian, Ubuntu (.deb)",
    fileRpm: "Fedora, openSUSE (.rpm)",
    fileArch: "Arch, CachyOS (.pkg.tar.zst)",
    fileChrome: "Chrome, Edge, Brave (.zip)",
    fileFirefox: "Firefox (.zip)",
  },
};

const EXAMPLES: Record<Lang, string[]> = {
  "pt-BR": ["minha senha do banco", "cartão final 4111", "senha do Wi-Fi de casa", "chave SSH do trabalho", "códigos do Gmail"],
  en: ["my bank password", "card ending in 4111", "home Wi-Fi password", "work SSH key", "Gmail backup codes"],
  es: ["mi contraseña del banco", "tarjeta terminada en 4111", "contraseña del Wi-Fi de casa", "clave SSH del trabajo", "códigos de Gmail"],
};

// ----- Language ---------------------------------------------------------------

function storedLang(): Lang | null {
  try {
    const value = localStorage.getItem("lang");
    return LANGS.includes(value as Lang) ? (value as Lang) : null;
  } catch {
    return null;
  }
}

function detectLang(): Lang {
  const asked = new URLSearchParams(location.search).get("lang");
  if (LANGS.includes(asked as Lang)) return asked as Lang;
  const stored = storedLang();
  if (stored) return stored;
  for (const l of navigator.languages ?? [navigator.language]) {
    const lower = l.toLowerCase();
    if (lower.startsWith("pt")) return "pt-BR";
    if (lower.startsWith("es")) return "es";
    if (lower.startsWith("en")) return "en";
  }
  return "en";
}

let lang: Lang = detectLang();
const t = (key: string, vars: Record<string, string> = {}) => (TEXT[lang][key] ?? TEXT.en[key] ?? key).replace(/\{(\w+)\}/g, (_, n) => vars[n] ?? "");

function applyLang() {
  document.documentElement.lang = lang;
  document.title = t("docTitle");
  document.querySelector('meta[name="description"]')?.setAttribute("content", t("docDescription"));
  for (const el of document.querySelectorAll<HTMLElement>("[data-i18n]")) el.textContent = t(el.dataset.i18n!);
  // Only strings from TEXT above, which hold no outside data.
  for (const el of document.querySelectorAll<HTMLElement>("[data-i18n-html]")) el.innerHTML = t(el.dataset.i18nHtml!);
  for (const el of document.querySelectorAll<HTMLElement>("[data-i18n-aria]")) el.setAttribute("aria-label", t(el.dataset.i18nAria!));
  for (const button of document.querySelectorAll<HTMLButtonElement>(".lang button")) {
    button.setAttribute("aria-pressed", String(button.dataset.lang === lang));
  }
  renderRelease();
  example = 0;
}

for (const button of document.querySelectorAll<HTMLButtonElement>(".lang button")) {
  button.addEventListener("click", () => {
    lang = button.dataset.lang as Lang;
    try {
      localStorage.setItem("lang", lang);
    } catch {
      // Private window: the choice lasts for this page only.
    }
    applyLang();
  });
}

// ----- Specimen ---------------------------------------------------------------

const plainEl = document.getElementById("plain")!;
const cipherEl = document.getElementById("cipher")!;
const still = matchMedia("(prefers-reduced-motion: reduce)");
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
let example = 0;

const noise = (length: number) => Array.from(crypto.getRandomValues(new Uint8Array(length)), (b) => ALPHABET[b & 63]).join("");

/** What Keyless sends for `text`: an envelope as long as the real one
 * (padded to 64 bytes, plus nonce and tag, in base64url). */
function envelopeFor(text: string): string {
  const bytes = Math.ceil((new TextEncoder().encode(text).length + 1) / 64) * 64 + 24 + 16;
  return "k1." + noise(Math.ceil((bytes * 4) / 3));
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function cycle() {
  for (;;) {
    const text = EXAMPLES[lang][example % EXAMPLES[lang].length];
    example++;
    const target = envelopeFor(text);
    if (still.matches) {
      plainEl.textContent = text;
      cipherEl.textContent = target;
      await sleep(5000);
      continue;
    }
    plainEl.textContent = "";
    cipherEl.textContent = "";
    for (let i = 1; i <= text.length; i++) {
      plainEl.textContent = text.slice(0, i);
      await sleep(45 + Math.random() * 50);
    }
    await sleep(350);
    // The envelope settles from left to right out of noise.
    for (let step = 3; step <= target.length; step += 3) {
      cipherEl.textContent = target.slice(0, step) + noise(target.length - step);
      await sleep(22);
    }
    cipherEl.textContent = target;
    await sleep(3200);
  }
}

// ----- Downloads --------------------------------------------------------------

interface Asset {
  name: string;
  size: number;
  browser_download_url: string;
}
interface Release {
  tag_name: string;
  draft: boolean;
  published_at: string;
  assets: Asset[];
}

let release: Release | null = null;
let releaseFailed = false;

const KINDS: { test: RegExp; platform: "windows" | "linux" | "extension"; label: string }[] = [
  { test: /_x64-setup\.exe$/, platform: "windows", label: "fileExe" },
  { test: /\.AppImage$/, platform: "linux", label: "fileAppImage" },
  { test: /\.deb$/, platform: "linux", label: "fileDeb" },
  { test: /\.rpm$/, platform: "linux", label: "fileRpm" },
  { test: /\.pkg\.tar\.zst$/, platform: "linux", label: "fileArch" },
  { test: /^keyless-chrome-.*\.zip$/, platform: "extension", label: "fileChrome" },
  { test: /^keyless-firefox-.*\.zip$/, platform: "extension", label: "fileFirefox" },
];
const DOWNLOAD_PREFIX = `https://github.com/${REPO}/releases/download/`;

function os(): "windows" | "linux" | null {
  const platform = ((navigator as Navigator & { userAgentData?: { platform?: string } }).userAgentData?.platform ?? navigator.userAgent).toLowerCase();
  if (platform.includes("win")) return "windows";
  if (platform.includes("linux") && !platform.includes("android")) return "linux";
  return null;
}

function size(bytes: number): string {
  if (bytes < 1048576) return `${Math.max(1, Math.round(bytes / 1024)).toLocaleString(lang)} KB`;
  return `${(bytes / 1048576).toLocaleString(lang, { maximumFractionDigits: bytes < 10 * 1048576 ? 1 : 0 })} MB`;
}

function renderRelease() {
  const line = document.getElementById("release-line")!;
  if (!release) {
    line.textContent = t(releaseFailed ? "releaseError" : "releaseLoading");
    return;
  }
  const date = new Date(release.published_at).toLocaleDateString(lang, { dateStyle: "long" });
  line.textContent = t("releaseLine", { version: release.tag_name, date });
  const assets = release.assets.filter((a) => a.browser_download_url.startsWith(DOWNLOAD_PREFIX));
  for (const list of document.querySelectorAll<HTMLUListElement>(".files")) {
    list.replaceChildren();
    for (const kind of KINDS.filter((k) => k.platform === list.dataset.platform)) {
      const asset = assets.find((a) => kind.test.test(a.name));
      if (!asset) continue;
      const link = document.createElement("a");
      link.href = asset.browser_download_url;
      const name = document.createElement("span");
      name.textContent = t(kind.label);
      const meta = document.createElement("span");
      meta.textContent = size(asset.size);
      link.append(name, meta);
      const item = document.createElement("li");
      item.append(link);
      list.append(item);
    }
    if (!list.childElementCount) {
      const item = document.createElement("li");
      item.className = "empty";
      item.textContent = t("noFiles");
      list.append(item);
    }
  }
  // The main button: the right file for this computer.
  const mine = os();
  const preferred = mine === "windows" ? /_x64-setup\.exe$/ : mine === "linux" ? /\.AppImage$/ : null;
  const asset = preferred ? assets.find((a) => preferred.test(a.name)) : null;
  const primary = document.getElementById("primary-download") as HTMLAnchorElement;
  const label = document.getElementById("primary-label")!;
  if (asset && mine) {
    primary.href = asset.browser_download_url;
    label.textContent = t("downloadFor", { os: mine === "windows" ? "Windows" : "Linux" });
  } else {
    primary.href = "#baixar";
    label.textContent = t("download");
  }
  document.getElementById("primary-version")!.textContent = release.tag_name;
}

async function loadRelease() {
  try {
    const response = await fetch(`https://api.github.com/repos/${REPO}/releases?per_page=10`, {
      headers: { Accept: "application/vnd.github+json" },
      referrerPolicy: "no-referrer",
    });
    if (!response.ok) throw new Error(String(response.status));
    const releases = (await response.json()) as Release[];
    release = releases.find((r) => !r.draft && Array.isArray(r.assets)) ?? null;
    if (!release) releaseFailed = true;
  } catch {
    releaseFailed = true;
  }
  renderRelease();
}

applyLang();
void cycle();
void loadRelease();
