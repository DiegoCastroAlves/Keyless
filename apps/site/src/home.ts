// The home page (keyless.diegoalves.dev): its texts in the visitor's
// language, the "what leaves your computer" specimen, the downloads of the
// newest release, read from GitHub, and how to install each of them.
// Everything is set as text; the only HTML used comes from the dictionary
// below.

import { prefsMenu } from "./prefs";

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
    navVault: "Cofre web",
    language: "Idioma",
    prefs: "Idioma e tema",
    theme: "Tema",
    themeSystem: "Sistema",
    themeLight: "Claro",
    themeDark: "Escuro",
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
    t3: "Sentinela",
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
    privacy: "Privacidade",
    madeBy: "Feito por Diego Castro Alves",
    fileExe: "Instalador",
    fileAppImage: "AppImage (qualquer distribuição)",
    fileDeb: "Debian, Ubuntu (.deb)",
    fileRpm: "Fedora, openSUSE (.rpm)",
    fileArch: "Arch, CachyOS (.pkg.tar.zst)",
    fileChrome: "Chrome, Edge, Brave (.zip)",
    fileFirefox: "Firefox (.zip)",
    navInstall: "Instalar",
    howToInstall: "Como instalar cada arquivo",
    installTitle: "Como instalar",
    installIntro: "Escolha o arquivo que você baixou. Os comandos já trazem o nome do arquivo da versão mais recente: é só copiar e colar no terminal.",
    formats: "Tipo de arquivo",
    formatAny: "Qualquer distribuição",
    formatExe: "Instalador .exe",
    leadAppImage: "Um arquivo só, que roda em qualquer distribuição sem instalar nada.",
    leadDeb: "Para Debian, Ubuntu, Linux Mint, Pop!_OS e outras distribuições baseadas neles.",
    leadRpm: "Para Fedora e openSUSE.",
    leadArch: "Para o Arch Linux e derivados, como CachyOS, Manjaro e EndeavourOS.",
    leadWindows: "Para o Windows de 64 bits.",
    stepDownload: "Baixe o arquivo",
    fileLoading: "procurando…",
    stepRun: "Deixe executável e abra",
    stepInstall: "Instale",
    stepOpen: "Abra o Keyless",
    inFolder: "No terminal, na pasta onde o arquivo foi salvo (em geral, Downloads):",
    noteRun: "Também dá pelo gerenciador de arquivos: nas propriedades do arquivo, permita que ele seja executado como programa e abra com dois cliques.",
    stepMenu: "Coloque no menu (opcional)",
    textMenu: "O AppImage não entra sozinho no menu de aplicativos. Um integrador de AppImages, como o Gear Lever, cria o atalho para você.",
    noteDeb:
      "O <code>./</code> avisa o apt que é um arquivo desta pasta, e ele baixa o que mais faltar. Se preferir, abra o arquivo no instalador de pacotes da sua distribuição.",
    noteRpm:
      "No openSUSE, o <code>--allow-unsigned-rpm</code> é necessário porque o pacote ainda não tem assinatura GPG: sem ele, o zypper avisa que o pacote não está assinado e pergunta se deve ignorar.",
    noteArch: "O pacman instala junto as dependências que faltarem, como o <code>webkit2gtk-4.1</code>.",
    openMenu: "Ele aparece no menu de aplicativos.",
    stepInstaller: "Abra o instalador",
    textInstaller: "Dê dois cliques no arquivo baixado. O Keyless é instalado só para o seu usuário, sem pedir permissão de administrador.",
    stepSmartScreen: "Se o Windows avisar",
    textSmartScreen:
      "O instalador ainda não tem assinatura de código, então o SmartScreen pode mostrar “O Windows protegeu o computador”. Clique em <strong>Mais informações</strong> e depois em <strong>Executar assim mesmo</strong>.",
    smartScreenTitle: "O Windows protegeu o computador",
    smartScreenMore: "Mais informações",
    smartScreenRun: "Executar assim mesmo",
    smartScreenDont: "Não executar",
    openStart: "Ele fica no menu Iniciar.",
    updatesTitle: "Atualizações",
    updatesAppImage:
      "Duas vezes por dia, o Keyless confere se saiu uma versão nova e avisa. Em <strong>Atualizar agora</strong>, ele baixa a versão nova, confere a assinatura dela e troca o próprio arquivo.",
    updatesPackage:
      "Duas vezes por dia, o Keyless confere se saiu uma versão nova e avisa. Em <strong>Atualizar agora</strong>, ele baixa o pacote, confere a assinatura e instala; o sistema pede a sua senha.",
    updatesArch:
      "Duas vezes por dia, o Keyless confere se saiu uma versão nova e avisa. Em <strong>Atualizar agora</strong>, ele baixa o pacote, confere a assinatura e instala com o pacman; o sistema pede a sua senha.",
    updatesWindows:
      "Duas vezes por dia, o Keyless confere se saiu uma versão nova e avisa. Em <strong>Atualizar agora</strong>, ele baixa o instalador, confere a assinatura e se atualiza sozinho.",
    tipsTitle: "Bom saber",
    tipFuse:
      "Se ele não abrir e reclamar do FUSE (“Cannot mount AppImage”), instale o pacote <code>fuse3</code>, por exemplo com <code>sudo apt install fuse3</code>.",
    tipUnlock: "Desbloquear com a senha do computador só funciona com o pacote da sua distribuição (.deb, .rpm ou Arch), não com o AppImage.",
    tipMove: "Se mudar o arquivo de lugar, abra o Keyless uma vez pelo novo caminho, para a extensão do navegador encontrá-lo.",
    tipApt: "Se o apt mostrar “Download is performed unsandboxed as root”, pode ignorar: é só um aviso, e a instalação segue normalmente.",
    terminal: "Terminal",
    copy: "Copiar",
    copied: "Copiado",
    copiedStatus: "Comando copiado.",
    copyFailed: "Use Ctrl+C",
    afterTitle: "Depois de instalar",
    afterAccount:
      "Abra o Keyless e escolha <strong>Criar uma nova conta</strong>, ou entre na que você já tem. Guarde bem o Kit de Emergência: é nele que fica a sua Chave Secreta.",
    afterBrowser:
      'Para preencher senhas no navegador, instale a extensão (<a href="https://github.com/DiegoCastroAlves/Keyless#browser-extension">veja como</a>) e pratique no <a href="/tutorial/">tutorial</a>.',
  },
  en: {
    docTitle: "Keyless: your passwords, only yours",
    docDescription: "Open-source password manager for Windows and Linux. Everything is encrypted on your device; the server keeps only what it cannot read.",
    skip: "Skip to content",
    nav: "Sections",
    navHow: "How it works",
    navTools: "Tools",
    navDownload: "Download",
    navVault: "Web vault",
    language: "Language",
    prefs: "Language and theme",
    theme: "Theme",
    themeSystem: "System",
    themeLight: "Light",
    themeDark: "Dark",
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
    t3: "Sentinel",
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
    privacy: "Privacy",
    madeBy: "Made by Diego Castro Alves",
    fileExe: "Installer",
    fileAppImage: "AppImage (any distribution)",
    fileDeb: "Debian, Ubuntu (.deb)",
    fileRpm: "Fedora, openSUSE (.rpm)",
    fileArch: "Arch, CachyOS (.pkg.tar.zst)",
    fileChrome: "Chrome, Edge, Brave (.zip)",
    fileFirefox: "Firefox (.zip)",
    navInstall: "Install",
    howToInstall: "How to install each file",
    installTitle: "How to install",
    installIntro: "Pick the file you downloaded. The commands already carry the newest version's file name: just copy them and paste them into a terminal.",
    formats: "File type",
    formatAny: "Any distribution",
    formatExe: ".exe installer",
    leadAppImage: "A single file that runs on any distribution, with nothing to install.",
    leadDeb: "For Debian, Ubuntu, Linux Mint, Pop!_OS and other distributions based on them.",
    leadRpm: "For Fedora and openSUSE.",
    leadArch: "For Arch Linux and its derivatives, such as CachyOS, Manjaro and EndeavourOS.",
    leadWindows: "For 64-bit Windows.",
    stepDownload: "Download the file",
    fileLoading: "looking…",
    stepRun: "Make it executable and open it",
    stepInstall: "Install it",
    stepOpen: "Open Keyless",
    inFolder: "In a terminal, in the folder the file was saved to (usually Downloads):",
    noteRun: "The file manager works too: in the file's properties, allow it to run as a program, then double-click it.",
    stepMenu: "Add it to the menu (optional)",
    textMenu: "An AppImage does not add itself to the applications menu. An AppImage manager such as Gear Lever makes the shortcut for you.",
    noteDeb:
      "The <code>./</code> tells apt it is a file in this folder, and apt fetches whatever else is missing. If you prefer, open the file in your distribution's package installer.",
    noteRpm:
      "On openSUSE, <code>--allow-unsigned-rpm</code> is needed because the package has no GPG signature yet: without it, zypper warns that the package is not signed and asks whether to ignore that.",
    noteArch: "pacman also installs any missing dependencies, such as <code>webkit2gtk-4.1</code>.",
    openMenu: "It is in the applications menu.",
    stepInstaller: "Run the installer",
    textInstaller: "Double-click the downloaded file. Keyless is installed for your user only, without asking for administrator rights.",
    stepSmartScreen: "If Windows warns you",
    textSmartScreen:
      "The installer is not code-signed yet, so SmartScreen may show “Windows protected your PC”. Click <strong>More info</strong>, then <strong>Run anyway</strong>.",
    smartScreenTitle: "Windows protected your PC",
    smartScreenMore: "More info",
    smartScreenRun: "Run anyway",
    smartScreenDont: "Don't run",
    openStart: "It is in the Start menu.",
    updatesTitle: "Updates",
    updatesAppImage:
      "Twice a day, Keyless checks for a new version and tells you. With <strong>Update now</strong>, it downloads the new version, checks its signature and replaces its own file.",
    updatesPackage:
      "Twice a day, Keyless checks for a new version and tells you. With <strong>Update now</strong>, it downloads the package, checks its signature and installs it; your system asks for your password.",
    updatesArch:
      "Twice a day, Keyless checks for a new version and tells you. With <strong>Update now</strong>, it downloads the package, checks its signature and installs it with pacman; your system asks for your password.",
    updatesWindows:
      "Twice a day, Keyless checks for a new version and tells you. With <strong>Update now</strong>, it downloads the installer, checks its signature and updates itself.",
    tipsTitle: "Good to know",
    tipFuse:
      "If it does not open and complains about FUSE (“Cannot mount AppImage”), install the <code>fuse3</code> package, for example with <code>sudo apt install fuse3</code>.",
    tipUnlock: "Unlocking with your computer's password needs your distribution's package (.deb, .rpm or Arch), not the AppImage.",
    tipMove: "If you move the file, open Keyless once from its new place, so that the browser extension finds it.",
    tipApt: "If apt says “Download is performed unsandboxed as root”, you can ignore it: it is only a notice, and the install goes on.",
    terminal: "Terminal",
    copy: "Copy",
    copied: "Copied",
    copiedStatus: "Command copied.",
    copyFailed: "Press Ctrl+C",
    afterTitle: "After installing",
    afterAccount:
      "Open Keyless and choose <strong>Create a new account</strong>, or sign in to the one you have. Keep your Emergency Kit safe: it holds your Secret Key.",
    afterBrowser:
      'To fill in passwords in your browser, install the extension (<a href="https://github.com/DiegoCastroAlves/Keyless#browser-extension">see how</a>) and practice in the <a href="/tutorial/">tutorial</a>.',
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
    navVault: "Bóveda web",
    language: "Idioma",
    prefs: "Idioma y tema",
    theme: "Tema",
    themeSystem: "Sistema",
    themeLight: "Claro",
    themeDark: "Oscuro",
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
    t3: "Centinela",
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
    privacy: "Privacidad",
    madeBy: "Hecho por Diego Castro Alves",
    fileExe: "Instalador",
    fileAppImage: "AppImage (cualquier distribución)",
    fileDeb: "Debian, Ubuntu (.deb)",
    fileRpm: "Fedora, openSUSE (.rpm)",
    fileArch: "Arch, CachyOS (.pkg.tar.zst)",
    fileChrome: "Chrome, Edge, Brave (.zip)",
    fileFirefox: "Firefox (.zip)",
    navInstall: "Instalar",
    howToInstall: "Cómo instalar cada archivo",
    installTitle: "Cómo instalar",
    installIntro:
      "Elige el archivo que descargaste. Los comandos ya llevan el nombre del archivo de la versión más reciente: solo tienes que copiarlos y pegarlos en la terminal.",
    formats: "Tipo de archivo",
    formatAny: "Cualquier distribución",
    formatExe: "Instalador .exe",
    leadAppImage: "Un solo archivo que funciona en cualquier distribución, sin instalar nada.",
    leadDeb: "Para Debian, Ubuntu, Linux Mint, Pop!_OS y otras distribuciones basadas en ellas.",
    leadRpm: "Para Fedora y openSUSE.",
    leadArch: "Para Arch Linux y sus derivadas, como CachyOS, Manjaro y EndeavourOS.",
    leadWindows: "Para Windows de 64 bits.",
    stepDownload: "Descarga el archivo",
    fileLoading: "buscando…",
    stepRun: "Hazlo ejecutable y ábrelo",
    stepInstall: "Instálalo",
    stepOpen: "Abre Keyless",
    inFolder: "En la terminal, en la carpeta donde se guardó el archivo (normalmente Descargas):",
    noteRun: "También desde el gestor de archivos: en las propiedades del archivo, permite ejecutarlo como programa y ábrelo con doble clic.",
    stepMenu: "Añádelo al menú (opcional)",
    textMenu: "Un AppImage no aparece solo en el menú de aplicaciones. Un gestor de AppImage, como Gear Lever, crea el acceso directo por ti.",
    noteDeb:
      "El <code>./</code> le indica a apt que es un archivo de esta carpeta, y apt descarga lo que falte. Si lo prefieres, abre el archivo en el instalador de paquetes de tu distribución.",
    noteRpm:
      "En openSUSE hace falta <code>--allow-unsigned-rpm</code> porque el paquete aún no tiene firma GPG: sin esa opción, zypper avisa de que el paquete no está firmado y pregunta si quieres ignorarlo.",
    noteArch: "pacman instala también las dependencias que falten, como <code>webkit2gtk-4.1</code>.",
    openMenu: "Aparece en el menú de aplicaciones.",
    stepInstaller: "Abre el instalador",
    textInstaller: "Haz doble clic en el archivo descargado. Keyless se instala solo para tu usuario, sin pedir permisos de administrador.",
    stepSmartScreen: "Si Windows te avisa",
    textSmartScreen:
      "El instalador aún no tiene firma de código, así que SmartScreen puede mostrar «Windows protegió su PC». Haz clic en <strong>Más información</strong> y luego en <strong>Ejecutar de todas formas</strong>.",
    smartScreenTitle: "Windows protegió su PC",
    smartScreenMore: "Más información",
    smartScreenRun: "Ejecutar de todas formas",
    smartScreenDont: "No ejecutar",
    openStart: "Está en el menú Inicio.",
    updatesTitle: "Actualizaciones",
    updatesAppImage:
      "Dos veces al día, Keyless comprueba si hay una versión nueva y te avisa. Con <strong>Actualizar ahora</strong>, la descarga, verifica su firma y reemplaza su propio archivo.",
    updatesPackage:
      "Dos veces al día, Keyless comprueba si hay una versión nueva y te avisa. Con <strong>Actualizar ahora</strong>, descarga el paquete, verifica su firma y lo instala; tu sistema te pide la contraseña.",
    updatesArch:
      "Dos veces al día, Keyless comprueba si hay una versión nueva y te avisa. Con <strong>Actualizar ahora</strong>, descarga el paquete, verifica su firma y lo instala con pacman; tu sistema te pide la contraseña.",
    updatesWindows:
      "Dos veces al día, Keyless comprueba si hay una versión nueva y te avisa. Con <strong>Actualizar ahora</strong>, descarga el instalador, verifica su firma y se actualiza solo.",
    tipsTitle: "Conviene saber",
    tipFuse:
      "Si no se abre y se queja de FUSE («Cannot mount AppImage»), instala el paquete <code>fuse3</code>, por ejemplo con <code>sudo apt install fuse3</code>.",
    tipUnlock: "Desbloquear con la contraseña del ordenador requiere el paquete de tu distribución (.deb, .rpm o Arch), no el AppImage.",
    tipMove: "Si mueves el archivo, abre Keyless una vez desde su nuevo lugar, para que la extensión del navegador lo encuentre.",
    tipApt: "Si apt dice «Download is performed unsandboxed as root», puedes ignorarlo: es solo un aviso y la instalación sigue normalmente.",
    terminal: "Terminal",
    copy: "Copiar",
    copied: "Copiado",
    copiedStatus: "Comando copiado.",
    copyFailed: "Pulsa Ctrl+C",
    afterTitle: "Después de instalar",
    afterAccount:
      "Abre Keyless y elige <strong>Crear una cuenta nueva</strong>, o inicia sesión en la que ya tienes. Guarda bien tu Kit de emergencia: en él está tu Clave Secreta.",
    afterBrowser:
      'Para rellenar contraseñas en el navegador, instala la extensión (<a href="https://github.com/DiegoCastroAlves/Keyless#browser-extension">mira cómo</a>) y practica en el <a href="/tutorial/">tutorial</a>.',
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
// The language and theme menu in the header.
const namePrefs = prefsMenu(document.querySelector<HTMLElement>(".prefs")!, t, {
  current: () => lang,
  choose: (next) => {
    lang = next;
    try {
      localStorage.setItem("lang", lang);
    } catch {
      // Private window: the choice lasts for this page only.
    }
    applyLang();
  },
});

function applyLang() {
  document.documentElement.lang = lang;
  document.title = t("docTitle");
  document.querySelector('meta[name="description"]')?.setAttribute("content", t("docDescription"));
  for (const el of document.querySelectorAll<HTMLElement>("[data-i18n]")) el.textContent = t(el.dataset.i18n!);
  // Only strings from TEXT above, which hold no outside data.
  for (const el of document.querySelectorAll<HTMLElement>("[data-i18n-html]")) el.innerHTML = t(el.dataset.i18nHtml!);
  for (const el of document.querySelectorAll<HTMLElement>("[data-i18n-aria]")) el.setAttribute("aria-label", t(el.dataset.i18nAria!));
  namePrefs();
  renderRelease();
  example = 0;
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
    // Faint noise as long as the envelope keeps the box the same size while
    // the text is typed.
    cipherEl.textContent = noise(target.length);
    cipherEl.classList.add("waiting");
    for (let i = 1; i <= text.length; i++) {
      plainEl.textContent = text.slice(0, i);
      await sleep(45 + Math.random() * 50);
    }
    await sleep(350);
    cipherEl.classList.remove("waiting");
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

type Guide = "appimage" | "deb" | "rpm" | "arch" | "windows";

// Each file with its install guide (below), if it has one.
const KINDS: { test: RegExp; platform: "windows" | "linux" | "extension"; label: string; guide?: Guide }[] = [
  { test: /_x64-setup\.exe$/, platform: "windows", label: "fileExe", guide: "windows" },
  { test: /\.AppImage$/, platform: "linux", label: "fileAppImage", guide: "appimage" },
  { test: /\.deb$/, platform: "linux", label: "fileDeb", guide: "deb" },
  { test: /\.rpm$/, platform: "linux", label: "fileRpm", guide: "rpm" },
  { test: /\.pkg\.tar\.zst$/, platform: "linux", label: "fileArch", guide: "arch" },
  { test: /^keyless-chrome-.*\.zip$/, platform: "extension", label: "fileChrome" },
  { test: /^keyless-firefox-.*\.zip$/, platform: "extension", label: "fileFirefox" },
];
const DOWNLOAD_PREFIX = `https://github.com/${REPO}/releases/download/`;
const RELEASES_PAGE = `https://github.com/${REPO}/releases`;

/** The newest release's files that come from this repository. */
const releaseAssets = () => release?.assets.filter((a) => a.browser_download_url.startsWith(DOWNLOAD_PREFIX)) ?? [];

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
  fillGuides();
  const line = document.getElementById("release-line")!;
  if (!release) {
    line.textContent = t(releaseFailed ? "releaseError" : "releaseLoading");
    return;
  }
  const date = new Date(release.published_at).toLocaleDateString(lang, { dateStyle: "long" });
  line.textContent = t("releaseLine", { version: release.tag_name, date });
  const assets = releaseAssets();
  for (const list of document.querySelectorAll<HTMLUListElement>(".files")) {
    list.replaceChildren();
    for (const kind of KINDS.filter((k) => k.platform === list.dataset.platform)) {
      const asset = assets.find((a) => kind.test.test(a.name));
      if (!asset) continue;
      const link = document.createElement("a");
      link.href = asset.browser_download_url;
      if (kind.guide) link.dataset.guide = kind.guide;
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
    primary.dataset.guide = mine === "windows" ? "windows" : "appimage";
    label.textContent = t("downloadFor", { os: mine === "windows" ? "Windows" : "Linux" });
  } else {
    primary.href = "#baixar";
    delete primary.dataset.guide;
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

// ----- Install guides ---------------------------------------------------------

/** A step after "Download the file" (text keys; the texts may hold HTML from
 * the dictionary). The terminals' lines are commands, with {file} for the
 * downloaded file's name. */
interface Step {
  title: string;
  text?: string;
  /** One terminal each, captioned with its system's name if there are several. */
  terminals?: { system?: string; lines: string[] }[];
  note?: string;
  smartScreen?: boolean;
}

// As the release workflow builds the files (.github/workflows/release.yml),
// and as the app updates itself (apps/desktop/src-tauri/src/updates.rs).
const GUIDES: Record<Guide, { lead: string; pattern: string; steps: Step[]; tips: string[]; updates: string }> = {
  appimage: {
    lead: "leadAppImage",
    pattern: "Keyless_*_amd64.AppImage",
    steps: [
      { title: "stepRun", text: "inFolder", terminals: [{ lines: ["chmod +x {file}", "./{file}"] }], note: "noteRun" },
      { title: "stepMenu", text: "textMenu" },
    ],
    // Its runtime is the static one: it needs fusermount (fuse3), not libfuse2.
    tips: ["tipFuse", "tipUnlock", "tipMove"],
    updates: "updatesAppImage",
  },
  deb: {
    lead: "leadDeb",
    pattern: "Keyless_*_amd64.deb",
    steps: [
      { title: "stepInstall", text: "inFolder", terminals: [{ lines: ["sudo apt install ./{file}"] }], note: "noteDeb" },
      { title: "stepOpen", text: "openMenu" },
    ],
    tips: ["tipApt"],
    updates: "updatesPackage",
  },
  rpm: {
    lead: "leadRpm",
    pattern: "Keyless-*.x86_64.rpm",
    steps: [
      {
        title: "stepInstall",
        text: "inFolder",
        // The package carries digests but no GPG signature, which zypper
        // asks about for a local file (dnf, by default, does not check it).
        terminals: [
          { system: "Fedora", lines: ["sudo dnf install ./{file}"] },
          { system: "openSUSE", lines: ["sudo zypper install --allow-unsigned-rpm ./{file}"] },
        ],
        note: "noteRpm",
      },
      { title: "stepOpen", text: "openMenu" },
    ],
    tips: [],
    updates: "updatesPackage",
  },
  arch: {
    lead: "leadArch",
    pattern: "keyless-*-x86_64.pkg.tar.zst",
    steps: [
      { title: "stepInstall", text: "inFolder", terminals: [{ lines: ["sudo pacman -U ./{file}"] }], note: "noteArch" },
      { title: "stepOpen", text: "openMenu" },
    ],
    tips: [],
    updates: "updatesArch",
  },
  windows: {
    lead: "leadWindows",
    pattern: "Keyless_*_x64-setup.exe",
    steps: [
      { title: "stepInstaller", text: "textInstaller" },
      // The installer is not code-signed yet.
      { title: "stepSmartScreen", text: "textSmartScreen", smartScreen: true },
      { title: "stepOpen", text: "openStart" },
    ],
    tips: [],
    updates: "updatesWindows",
  },
};
const GUIDE_IDS = Object.keys(GUIDES) as Guide[];

// A file name that can be pasted into a terminal as it is.
const PLAIN_NAME = /^[\w.+-]+$/;

/** An element whose text comes from the dictionary: applyLang sets it, and
 * sets it again when the language changes. */
function element<K extends keyof HTMLElementTagNameMap>(tag: K, className = "", key?: string, html = false): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (key) node.dataset[html ? "i18nHtml" : "i18n"] = key;
  return node;
}

// Drawn like the header's icons (16px, stroked; theme.css).
const GUIDE_ICONS = {
  copy: ["M5.75 5.75h7.5v7.5h-7.5z", "M10.25 5.75v-3h-7.5v7.5h3"],
  done: ["M3 8.5l3.25 3.25L13 5"],
  download: ["M8 2v8.5M4.5 7 8 10.5 11.5 7M2.75 13.75h10.5"],
  update: ["M14 8a6 6 0 1 1-6-6c1.68 0 3.29.67 4.49 1.83L14 5.33", "M14 2v3.33h-3.33"],
};

function icon(name: keyof typeof GUIDE_ICONS): SVGSVGElement {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("aria-hidden", "true");
  svg.classList.add(`icon-${name}`);
  for (const d of GUIDE_ICONS[name]) {
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", d);
    svg.append(path);
  }
  return svg;
}

const copyTimers = new WeakMap<HTMLButtonElement, number>();

/** Copies the terminal's commands, one per line, and says so on the button
 * for a moment. */
async function copyCommands(button: HTMLButtonElement, code: HTMLElement) {
  const text = Array.from(code.querySelectorAll(".term-command"), (command) => command.textContent).join("\n");
  const status = document.getElementById("copy-status")!;
  let copied = true;
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // No clipboard here (an older browser, or it was refused): the commands
    // are selected for Ctrl+C instead. The prompts cannot be selected.
    copied = false;
    getSelection()?.selectAllChildren(code);
  }
  const label = button.querySelector<HTMLElement>("[data-i18n]")!;
  const show = (key: string) => {
    label.dataset.i18n = key;
    label.textContent = t(key);
  };
  show(copied ? "copied" : "copyFailed");
  button.classList.toggle("copied", copied);
  status.textContent = copied ? t("copiedStatus") : "";
  clearTimeout(copyTimers.get(button));
  copyTimers.set(
    button,
    window.setTimeout(() => {
      show("copy");
      button.classList.remove("copied");
      status.textContent = "";
    }, 2000),
  );
}

/** A terminal with `lines` (fillGuides puts the file's name in them) and a
 * button that copies them. */
function terminal(system: string | undefined, lines: string[]): HTMLElement {
  const caption = element("span", "term-label", system ? undefined : "terminal");
  if (system) caption.textContent = system;
  const copy = element("button", "copy");
  copy.type = "button";
  copy.append(icon("copy"), icon("done"), element("span", "", "copy"));
  const bar = element("div", "term-bar");
  bar.append(caption, copy);
  const code = element("code");
  for (const line of lines) {
    const prompt = element("span", "term-prompt");
    prompt.textContent = "$";
    prompt.setAttribute("aria-hidden", "true");
    const command = element("span", "term-command");
    command.dataset.command = line;
    const row = element("span", "term-line");
    row.append(prompt, command);
    code.append(row);
  }
  const body = element("pre", "term-body");
  body.append(code);
  copy.addEventListener("click", () => void copyCommands(copy, code));
  const box = element("div", "term");
  box.append(bar, body);
  return box;
}

/** The file to download, filled in by fillGuides. */
function fileLink(): HTMLAnchorElement {
  const link = element("a", "guide-file mono");
  link.append(icon("download"), element("span", "guide-file-name"), element("span", "guide-file-size"));
  return link;
}

/** A sketch of the SmartScreen warning with its two clicks marked (the
 * step's text says the same, so it is hidden from screen readers). */
function smartScreen(): HTMLElement {
  const mark = (n: string) => {
    const node = element("span", "smartscreen-mark mono");
    node.textContent = n;
    return node;
  };
  const more = element("span", "smartscreen-more");
  more.append(mark("1"), element("span", "", "smartScreenMore"));
  const run = element("span", "smartscreen-button target");
  run.append(mark("2"), element("span", "", "smartScreenRun"));
  const actions = element("span", "smartscreen-actions");
  actions.append(run, element("span", "smartscreen-button", "smartScreenDont"));
  const sketch = element("div", "smartscreen");
  sketch.setAttribute("aria-hidden", "true");
  sketch.append(element("span", "smartscreen-title", "smartScreenTitle"), element("span", "smartscreen-text"), more, actions);
  return sketch;
}

function guideStep(step: Step, number: number, file?: HTMLElement): HTMLLIElement {
  const numeral = element("span", "guide-number mono");
  numeral.textContent = String(number).padStart(2, "0");
  numeral.setAttribute("aria-hidden", "true");
  const body = element("div", "guide-body");
  body.append(element("h3", "", step.title));
  if (step.text) body.append(element("p", "", step.text, true));
  if (file) body.append(file);
  for (const { system, lines } of step.terminals ?? []) body.append(terminal(system, lines));
  if (step.smartScreen) body.append(smartScreen());
  if (step.note) body.append(element("p", "guide-note", step.note, true));
  const item = element("li", "guide-step");
  item.append(numeral, body);
  return item;
}

/** Shows the guide for `id`, moving the focus to its tab if asked. */
function showGuide(id: Guide, focus = false) {
  for (const tab of document.querySelectorAll<HTMLButtonElement>(".format")) {
    const selected = tab.dataset.format === id;
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
    if (selected && focus) tab.focus();
  }
  for (const panel of document.querySelectorAll<HTMLElement>(".guide")) panel.hidden = panel.id !== `guide-${id}`;
}

/** Builds a panel for each guide under the tabs in the page, and opens the
 * one for this computer (the AppImage on Linux, as the main button). */
function buildGuides() {
  const container = document.getElementById("guides")!;
  for (const id of GUIDE_IDS) {
    const guide = GUIDES[id];
    const steps = element("ol", "guide-steps");
    steps.append(guideStep({ title: "stepDownload" }, 1, fileLink()), ...guide.steps.map((step, i) => guideStep(step, i + 2)));

    const updatesTitle = element("h3", "mono");
    updatesTitle.append(icon("update"), element("span", "", "updatesTitle"));
    const updates = element("div", "guide-box updates");
    updates.append(updatesTitle, element("p", "", guide.updates, true));
    const side = element("div", "guide-side");
    side.append(updates);
    if (guide.tips.length) {
      const list = element("ul");
      list.append(...guide.tips.map((tip) => element("li", "", tip, true)));
      const tips = element("div", "guide-box");
      tips.append(element("h3", "mono", "tipsTitle"), list);
      side.append(tips);
    }

    const panel = element("div", "guide");
    panel.id = `guide-${id}`;
    panel.setAttribute("role", "tabpanel");
    panel.setAttribute("aria-labelledby", `tab-${id}`);
    panel.append(element("p", "guide-lead", guide.lead), steps, side);
    container.append(panel);
  }

  const formats = document.querySelector<HTMLElement>(".formats")!;
  const tabs = Array.from(formats.querySelectorAll<HTMLButtonElement>(".format"));
  for (const tab of tabs) tab.addEventListener("click", () => showGuide(tab.dataset.format as Guide));
  formats.addEventListener("keydown", (event) => {
    const at = tabs.indexOf(document.activeElement as HTMLButtonElement);
    const next =
      event.key === "ArrowRight" ? (at + 1) % tabs.length
      : event.key === "ArrowLeft" ? (at - 1 + tabs.length) % tabs.length
      : event.key === "Home" ? 0
      : event.key === "End" ? tabs.length - 1
      : -1;
    if (at < 0 || next < 0) return;
    event.preventDefault();
    showGuide(tabs[next].dataset.format as Guide, true);
  });
  // A file chosen in the downloads, or the main button: its guide comes up
  // while it downloads.
  document.addEventListener("click", (event) => {
    if (!(event.target instanceof Element) || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    const link = event.target.closest<HTMLAnchorElement>("a[data-guide]");
    if (!link) return;
    showGuide(link.dataset.guide as Guide);
    document.getElementById("instalar")!.scrollIntoView({ block: "start" });
  });
  showGuide(os() === "windows" ? "windows" : "appimage");
}

/** Puts the newest release's file in each guide: its link, and its name in
 * the commands (a pattern for it until the release is read, or if GitHub
 * cannot be reached). */
function fillGuides() {
  const assets = releaseAssets();
  for (const id of GUIDE_IDS) {
    const kind = KINDS.find((k) => k.guide === id)!;
    const asset = assets.find((a) => kind.test.test(a.name) && PLAIN_NAME.test(a.name));
    const name = asset?.name ?? GUIDES[id].pattern;
    const panel = document.getElementById(`guide-${id}`)!;
    for (const command of panel.querySelectorAll<HTMLElement>(".term-command")) command.textContent = command.dataset.command!.replaceAll("{file}", name);
    const link = panel.querySelector<HTMLAnchorElement>(".guide-file")!;
    link.href = asset?.browser_download_url ?? RELEASES_PAGE;
    link.classList.toggle("pending", !asset);
    // On a narrow screen the name breaks after its _ and -, not mid-word.
    link.querySelector(".guide-file-name")!.replaceChildren(...name.split(/(?<=[_-])/).flatMap((part, i) => (i ? [document.createElement("wbr"), part] : [part])));
    link.querySelector(".guide-file-size")!.textContent = asset ? size(asset.size) : release || releaseFailed ? "GitHub" : t("fileLoading");
  }
}

buildGuides();
applyLang();
void cycle();
void loadRelease();
