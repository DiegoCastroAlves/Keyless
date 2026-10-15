# Política de privacidad de Keyless

Actualizada el 15 de octubre de 2026

Keyless es un gestor de contraseñas de conocimiento cero. Todo lo que
guardas en tus bóvedas se cifra en tu dispositivo antes de enviarse a
cualquier sitio, con claves que salen de tu contraseña maestra y tu Clave
Secreta. Ninguna de las dos sale de tus dispositivos, así que nadie más, ni
quien gestiona el servidor de Keyless, puede leer tus bóvedas.

## Qué guarda el servidor

- Tu correo electrónico, que identifica tu cuenta, y el idioma de la app
  cuando la creaste, usado solo para escribir en él los correos de la
  cuenta.
- Los datos cifrados de tus bóvedas, tu clave pública y tus claves cifradas.
- Metadatos técnicos para sincronizar: cuántas bóvedas y elementos tienes,
  su tamaño aproximado y cuándo cambian.
- Registros de conexión del proveedor de alojamiento (dirección IP, hora,
  tipo de petición), por seguridad y operación.
- Para cada dispositivo con la sesión iniciada en tu cuenta: la dirección IP
  y el país de su última conexión y cuándo se usó por última vez, para que
  veas dónde está abierta tu cuenta y puedas cerrar la sesión de un
  dispositivo. El nombre y el sistema del dispositivo se cifran como tus
  bóvedas.
- Para cada llave de acceso (passkey) que añadas para iniciar sesión: el ID
  de la credencial, cuándo se añadió y se usó por última vez, y su nombre y
  una copia cifrada de lo que necesita el inicio de sesión (que solo la
  llave de acceso abre).

## Iniciar sesión con Google

Si eliges continuar con Google, Keyless recibe de Google tu correo
verificado, tu nombre y tu foto de perfil. Se guardan con tu cuenta y solo
sirven para identificarla. Keyless no pide acceso a ningún otro dato o
servicio de Google, y entrar con Google nunca da acceso a tus bóvedas:
abrirlas siempre exige la contraseña maestra y la Clave Secreta.

## Enlaces compartidos con correos concretos

Cuando alguien comparte un elemento solo con algunos correos, el servidor
guarda un hash (SHA-256) de cada dirección, no la dirección. Para abrir un
enlace así, escribes tu correo y recibes un código de un solo uso. Para
ello, el servidor guarda tu correo y el idioma de la página que usaste, y
los borra 30 días después de tu último código. Esto no da acceso a nada más
que a los elementos compartidos con esa dirección.

## La extensión del navegador

- La extensión solo habla con la app de Keyless en el mismo ordenador
  (mediante el native messaging del navegador), por un canal cifrado con
  claves acordadas al conectarlas. Los inicios de sesión, tarjetas y otros
  datos llegan a una página solo cuando los rellenas, o cuando una opción
  que activaste los rellena.
- Lee las páginas que visitas para encontrar formularios de inicio de
  sesión, pago y dirección y ofrecer Keyless allí. Lo que encuentra se queda
  en tu navegador y en la app.
- Un texto que copias en una página y que parece una clave de API va a la
  app en tu ordenador, que comprueba su formato para ofrecer guardarlo.
- Cuando eliges cambiar una contraseña filtrada, abre la dirección
  `/.well-known/change-password` del sitio.
- No tiene analítica ni código remoto. Lo que guardas con ella va a la app,
  que lo sincroniza con cifrado de extremo a extremo junto con el resto de
  tu bóveda.

## Terceros

- **Supabase** aloja el servidor de Keyless (autenticación y base de datos).
- **Resend** entrega los correos de la cuenta (confirmaciones y códigos de
  un solo uso): recibe la dirección y el texto del correo.
- **Have I Been Pwned** comprueba si una contraseña aparece en filtraciones
  conocidas, para Centinela: una vez al día y cuando guardas una contraseña
  nueva (puedes desactivarlo en Centinela), o cuando lo pides. Solo se
  envían los 5 primeros caracteres del hash SHA-1 de la contraseña
  (k-anonimato); la contraseña nunca sale de tu dispositivo.
- **Have I Been Pwned** y **2fa.directory** publican las listas de sitios
  con filtraciones y de sitios con códigos de verificación o llaves de
  acceso, que Centinela descarga enteras una vez al día y guarda en tu
  dispositivo para comparar allí. No se les envía nada sobre tus elementos;
  como en cualquier descarga, ven la dirección IP de la petición. Cada lista
  se puede desactivar en Centinela: deja de descargarse, y la copia en tu
  dispositivo se borra.

Keyless no tiene anuncios, analítica ni rastreo, y nunca vende ni comparte
tus datos.

## Borrar tus datos

Puedes borrar tu cuenta en la app (Ajustes > Cuenta). La cuenta y todo lo
guardado con ella se borran para siempre al cabo de 7 días, plazo en el que
puedes cancelarlo iniciando sesión de nuevo. Los elementos que borras se
guardan, aún cifrados, 30 días en Eliminados recientemente.

## Contacto

Preguntas sobre esta política: diego.castroalves1@gmail.com.
