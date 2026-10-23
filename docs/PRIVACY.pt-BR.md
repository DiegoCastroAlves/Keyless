# Política de privacidade do Keyless

Atualizada em 23 de outubro de 2026

O Keyless é um gerenciador de senhas de conhecimento zero. Tudo o que você
guarda nos cofres é criptografado no seu dispositivo antes de ir para
qualquer lugar, com chaves que vêm da sua senha mestra e da sua Chave
Secreta. Nenhuma das duas sai dos seus dispositivos, então ninguém mais, nem
quem cuida do servidor do Keyless, consegue ler seus cofres.

## O que o servidor guarda

- Seu e-mail, que identifica a sua conta, e o idioma do app quando você a
  criou, usado só para escrever nele os e-mails da conta.
- Os dados criptografados dos cofres, sua chave pública e suas chaves
  criptografadas, e as configurações que acompanham a sua conta nos outros
  aparelhos (como as senhas sugeridas são feitas), criptografadas do mesmo
  jeito.
- Metadados técnicos para sincronizar: quantos cofres e itens você tem, o
  tamanho aproximado dos itens e quando mudam.
- Registros de conexão mantidos pelo provedor de hospedagem (endereço IP,
  horário, tipo de pedido), para segurança e operação.
- Para cada dispositivo conectado à sua conta: o endereço IP e o país do
  último acesso e quando foi usado pela última vez, para você ver onde sua
  conta está aberta e desconectar um dispositivo. O nome e o sistema do
  dispositivo são criptografados como os seus cofres.
- Para cada chave de acesso (passkey) que você adicionar para entrar: o ID
  da credencial, quando foi adicionada e usada pela última vez, e o nome e
  uma cópia criptografada do que a entrada precisa (que só a chave de acesso
  abre).

## Contas criadas com o Google

O Keyless não oferece mais a entrada com o Google. As contas criadas com ele
antes guardam o e-mail verificado, o nome e a foto de perfil que o Google
enviou na época, junto com a conta e só para identificá-la, até a conta ser
excluída. O Keyless nunca teve acesso a nenhum outro dado ou serviço do
Google.

## Links compartilhados com e-mails específicos

Quando alguém compartilha um item só com alguns e-mails, o servidor guarda
um hash (SHA-256) de cada endereço, não o endereço. Para abrir um link
assim, você informa seu e-mail e recebe um código de uso único. Para isso, o
servidor guarda o seu e-mail e o idioma da página que você usou, e os apaga
30 dias depois do seu último código. Isso não dá acesso a nada além dos
itens compartilhados com esse endereço.

## A extensão do navegador

- A extensão conversa apenas com o app do Keyless no mesmo computador (pelo
  native messaging do navegador), por um canal criptografado com chaves
  combinadas quando você os conecta. Logins, cartões e outros dados chegam a
  uma página só quando você os preenche, ou quando uma opção que você ligou
  preenche.
- Ela lê as páginas que você visita para achar formulários de login,
  pagamento e endereço e oferecer o Keyless ali. O que ela encontra fica no
  seu navegador e no app.
- Um texto que você copia numa página e que parece uma chave de API vai para
  o app no seu computador, que confere o formato para oferecer guardá-lo.
- Quando você escolhe trocar uma senha vazada, ela abre o endereço
  `/.well-known/change-password` do site.
- Ela não tem análise de uso nem código remoto. O que você salva por ela vai
  para o app, que sincroniza com criptografia de ponta a ponta junto com o
  resto do seu cofre.

## Terceiros

- O **Supabase** hospeda o servidor do Keyless (autenticação e banco de
  dados).
- **Resend** entrega os e-mails da conta (confirmações e códigos de uso
  único): recebe o endereço e o texto do e-mail.
- O **Have I Been Pwned** verifica se uma senha aparece em vazamentos
  conhecidos, para o Sentinela: uma vez por dia e quando você salva uma
  senha nova (dá para desligar no Sentinela), ou quando você pede. Só os 5
  primeiros caracteres do hash SHA-1 da senha são enviados (k-anonimato); a
  senha nunca sai do seu dispositivo.
- O **Have I Been Pwned** e o **2fa.directory** publicam as listas de sites
  que vazaram dados e de sites com códigos de verificação ou chaves de
  acesso, que o Sentinela baixa inteiras uma vez por dia e guarda no seu
  dispositivo para comparar ali. Nada sobre os seus itens é enviado a eles;
  como em qualquer download, eles veem o endereço IP do pedido. Cada lista
  pode ser desligada no Sentinela: ela deixa de ser baixada, e a cópia no
  seu dispositivo é apagada.
- **Os sites dos seus logins** fornecem os próprios ícones: os apps de
  computador e de Android baixam o ícone do site de cada login do próprio
  site (nunca por um serviço que saberia quais sites você tem), guardam o
  ícone cifrado no dispositivo e pedem de novo uma vez por mês. O site vê o
  endereço IP do pedido, como quando você o visita. Dá para desligar nas
  configurações do app ("Mostrar ícones dos sites"); os ícones guardados são
  apagados.

O Keyless não tem anúncios, análise de uso nem rastreamento, e nunca vende
nem compartilha seus dados.

## Apagar seus dados

Você pode apagar sua conta no app (Configurações > Conta). A conta e tudo o
que está guardado com ela são apagados de vez depois de 7 dias, prazo em que
dá para desistir entrando de novo. Itens que você apaga ficam guardados,
ainda criptografados, por 30 dias em Excluídos recentemente.

## Contato

Dúvidas sobre esta política: diego.castroalves1@gmail.com.
