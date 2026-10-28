# Flux Gestão Inteligente

Aplicativo Expo para gestão de loja com Supabase, cadastro por convite, painel administrativo, pagamentos Pix e identidade visual Flux.

## Configuração local

Configure `.env` com `EXPO_PUBLIC_SUPABASE_URL` e `EXPO_PUBLIC_SUPABASE_ANON_KEY`. Nunca coloque a chave `service_role`, o token do Mercado Pago ou a chave de e-mail em variáveis `EXPO_PUBLIC_*`.

## Ativação do Supabase

1. Aplique as migrations no projeto:

   ```powershell
   npx.cmd supabase login
   npx.cmd supabase link --project-ref SEU_PROJECT_REF
   npx.cmd supabase db push
   ```

2. Publique as Edge Functions:

   ```powershell
   npx.cmd supabase functions deploy create-invite-payment
   npx.cmd supabase functions deploy get-invite-payment-status
   npx.cmd supabase functions deploy mercadopago-webhook
   npx.cmd supabase functions deploy validate-registration-pin
   npx.cmd supabase functions deploy admin-overview
   ```

3. Entre com `alexandremoderbr@gmail.com`, abra **Financeiro > Perfil e segurança > Painel administrador**. Defina o preço do convite e configure:
   - Access Token do Mercado Pago.
   - Segredo de assinatura dos webhooks de pagamento.
   - Chave da API do Resend e remetente autorizado.

   Os segredos são gravados no Supabase Vault criptografados e nunca são enviados de volta ao aplicativo. Deixe um campo vazio para manter a credencial já salva.

   O próprio painel exibe e copia a URL exata do webhook para cadastrar no Mercado Pago.

   Mantenha a confirmação de e-mail do Supabase ativada para proteger o primeiro acesso administrativo.

4. Copie a URL de webhook exibida no painel admin e cadastre-a no Mercado Pago. O endereço tem este formato:

   ```text
   https://SEU_PROJECT_REF.supabase.co/functions/v1/mercadopago-webhook
   ```

   Ative notificações de pagamentos e use o segredo de assinatura correspondente. No Mercado Pago, configure a URL de notificação sem autenticação JWT.

5. No painel administrador você também pode ativar a manutenção, alterar a logo e o banner, publicar novidades e ver as contas, vendas de convites, pagamentos pendentes e saldo calculado de cada loja.

Após a aprovação verificada pelo webhook, o sistema emite um código único que expira em 24 horas e o envia por e-mail. A conta criada com esse código permanece ativa; os dados de cada usuário ficam separados pelas políticas RLS existentes e pelas colunas `user_id`.
