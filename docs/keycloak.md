# Integración Keycloak / Red Hat build of Keycloak

La versión exacta 26.4.11 solicitada debe comprobarse en tu distribución: las versiones de Keycloak upstream y de Red Hat pueden diferir. VIGIA usa el protocolo estándar OIDC y no instala ni administra el servidor de identidad.

1. Crea un realm y un cliente OpenID Connect con ID `vigia` (o configura `OIDC_CLIENT_ID`). Activa **Client authentication** y **Standard flow**. Desactiva implicit flow, direct access grants y service accounts si no los necesitas. Exige PKCE S256 y firma RS256 del ID token.
2. Registra exclusivamente el callback final, por ejemplo `https://vigia.empresa.cl/auth/callback/`, sin comodines. En desarrollo registra `http://localhost:8000/auth/callback/`. La aplicación usa navegación del servidor y no necesita CORS abierto.
3. Crea el rol **de cliente** `vigia-admin`; asígnalo solo a administradores de seguridad, directamente o mediante un grupo. Los usuarios comunes pueden iniciar sesión sin ese rol.
4. Añade un protocol mapper de tipo **User Client Role** para este cliente. El claim debe ser `resource_access.vigia.roles` (sustituye `vigia` si cambias el ID); multivalor, tipo string, **Add to ID token = ON**. Si el rol solo está en el access token, VIGIA no concede permisos administrativos. Restringe los roles accesibles mediante client scopes; evita full scope allowed cuando no sea necesario.
5. Configura MFA para administradores, política de contraseñas/antifuerza bruta y una vida del ID token apropiada (por ejemplo 5 minutos). No se guardan access tokens, refresh tokens ni ID tokens.
6. Configura en el despliegue:

   ```text
   OIDC_ISSUER=https://sso.empresa.cl/realms/mi-realm
   OIDC_CLIENT_ID=vigia
   OIDC_CLIENT_SECRET=<valor introducido solo en el gestor de secretos>
   OIDC_REDIRECT_URI=https://vigia.empresa.cl/auth/callback/
   OIDC_ADMIN_ROLE=vigia-admin
   ```

7. Permite el dominio SSO en la política de salida del entorno. No deshabilites TLS para un certificado corporativo: instala la CA correspondiente.
8. Verifica Discovery, login de usuario, login de administrador, cierre de sesión local, caducidad y rechazo de usuario desactivado. Comprueba que un usuario común no obtiene `details` al solicitar `/results/<uuid>/?format=json` y que el rol aparece en un **ID token validado**, sin imprimirlo en logs.

La sesión local no recibe backchannel logout ni eventos de revocación inmediata. Si necesitas revocación instantánea o logout global, es una ampliación pendiente; no prolongues la sesión local más allá de la caducidad del token para compensarlo.
