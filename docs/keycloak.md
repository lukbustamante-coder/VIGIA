# Integración Keycloak / Red Hat build of Keycloak

La versión exacta 26.4.11 solicitada debe comprobarse en tu distribución: las versiones de Keycloak upstream y de Red Hat pueden diferir. VIGIA usa el protocolo estándar OIDC y no instala ni administra el servidor de identidad.

1. Crea un realm y un cliente OpenID Connect con ID `vigia` (o configura `OIDC_CLIENT_ID`). Activa **Client authentication** y **Standard flow**. Desactiva implicit flow, direct access grants y service accounts si no los necesitas. Exige PKCE S256 y firma RS256 del ID token.
2. Registra exclusivamente el callback final, por ejemplo `https://vigia.empresa.cl/auth/callback/`, sin comodines. En desarrollo registra `http://localhost:8000/auth/callback/`. En **Valid post logout redirect URIs** registra también `http://localhost:8000/auth/logout/callback/` para desarrollo o `https://vigia.empresa.cl/auth/logout/callback/` para producción. Son rutas diferentes: el callback de login no reemplaza al de logout. La aplicación usa navegación del servidor y no necesita CORS abierto.
3. Crea el rol **de cliente** `vigia-admin`; asígnalo solo a administradores de seguridad, directamente o mediante un grupo. Los usuarios comunes pueden iniciar sesión sin ese rol.
4. Añade un protocol mapper de tipo **User Client Role** para este cliente. El claim debe ser `resource_access.vigia.roles` (sustituye `vigia` si cambias el ID); multivalor, tipo string, **Add to ID token = ON**. Si el rol solo está en el access token, VIGIA no concede permisos administrativos. Restringe los roles accesibles mediante client scopes; evita full scope allowed cuando no sea necesario.
5. Configura MFA para administradores, política de contraseñas/antifuerza bruta y una vida del ID token apropiada (por ejemplo 5 minutos). No se guardan access tokens, refresh tokens ni ID tokens.
6. Configura en el despliegue:

   ```text
   OIDC_ISSUER=https://sso.empresa.cl/realms/mi-realm
   OIDC_CLIENT_ID=vigia
   OIDC_CLIENT_SECRET=<valor introducido solo en el gestor de secretos>
   OIDC_REDIRECT_URI=https://vigia.empresa.cl/auth/callback/
   OIDC_POST_LOGOUT_REDIRECT_URI=https://vigia.empresa.cl/auth/logout/callback/
   OIDC_ADMIN_ROLE=vigia-admin
   ```

7. Permite el dominio SSO en la política de salida del entorno. No deshabilites TLS para un certificado corporativo: instala la CA correspondiente.
8. Verifica Discovery, login de usuario, login de administrador, cierre local y en Keycloak, caducidad y rechazo de usuario desactivado. El logout requiere POST con CSRF; borra primero la sesión local y redirige al endpoint de Discovery con `client_id`, `post_logout_redirect_uri` y un `state` de un solo uso. No se guardan ni envían ID tokens como hint, por lo que Keycloak puede mostrar una confirmación de cierre; confírmala para terminar la sesión SSO. El siguiente login añade `prompt=login` y renueva roles desde un token validado. Si Discovery falla, la sesión local queda cerrada y se muestra un mensaje. Comprueba que un usuario común no obtiene `details` al solicitar `/results/<uuid>/?format=json` y que el rol aparece en un **ID token validado**, sin imprimirlo en logs.

La sesión local no recibe backchannel logout ni eventos de revocación inmediata desde otras aplicaciones. El cierre iniciado manualmente en VIGIA usa RP-Initiated Logout, pero no sustituye esa integración de revocación. La confirmación de retorno no prueba por sí sola el estado de sesiones de proveedores federados externos. No prolongues la sesión local más allá de la caducidad del token.

## Diagnóstico de inicio de sesión

Para comprobar un archivo editado ejecuta `uv run python -m py_compile analysis/auth.py` y, con las variables cargadas, `uv run python manage.py check`. Un `TabError` o `IndentationError` impide arrancar Python; es independiente de las credenciales de Keycloak. Usa cuatro espacios por nivel y no mezcles tabulaciones.

Si el proveedor acepta las credenciales pero VIGIA rechaza el retorno, consulta la línea `Fallo OIDC (callback): tipo=... codigo=...` en la terminal del servidor. `invalid_client` apunta a la configuración/autenticación del cliente; `invalid_grant` puede deberse al código de autorización, callback o PKCE. Las clases de error de validación identifican problemas de tokens, estado o claims. No sustituyas los controles de firma/issuer/audience/nonce ni imprimas `str(error)`, respuestas completas del proveedor, tokens, secretos, `.env` o URLs con códigos de autorización para diagnosticarlo. Los logs nuevos solo registran la clase de excepción y códigos de protocolo de una lista permitida.

`MismatchingStateError` significa que no se pudo recuperar la solicitud de autorización de la sesión del navegador; ocurre antes de intercambiar el código y no identifica una contraseña incorrecta. VIGIA usa cookies propias `vigia_sessionid` y `vigia_csrftoken`, porque las cookies de localhost se comparten entre puertos y otras aplicaciones Django pueden reemplazar el `sessionid` genérico. Al actualizar desde los nombres antiguos será necesario iniciar sesión de nuevo una vez.

Empieza desde el mismo origen configurado en `OIDC_REDIRECT_URI` (en WSL, normalmente `http://localhost:8000`). La ruta de inicio ahora redirige a ese origen antes de guardar state, nonce y PKCE; no transporta códigos ni tokens entre hosts. `0.0.0.0` es la dirección de escucha del servidor, no la dirección recomendada para abrir el sitio. En despliegues con terminación TLS configura correctamente el proxy de confianza para que Django reconozca HTTPS.

Un retorno inválido se rechaza sin borrar otras solicitudes pendientes ni una sesión ya autenticada. La página ofrece reiniciar el flujo desde el origen configurado; no recargues el callback ni reutilices su código. El log `Estado OIDC no recuperado: cookie_recibida=... sesion_cargada=... estado_guardado=...` registra solo indicadores booleanos. Si la cookie no llega, comprueba el host y la aceptación de cookies; si llega sin sesión, revisa expiración, estabilidad de la clave de sesión y almacenamiento compartido. No cambies SameSite a None ni desactives state/nonce para resolverlo.
