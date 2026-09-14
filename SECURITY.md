# Seguridad y modelo de amenazas

## Límites del producto

PhishGuard es una capa de aviso local. No sustituye el filtrado DNS, la protección del navegador ni la formación de usuarios. No afirma conocer todos los sitios maliciosos.

## Datos

- No se envían solicitudes de red.
- No se captura texto introducido, credenciales, cookies, historial ni el contenido de los campos.
- El único estado efímero por pestaña contiene una puntuación y mensajes de reglas; se elimina al cerrar la pestaña o terminar la sesión del navegador.
- No se guarda la URL, la ruta, parámetros ni fragmentos.

## Superficie y controles

| Riesgo | Control |
| --- | --- |
| Página muy grande o dinámica | Se limita el texto analizado, el número de formularios/iframes y se agrupan nuevos análisis con una espera breve. |
| Mensajes malformados al service worker | Se valida tipo, tamaño y rango de cada valor antes de guardarlo o mostrarlo. |
| Inyección de interfaz | La ventana emergente usa textContent; el aviso en página usa Shadow DOM cerrado y no inserta HTML de la página. |
| Privilegios excesivos | La extensión solicita únicamente storage; no usa permisos de red, historial, cookies, descargas ni acceso al portapapeles. |
| Fuga de información | El motor es local, sin telemetría ni APIs de reputación. |
| Evasión por contenido cargado tarde | Un observador detecta cambios relevantes en la página y vuelve a analizarla. |

## Proceso de cambios

1. No añadir dependencias remotas a la extensión.
2. No usar eval, innerHTML con datos de página, ni cargar scripts desde una URL.
3. Revisar cada permiso nuevo: debe tener una razón y constar en el README.
4. Probar en una página propia con formulario HTTPS, un formulario HTTP y un formulario cuyo destino sea otro dominio.
5. Antes de publicar, revisar manualmente chrome://extensions para confirmar los permisos declarados.

## Mejoras futuras

- Lista firmada de indicadores de compromiso, descargada solo con consentimiento explícito.
- Pruebas automatizadas de reglas con casos benignos y maliciosos simulados.
- Integración empresarial opcional con SIEM, minimizando datos y con aprobación previa.