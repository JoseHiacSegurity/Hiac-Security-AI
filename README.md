# Hiac Security AI — PhishGuard

Ciberseguridad e IA para proteger a niños y personas vulnerables frente al phishing y fraude bancario.

## MVP: detección de phishing en tiempo real

Este repositorio ahora incluye una extensión de Chrome (Manifest V3) que analiza localmente cada página cargada y advierte de señales de riesgo antes de que alguien entregue credenciales.

### Privacidad

- No lee, registra ni transmite contraseñas o valores de formularios.
- El análisis y la puntuación se realizan dentro del navegador.
- Las reglas son explicables y auditables en `src/rules.js`.

### Instalación local

1. Clona o descarga el repositorio.
2. En Chrome, abre `chrome://extensions`.
3. Activa **Modo de desarrollador**.
4. Selecciona **Cargar descomprimida** y elige esta carpeta.
5. El icono muestra la puntuación para la pestaña actual. Ábrelo para revisar las señales.

### Señales evaluadas

| Señal | Ejemplo |
| --- | --- |
| Formulario de contraseña sin HTTPS | Página HTTP con campo password |
| Dominio parecido a una marca | `micros0ft-ejemplo.com` |
| URL engañosa | Punycode, IP directa o `@` |
| Formulario que publica a otro dominio | Login con destino externo |
| Técnicas de ocultación | iframe oculto |

Una puntuación de 60 o más es de riesgo alto. Es una ayuda de seguridad y no sustituye verificar el dominio antes de iniciar sesión.

### Estructura

- `manifest.json`: configuración de la extensión.
- `src/rules.js`: motor de detección local.
- `src/content.js`: inspección de URL y DOM.
- `src/background.js`: puntuación por pestaña.
- `src/popup.*`: resultados para la persona usuaria.

El analizador de línea de comandos para mensajes sospechosos y los módulos anti-ransomware/malware pueden añadirse como fases posteriores del proyecto.
