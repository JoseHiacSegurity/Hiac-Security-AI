# Hiac Security AI — PhishGuard

Ciberseguridad e IA para proteger a niños y personas vulnerables frente al phishing y fraude bancario.

## Detección de phishing en tiempo real

PhishGuard es una extensión de Chrome (Manifest V3) que analiza localmente la página cargada y detiene el primer envío de un formulario de contraseña cuando detecta riesgo alto. La persona usuaria debe confirmar explícitamente si desea continuar.

## Privacidad

- No lee, registra ni transmite contraseñas o valores de formularios.
- No se guarda la URL, la ruta ni los parámetros: solo una puntuación temporal por pestaña.
- El análisis y la puntuación se realizan dentro del navegador, sin telemetría ni APIs remotas.
- Las reglas son explicables y auditables en `src/rules.js`.

## Instalación local

1. Clona o descarga el repositorio.
2. En Chrome, abre `chrome://extensions`.
3. Activa **Modo de desarrollador**.
4. Selecciona **Cargar descomprimida** y elige esta carpeta.
5. Recarga la extensión después de cada actualización. El icono muestra la puntuación para la pestaña actual.

## Señales evaluadas

| Señal | Acción |
| --- | --- |
| Formulario de contraseña sin HTTPS | Riesgo alto; se exige confirmación antes de enviar |
| Destino del formulario sin HTTPS | Riesgo alto; se exige confirmación antes de enviar |
| Dominio parecido a una marca | Se marca y se combina con otras señales |
| URL engañosa | Punycode, IP directa, `@`, ruta codificada |
| Infraestructura sospechosa | TLD de riesgo, host largo o muchos subdominios |
| Página evasiva | Iframe oculto o redirecciones múltiples |

Una puntuación de 60 o más es de riesgo alto. PhishGuard no sustituye verificar el dominio antes de iniciar sesión.

## Calidad

Las reglas se prueban con Node sin dependencias externas. El flujo de GitHub Actions las ejecuta en cada cambio a `main` y en cada pull request:

```sh
node --test tests/rules.test.mjs
```

## Estructura

- `manifest.json`: configuración y permisos mínimos de la extensión.
- `src/rules.js`: motor de detección local.
- `src/content.js`: inspección de URL/DOM y barrera antes del envío.
- `src/background.js`: puntuación efímera por pestaña.
- `src/popup.*`: resultados para la persona usuaria.
- `tests/rules.test.mjs`: pruebas de regresión.
- `SECURITY.md`: modelo de amenazas y proceso seguro.

El analizador de línea de comandos para mensajes sospechosos y los módulos anti-ransomware/malware pueden añadirse como fases posteriores del proyecto.
