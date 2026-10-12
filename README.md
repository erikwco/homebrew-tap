# erikwco/tap

Tap de Homebrew para [Projectory](https://github.com/erikwco/projectory). La fórmula instala los binarios precompilados que publica cada release (macOS y Linux, Intel/AMD de 64 bits y ARM64); no compila nada ni depende de Go.

## Instalación

```sh
brew install erikwco/tap/projectory
```

Al instalar con el nombre completo, Homebrew confía en esta fórmula (desde Homebrew 7 los taps de terceros requieren confianza explícita; `brew trust erikwco/tap` confía en todo el tap).

Activa la función `pt` añadiendo a `~/.zshrc` (o a `~/.bashrc` con `init bash`):

```sh
eval "$("$(brew --prefix)/opt/projectory/bin/projectory" init zsh)"
```

## Actualización

```sh
brew update && brew upgrade erikwco/tap/projectory
```

`projectory update` detecta las instalaciones de Homebrew y se niega a reemplazar sus archivos: indica este mismo comando y termina con error.

## Publicar una versión (mantenedores)

La fórmula se genera solo a partir de un release real, publicado e inmutable de `erikwco/projectory`. Nunca se edita a mano.

1. Prueba antes de publicar. Valida el release, descarga los cuatro archivos, verifica `checksums.txt`, los digests de la API y las atestaciones, y ejecuta `brew style`, `audit`, `install` y `test` en macOS ARM64, Linux x86_64 y Linux ARM64 (macOS Intel es opcional). Admite candidatos:

   ```sh
   gh workflow run bump.yml -R erikwco/homebrew-tap -f version=1.0.0-rc.1 -f dry_run=true
   ```

2. Publica una versión estable (sin `v`). Debe lanzarse desde `main`:

   ```sh
   gh workflow run bump.yml -R erikwco/homebrew-tap -f version=1.0.0 -f dry_run=false
   ```

   El workflow abre el pull request `bump/projectory-1.0.0` con la evidencia de las pruebas en la descripción. Revísalo y fusiónalo. Para seguir la ejecución: `gh run watch -R erikwco/homebrew-tap`.

Garantías del workflow:

- La versión se valida con un patrón estricto (`MAJOR.MINOR.PATCH` o `-rc.N` con N ≥ 1) antes de usarse, y nunca se interpola en scripts.
- Los candidatos (`-rc.N`) y los releases no inmutables solo se aceptan en `dry_run`.
- Volver a lanzar la misma versión es idempotente: reutiliza la rama y el pull request, o no hace nada si `main` ya la publica.
- Se niega a retroceder a una versión anterior a la de `main` o a la de otro pull request de bump abierto, y a reescribir una versión ya publicada con contenido distinto. Los pull requests de bump anteriores quedan cerrados como reemplazados.
- Usa solo el `GITHUB_TOKEN` de este repositorio. El commit se crea con la API de contenidos (firmado por GitHub), sin credenciales de git persistidas.

Los pull requests creados con `GITHUB_TOKEN` no disparan workflows de `pull_request`; por eso la evidencia de pruebas viaja en la descripción del pull request y no hay checks obligatorios para ellos.

## Configuración del repositorio

- Público, con `main` protegida: cambios solo mediante pull request, sin checks de estado obligatorios.
- Settings → Actions → General → Workflow permissions: lectura predeterminada y **Allow GitHub Actions to create and approve pull requests** activado.
- Settings → Actions → General: permitir las acciones `actions/*` y `Homebrew/actions/*` (fijadas por SHA en el workflow).
- Settings → General: activar **Automatically delete head branches**.

## Desarrollo

El generador `scripts/projectory_formula.py` usa solo la biblioteca estándar de Python 3:

```sh
python3 -I -m unittest discover -s tests -v
python3 -I scripts/projectory_formula.py verify-assets --version 1.0.0 --dir ruta/a/dist
python3 -I scripts/projectory_formula.py generate --version 1.0.0 --checksums ruta/a/dist/checksums.txt --output Formula/projectory.rb
```

`--allow-prerelease` acepta candidatos para pruebas locales. `python3 -I scripts/projectory_formula.py --help` lista todos los subcomandos.
