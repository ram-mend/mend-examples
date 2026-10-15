# Shaded dependency hierarchy: a pre-build hook for Mend SCA (Maven)

[shaded_deps_hierarchy.py](./shaded_deps_hierarchy.py) makes the Mend SCA scan report the libraries that a Maven dependency bundles ("shades") inside its own jar.

A shaded jar's published POM doesn't list the libraries it bundles. The Maven scan therefore sees the jar as a leaf, and doesn't report the bundled libraries or their vulnerabilities. 

For example at [pom.xml](./maven-sample/pom.xml), `org.apache.parquet:parquet-jackson` 1.18.0 bundles three Jackson libraries, and `jackson-core` in turn bundles FastDoubleParser. With the hook, Mend reports them under the library that bundles them:

```
parquet-jackson 1.18.0
├─ jackson-core 2.22.1 ── fastdoubleparser 2.0.1
├─ jackson-annotations 2.22
└─ jackson-databind 2.22.1 ─┬─ jackson-annotations 2.22
                            └─ jackson-core 2.22.1 ── fastdoubleparser 2.0.1
```

Tested with Mend for GitHub Enterprise (self-hosted) 26.9.1.4.

## How it works

The scanner runs the hook in the cloned repository before each scan. For each repository with a `pom.xml` at its root, the hook does the following (if `REPOS` is set, only for the repositories it lists):

1. **Finds bundled libraries.** It resolves the dependencies with Maven and looks inside each dependency jar for:
   - other libraries' `META-INF/maven/<groupId>/<artifactId>/pom.properties`;
   - the jar's own `pom.xml`, when it configures `maven-shade-plugin`.
2. **Declares each one under its parent.** Each bundled library is declared under the library that declares it, through a byte-identical copy of its published jar. The copy's classifier names that parent, for example `jackson-core-2.22.1-shaded-parquet-jackson-1.18.0.jar`. As a result:
   - a library bundled in several places appears under each parent;
   - the project's own version of a library can't hide a bundled copy.
3. **Verifies the tree.** Maven reads the patched POMs from a temporary repository under `.mvn/`, and the hook re-resolves until every copy is in place. It then logs `Verified`.

Mend identifies each copy by its SHA-1 and reports it under its normal name and version. The project's `pom.xml` is never changed, and nothing is pushed to the repository.

## Requirements

- **Mend for GitHub Enterprise (self-hosted),** with a scan customization repository (see Installation).
- **Maven 3.9 or later and `python3` in the scanner image.** Only the Python standard library is used; tested with Python 3.10. The 26.9.1.4 scanner image includes both. To check:

  ```bash
  docker exec <scanner-container> sh -c 'mvn -v | grep "Apache Maven"; python3 --version'
  ```
- **Access to your Maven repositories.** The scanner must be able to download the published jars of bundled libraries; the hook uses `mvn dependency:get`.

## Installation

1. **Customization repository.** Create (or reuse) a repository in an organization where the Mend app is installed, for example `mend-scan-hooks`.
2. **Add the script** as `hooks/common/pre-build/01_shaded_deps_hierarchy.py`:
   - Keep `#!/usr/bin/env python3` as the first line, and keep Unix (LF) line endings. The scanner executes the file directly.
   - Commit it as executable: `git update-index --chmod=+x hooks/common/pre-build/01_shaded_deps_hierarchy.py`.
   - Put nothing else in that folder, including this README. The scanner executes every file in it.
3. **Optionally, configure** the settings at the top of the script (see Configuration). By default the hook acts on every Maven repository. To start with a pilot repository, set `REPOS` to its name.
4. **Point the controller at the repository.** Add this environment variable to the controller container, then recreate the container (for example with `docker compose up -d`). A plain restart doesn't reload environment variables.

   ```
   MEND_GLOBAL_CUSTOMIZATION_REPO=<org>/<repo>
   ```

   To check: `docker exec <controller-container> env | grep MEND_GLOBAL_CUSTOMIZATION_REPO`

## Configuration

| Setting | Default | What to set |
|---|---|---|
| `REPOS` | `""`: every repository with a `pom.xml` at its root | Space-separated names of the repositories to act on, for example one pilot repository first. Leave empty for all Maven repositories. |
| `MVN_LOG_LEVEL` | `""`: normal Maven output | `-X` (debug) while troubleshooting, `-q` for errors only. |
| `MAX_ROUNDS` | `10` | Leave as is. It limits the re-resolution rounds used to follow nested shading. |

The hook runs for every scan in the organization. It exits immediately for a repository without a `pom.xml` at its root, and, when `REPOS` is set, for a repository it doesn't list.

## Verifying

1. **Trigger a scan** of a Maven repository (one listed in `REPOS`, if you set it): push a commit that triggers a scan, for example a change to `.whitesource`.
2. **Read the hook's output** in the scanner's scan log. Each line is prefixed with the hook path and scan context:

   ```bash
   docker exec <scanner-container> sh -c 'grep -h "\[shaded-hook\]" /tmp/sca_*.log | grep -v "mvn -B" | tail -40'
   ```

   Look for `Shaded in <jar>: <library>` lines and a closing line like this one, followed by the final dependency tree:

   ```
   [shaded-hook] Verified: all 8 bundled dependencies resolve, each as its own copy under the library that declares it (8 copies)
   ```

   The scan log line that runs the hook contains `execution success; exit code: 0`.
3. **Check Mend.** The bundled libraries appear as transitive dependencies of the library that bundles them, with their vulnerabilities, in the project and in its SBOM export.

## What to expect

- **Fixing findings.** A vulnerability in a bundled library is fixed by upgrading the library that bundles it (for example, a newer `parquet-jackson`), not the bundled library itself. Mend's fix suggestions may still name the bundled library.
- **Runtime.** The hook adds a few Maven runs to each scan of a repository it acts on; in testing this was about 10 to 30 seconds for a small project. A repository without shaded jars costs one extra `mvn dependency:list`.
- **Files in the scanner's local Maven repository.** The copies are written to the scanner's local Maven repository (`~/.m2/repository`), because the scanner identifies jars only there.
  - They are byte-identical to published jars, under coordinates that no public repository publishes.
  - They never overwrite existing files, stay between scans and don't affect other builds.
- **Changes in the clone only.** The hook adds two lines to `.mvn/maven.config` and creates `.mvn/shaded-overlay-repo/`. Both are excluded from the file scan, and the scanner deletes the clone after the scan.
- **If the hook fails** (a Maven error, or a jar it can't read), it removes its changes and exits 1.
  - The scan runs as if the hook weren't installed, and the SCA result shows a Warning.
  - If your check runs use `strictMode: failOnWarning`, that check fails.

## Limitations

- **Maven projects only,** with a `pom.xml` at the repository root. Gradle and other build tools aren't covered.
- **Maven metadata needed.** Bundled libraries are found only through Maven metadata in the jar: the bundled library's `pom.properties`, or the jar's own `pom.xml` with a `maven-shade-plugin` configuration. Relocated code without metadata is only logged, as `contains relocated code with no Maven metadata`.
- **Reported as the published library.** Bundled code is reported as the published library (matched by SHA-1), not as the relocated classes.
- **Not tested:** multi-module projects, private Maven registries and very large projects.

## Troubleshooting

| Symptom in the scan log | Cause and fix |
|---|---|
| No `[shaded-hook]` lines | The controller doesn't have `MEND_GLOBAL_CUSTOMIZATION_REPO`, the Mend app can't access the customization repository, or the script isn't in `hooks/common/pre-build/`. |
| Only the hook's first line (`[shaded-hook] repo=<name> dir=…`) | The repository has no `pom.xml` at its root, or `REPOS` is set and doesn't list it. |
| `Exec format error` | The first line isn't `#!/usr/bin/env python3`. |
| `/usr/bin/env: 'python3\r': No such file or directory` | The file has Windows line endings. Convert it to LF. |
| `/usr/bin/env: 'python3': No such file or directory` | The scanner image has no Python 3. |
| `WARNING: …; removing the overlay - shaded libraries won't be reported` | The hook rolled back. The lines above it show the Maven or Python error; set `MVN_LOG_LEVEL="-X"` for more detail. |
| `WARNING: couldn't fetch …` | The scanner can't download that published jar from your Maven repositories, so that library isn't reported. |
| `nested deeper than MAX_ROUNDS` | Shading is nested deeper than the round limit. Increase `MAX_ROUNDS`. |

## Removing the hook

1. Delete `hooks/common/pre-build/01_shaded_deps_hierarchy.py` from the customization repository. The next scan runs without the hook. To stop it for some repositories only, list the others in `REPOS`.
2. Optionally, remove the copies from the scanner's local Maven repository. This lists them:

   ```bash
   docker exec <scanner-container> sh -c 'find ~/.m2/repository -name "*.jar" | awk -F/ "index(\$NF, \$(NF-2) \"-\" \$(NF-1) \"-shaded-\") == 1"'
   ```

   To delete them, add `| xargs rm -f` after the `awk` command, inside the quotes. The filter matches only jars named `<artifactId>-<version>-shaded-…`, so published artifacts such as `hadoop-shaded-guava` are left alone.
