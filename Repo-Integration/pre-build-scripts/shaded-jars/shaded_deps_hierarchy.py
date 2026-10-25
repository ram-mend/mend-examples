#!/usr/bin/env python3
# shaded_deps_hierarchy.py - Mend SCA pre-build hook: reports the libraries a
# Maven dependency bundles ("shades") inside its jar, each under the library
# that bundles it, as byte-identical copies of their published jars (Mend
# matches them by SHA-1) in an overlay repo in front of the local one. See
# README.md. Needs python3 (standard library only; tested with 3.10), Maven 3.9+.
#
# The scanner executes this file directly: keep "#!/usr/bin/env python3" as
# the first line, and Unix (LF) line endings.

REPOS = ""                   # repos to run for, space-separated; "" (or "*") = every repo
MVN_LOG_LEVEL = ""           # Maven output: -X = debug, "" = normal, -q = errors only
MAX_ROUNDS = 10              # bounds re-resolution (nested shading)
BINARY_JARS = True           # in a repo without pom.xml, report what its jars bundle (writes a pom.xml for the scan)
REACHABILITY = True          # write the app's imports of relocated (shaded) classes under their original names, for Mend's reachability analysis
HARD_LINKS = True            # copies of published jars in the local Maven repo: hard links to the jar (no extra disk space); False = full copies
REPORT_EXCLUDED = False      # a bundled library an <exclusion> on its path removes: False = not reported, as Maven leaves it out; True = reported anyway

import collections, filecmp, html.entities, os, re, shutil, subprocess, sys, tempfile, traceback, zipfile
import xml.etree.ElementTree as ET
from xml.parsers import expat

NS = "http://maven.apache.org/POM/4.0.0"
ET.register_namespace("", NS)
ET.register_namespace("xsi", "http://www.w3.org/2001/XMLSchema-instance")
RELOCATED = re.compile(r"^((?:.*/)?(?:shaded|repackaged|relocated)/[^/]+)/")
CLASSIFIER_PREFIX = "shaded-"
OWN_VERSION = "%s-own%d"  # g:a:v of a copy's POM at a version of its own, the published one being the first
SHADED_GROUP = "%s.shaded-copy"  # a copy's groupId once an exclusion on its path drops it (it matches g:a only)
DEP_PLUGIN = "org.apache.maven.plugins:maven-dependency-plugin:3.6.0"
HELP_PLUGIN = "org.apache.maven.plugins:maven-help-plugin:3.5.1"  # binary mode: where the local repo is
BINARY_PREFIX = CLASSIFIER_PREFIX + "binary-"  # + version: a jar in the repository, declared as a copy of itself
POM_PROPERTIES = re.compile(r"META-INF/maven/[^/]+/[^/]+/pom\.properties")
BUILD_FILES = {"pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "build.sbt"}
CONFIG = os.path.join(".mvn", "maven.config")
TREE_LINE = re.compile(r"((?:[| ]  )*[+\\]- |)(\(?[^\s:]+(?::\S+){3})")  # (prefix, g:a:type:...)
REACH_DIR = ".shaded-hook-reachability"  # <module>/REACH_DIR/<path in the module>: a source file's companion
JAVA_PACKAGE = re.compile(r"^\s*package\s+([\w$.]+)\s*;", re.M)
JAVA_IMPORT = re.compile(r"(?:^|(?<=;))\s*import\s+(static\s+)?([\w$.]+(?:\.\*)?)\s*;", re.M)  # two on a line too
JAVA_TYPE = re.compile(r"(?<![\w$.])(?:class|interface|enum|record|@\s*interface)\s+[\w$]")  # where the header ends
COMMENTS = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
NOT_CLASSES = {"package-info.class", "module-info.class"}
UNREADABLE = set()  # the POMs parse_pom couldn't read, each warned about once
COMPANION = ("// Written by the shaded-jars pre-build hook for this scan, for Mend's reachability analysis:\n"
             "// the imports of relocated (shaded) classes in %s, under their original names.\n%s%s")


class Rollback(Exception):
    """Undo everything and exit 1, so the scan runs as if this hook weren't there."""


def log(msg):
    print("[shaded-hook] " + msg, flush=True)


def ns_of(root):
    return "{%s}" % NS if root.tag.startswith("{") else ""


def repo_path(repo, g, a, v, ext="pom", classifier=""):
    name = "%s-%s%s.%s" % (a, v, "-" + classifier if classifier else "", ext)
    return os.path.join(repo, *g.split("."), a, v, name)


def copy_aside(src, dst):
    """Copy through a temporary name in DST's folder: no other scan sees part
    of it, and a name near the 255-byte limit fits."""
    part = os.path.join(os.path.dirname(dst), ".%d.part" % os.getpid())
    shutil.copyfile(src, part)
    os.replace(part, dst)


def link_or_copy(src, dst):
    """SRC's bytes at DST, a new name: with HARD_LINKS a hard link where the
    filesystem allows one, else a copy. True if linked."""
    if HARD_LINKS:
        try:
            os.link(src, dst)
            return True
        except FileExistsError:
            return False
        except OSError:
            pass
    copy_aside(src, dst)
    return False


def classifier_for(patch):
    """The classifier of the copies a POM (a patches entry) declares: its library
    and published version, then its own copy's classifier, so a copy's file
    name spells its path to the project's dependency."""
    g, a, v = patch["real"].split(":")
    return CLASSIFIER_PREFIX + a + "-" + v + ("-" + patch["cls"] if patch["cls"] else "")


def coords(s):
    """(g, a, classifier, v) of Maven's g:a:type[:classifier]:version[:scope]."""
    p = s.split(":")
    return (p[0], p[1], p[3], p[4]) if len(p) >= 6 else (p[0], p[1], "", p[3])


def is_runtime(dep, ns, scope=""):
    """A <dependency> passed on to consumers. scope: the managed one, if it sets none."""
    get = lambda tag: dep.findtext(ns + tag, "").strip()
    return (get("scope") or scope) in ("", "compile", "runtime") and get("optional") != "true"


def parse_pom(data, name):
    """The root element of a POM's bytes. Maven's reader ignores XML namespaces
    and knows HTML's named entities, so a POM Maven builds with can hold what
    xml.etree rejects, such as <Xlint:-unchecked/> (hadoop-project 3.0-3.3.0)
    or &oslash;. Such a POM is read again as Maven reads it: without namespaces.
    None if even that fails: the caller goes on as if the file weren't there.
    name: the file in the warning."""
    try:
        return ET.fromstring(data)
    except ET.ParseError:
        pass
    builder, parser = ET.TreeBuilder(), expat.ParserCreate()  # no namespace separator: a prefix is part of the name
    parser.buffer_text = True
    parser.StartElementHandler, parser.EndElementHandler = builder.start, builder.end
    parser.CharacterDataHandler = builder.data
    parser.UseForeignDTD(True)  # an undeclared entity is then skipped, not an error
    parser.SkippedEntityHandler = lambda entity, _: builder.data(chr(html.entities.name2codepoint.get(entity, 0xFFFD)))
    try:
        parser.Parse(data, True)
        return builder.close()
    except expat.ExpatError as e:
        if name not in UNREADABLE:
            UNREADABLE.add(name)
            log("WARNING: %s isn't readable XML, even as Maven reads it (%s); the hook goes on as if that file "
                "weren't there" % (name, e))
        return None


class Pom:
    """A POM plus the properties, and the managed versions and scopes, of its
    parent chain. name: the POM in a warning (parse_pom)."""

    def __init__(self, data, g, v, repos, name):
        self.root = parse_pom(data, name)
        self.props, self.managed = {}, {}
        if self.root is None:
            return
        chain, node = [self.root], self.root
        for _ in range(10):
            parent = node.find(ns_of(node) + "parent")
            if parent is None:
                break
            pg, pa, pv = (parent.findtext(ns_of(node) + t, "").strip()
                          for t in ("groupId", "artifactId", "version"))
            self.props.setdefault("project.parent.version", pv)
            path = next((p for p in (repo_path(r, pg, pa, pv) for r in repos) if os.path.exists(p)), None)
            if path is None:
                break
            with open(path, "rb") as f:
                node = parse_pom(f.read(), path)
            if node is None:
                break  # as a parent that isn't in the repos
            chain.append(node)
        for node in reversed(chain):  # child overrides parent
            for p in node.findall(ns_of(node) + "properties/*"):
                self.props[p.tag.rsplit("}", 1)[-1]] = (p.text or "").strip()
        self.props.update({k: g for k in ("groupId", "project.groupId", "pom.groupId")})
        self.props.update({k: v for k in ("version", "project.version", "pom.version")})
        for node in reversed(chain):
            ns = ns_of(node)
            for d in node.findall("%sdependencyManagement/%sdependencies/%sdependency" % (ns, ns, ns)):
                self.managed[self.key(d, ns)] = (self.expand(d.findtext(ns + "version")),
                                                 self.expand(d.findtext(ns + "scope")))

    def expand(self, s):
        s = (s or "").strip()
        for _ in range(10):
            new = re.sub(r"\$\{([^}]+)\}", lambda m: self.props.get(m.group(1), m.group(0)), s)
            if new == s:
                break
            s = new
        return s

    def key(self, dep, ns):
        """Maven's dependency management key: a test-jar managed with test scope
        doesn't make the jar of the same library a test dependency."""
        get = lambda tag, default="": self.expand(dep.findtext(ns + tag)) or default
        return ":".join((get("groupId"), get("artifactId"), get("type", "jar"), get("classifier")))

    def runtime_deps(self):
        """{g:a: version} of the dependencies passed on to consumers, in POM
        order; None if the POM can't be read."""
        if self.root is None:
            return None
        ns = ns_of(self.root)
        found = {}
        for d in self.root.findall("%sdependencies/%sdependency" % (ns, ns)):
            key = self.key(d, ns)
            version, scope = self.managed.get(key, ("", ""))
            if is_runtime(d, ns, scope):
                found[key.rsplit(":", 2)[0]] = self.expand(d.findtext(ns + "version")) or version
        return found


def pom_properties(z, entry):
    """(g, a, v) of a pom.properties in zip Z ("" where one is missing)."""
    lines = z.read(entry).decode("utf-8", "replace").splitlines()
    props = dict(l.split("=", 1) for l in lines if "=" in l and not l.startswith("#"))
    return tuple(props.get(k, "").strip() for k in ("groupId", "artifactId", "version"))


def analyze(jar, g, a, v, pom_path, repos, name=None):
    """({g:a: version} of the libraries a jar bundles, {g:a: [g:a it depends on]}
    among them from their embedded POMs, [g:a] the jar's own original pom.xml
    declares). pom_path: the published POM, or None (only pom.properties count).
    name: the jar's name in the log."""
    name, own = name or os.path.basename(jar), g + ":" + a
    bundled, own_deps = {}, []
    with zipfile.ZipFile(jar) as z:
        names = set(z.namelist())
        # 1. other libraries' pom.properties
        for entry in sorted(names):
            if not POM_PROPERTIES.fullmatch(entry):
                continue
            lg, la, lv = pom_properties(z, entry)
            if lg and la and lv and lg + ":" + la != own:
                bundled[lg + ":" + la] = lv
                log("Shaded in %s: %s:%s:%s" % (name, lg, la, lv))
        # 2. the jar's own pom.xml: runtime deps the published POM dropped
        own_pom = "META-INF/maven/%s/%s/pom.xml" % (g, a)
        if own_pom in names:
            raw = z.read(own_pom)
            declared = Pom(raw, g, v, repos, "%s!/%s" % (name, own_pom)).runtime_deps()
            if declared is None:  # unreadable: as a jar without one
                raw, declared = b"", {}
            own_deps = list(declared)
            if b"maven-shade-plugin" in raw and pom_path:
                with open(pom_path, "rb") as f:
                    kept = Pom(f.read(), g, v, repos, pom_path).runtime_deps()
                if kept is None:  # unreadable: as without a published POM, only pom.properties count
                    declared = {}
                for ga, ver in sorted(declared.items()):
                    if ga in kept or ga in bundled or ga == own:
                        continue
                    if "${" in ga + ver or not ver:
                        if any(b.split(":")[1] == ga.split(":")[1] for b in bundled):
                            continue  # same library, already found with its version
                        log("WARNING: %s bundles %s%s but its version can't be determined; not reported"
                            % (name, ga, ":" + ver if ver else ""))
                        continue
                    bundled[ga] = ver
                    log("Shaded in %s: %s:%s (from its own pom.xml)" % (name, ga, ver))
        # dependencies among the bundled libraries, from their embedded POMs
        graph = {}
        for ga, ver in bundled.items():
            lg, la = ga.split(":")
            embedded = "META-INF/maven/%s/%s/pom.xml" % (lg, la)
            deps = (Pom(z.read(embedded), lg, ver, repos, "%s!/%s" % (name, embedded)).runtime_deps()
                    if embedded in names else {})
            graph[ga] = [d for d in deps or {} if "${" not in d]
        if not bundled:
            classes = [n for n in names if n.endswith(".class") and not n.startswith("META-INF/")]
            counts = collections.Counter(m.group(1) for m in map(RELOCATED.match, classes) if m)
            if counts:
                licenses = sorted(os.path.basename(n) for n in names
                                  if re.fullmatch(r"META-INF/[^/]+-LICENSE[^/]*", n))
                log("WARNING: %s contains relocated code with no Maven metadata, not reported: %s%s"
                    % (name, ", ".join("%s (%d classes)" % kv for kv in sorted(counts.items())),
                       "; license files: " + ", ".join(licenses) if licenses else ""))
    return bundled, graph, own_deps


def resolved_artifacts(path):
    """[(g, a, classifier, v, file)] from dependency:list -DoutputAbsoluteArtifactFilename."""
    arts = []
    with open(path) as f:
        for line in f:
            gav, sep, file = line.split(" -- ")[0].strip().partition(":/")
            if sep and gav.count(":") >= 4:  # g:a:type[:classifier]:version:scope
                arts.append(coords(gav) + ("/" + file.split()[0],))
    return arts


def tree_lines(path):
    """The text dependency:tree in PATH: a root, or a node after "+- " or
    "\\- ". dependency:list wrote its entries (indented) to the same file."""
    with open(path, errors="replace") as f:
        return [line for line in f.read().splitlines() if TREE_LINE.match(line)]


def read_tree(path, omitted=False):
    """[(node, its parent node or None)] in tree order, each node (g, a,
    classifier, v). Nodes Maven omitted (in parentheses, with -Dverbose: a
    duplicate or a conflict) are left out, as the agent doesn't send them,
    unless OMITTED. An excluded node isn't listed at all."""
    tree, stack = [], []
    for line in tree_lines(path):
        prefix, node = TREE_LINE.match(line).groups()
        del stack[len(prefix) // 3:]
        stack.append(None if node.startswith("(") and not omitted else coords(node.lstrip("(")))
        if None not in stack:
            tree.append((stack[-1], stack[-2] if len(stack) > 1 else None))
    return tree


def local_repo(arts):
    """The local repository root, from where Maven put a resolved artifact."""
    for g, a, _, v, file in arts:
        layout = os.path.join(*g.split("."), a, v)
        folder = os.path.dirname(file)
        if folder.endswith(os.sep + layout):
            return folder[:-len(layout) - 1]
    return ""


def mvn_run(*args, stdin=None):
    """Print the full command line, then run it; True if Maven succeeded."""
    log("$ mvn -B %s %s" % (MVN_LOG_LEVEL, " ".join(args)))
    return subprocess.run(["mvn", "-B"] + MVN_LOG_LEVEL.split() + list(args), stdin=stdin).returncode == 0


def resolve(work, n, tail=""):
    """Every resolved artifact with its file path, and from round 2 on the tree
    as the scanner's agent gets it, in one Maven run (both append to
    WORK/resolved.txt). tail: local repos behind the real one, for this run."""
    out = os.path.join(work, "resolved.txt")
    if os.path.exists(out):
        os.remove(out)
    tree = [DEP_PLUGIN + ":tree", "-Dverbose", "-DoutputType=text", "-T1"] if n > 1 else []
    return mvn_run(DEP_PLUGIN + ":list", *tree, "-DoutputAbsoluteArtifactFilename=true",
                   "-DoutputFile=" + out, "-DappendOutput=true",
                   *(["-Dmaven.repo.local.tail=" + tail] if tail else []))


def settings_local_repo(work):
    """The local repository Maven uses, which honours -Dmaven.repo.local: in a
    repository without pom.xml, no resolved artifact shows it."""
    out = os.path.join(work, "local-repo.txt")
    if not mvn_run(HELP_PLUGIN + ":evaluate", "-Dexpression=settings.localRepository", "-Doutput=" + out,
                   stdin=subprocess.DEVNULL) or not os.path.exists(out):
        return ""
    with open(out) as f:
        return f.read().strip()


MINIMAL_POM = ('<?xml version="1.0" encoding="UTF-8"?>\n<project xmlns="%s">\n  <modelVersion>4.0.0</modelVersion>\n'
               '  <groupId>%%s</groupId>\n  <artifactId>%%s</artifactId>\n  <version>%%s</version>\n</project>\n' % NS)
# + the jars' own <packaging>, if any (never pom: Mend's agent skips a pom-packaged project, maven.ignorePomModules)
PROJECT_POM = ('<?xml version="1.0" encoding="UTF-8"?>\n'
               '<!-- written by the shaded-jars pre-build hook for this scan: the jars here that bundle libraries -->\n'
               '<project xmlns="%s">\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>shaded-hook</groupId>\n'
               '  <artifactId>binaries</artifactId>\n  <version>0</version>\n%%s'
               '  <dependencies>\n%%s  </dependencies>\n</project>\n' % NS)
DEPENDENCY = ("    <dependency><groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version>"
              "<classifier>%s</classifier></dependency>\n")


def find_binaries():
    """[(path, g, a, v)] of the jars named <artifactId>-<version>.jar after their
    own pom.properties that bundle libraries. None in a repository with a build
    anywhere: a Maven project in a subfolder would pick up .mvn/maven.config."""
    found = []
    for dirpath, dirs, names in os.walk("."):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))  # .git, .mvn: not part of the scan
        if BUILD_FILES & set(names):
            return []
        for name in sorted(n for n in names if n.endswith(".jar")):
            path = os.path.relpath(os.path.join(dirpath, name))
            try:
                with zipfile.ZipFile(path) as z:
                    libs = [pom_properties(z, e) for e in z.namelist() if POM_PROPERTIES.fullmatch(e)]
                    own = [gav for gav in libs if name == "%s-%s.jar" % gav[1:]]
                    own_pom = own and "META-INF/maven/%s/%s/pom.xml" % own[0][:2]
                    shade = own_pom in z.namelist() and b"maven-shade-plugin" in z.read(own_pom)
            except (zipfile.BadZipFile, OSError):
                log("WARNING: %s isn't a readable jar; not inspected" % path)
                continue
            if own and (len(libs) > 1 or shade):
                found.append((path,) + own[0])
    return found


def own_packaging(path, g, a):
    """The <packaging> the jar's own pom.xml declares, or "" (Maven's default, jar)."""
    with zipfile.ZipFile(path) as z:
        entry = "META-INF/maven/%s/%s/pom.xml" % (g, a)
        if entry not in z.namelist():
            return ""
        root = parse_pom(z.read(entry), "%s!/%s" % (os.path.basename(path), entry))
    return "" if root is None else (root.findtext(ns_of(root) + "packaging") or "").strip()


def class_packages(jar):
    """{package path: {class file names}} of a jar. META-INF/ holds
    multi-release copies, and the default package, package-info and
    module-info say nothing about where a library's classes went."""
    packages = collections.defaultdict(set)
    with zipfile.ZipFile(jar) as z:
        for entry in z.namelist():
            folder, _, name = entry.rpartition("/")
            if name.endswith(".class") and name not in NOT_CLASSES and folder and not entry.startswith("META-INF/"):
                packages[folder].add(name)
    return packages


def relocations(bundling_jar, bundled_jars):
    """{relocated package: {original packages}}, dotted, of a jar that bundles
    BUNDLED_JARS, matched by class file names: a package no bundled jar has,
    whose original is a bundled package (never one under it) with all its
    classes, the one whose name it ends with, else the only one, for a package
    of at least 3 classes, so common class names can't match by chance."""
    bundled, holders = [class_packages(jar) for jar in bundled_jars], collections.defaultdict(set)
    for packages in bundled:
        for p, names in packages.items():
            for name in names:
                holders[name].add(p)  # an index by class name, so large uber-jars stay fast
    found = {}
    for q, names in class_packages(bundling_jar).items():
        if any(q in packages for packages in bundled):
            continue
        matches = {p for p in set.intersection(*(holders.get(name, set()) for name in names))
                   if not p.startswith(q + "/")}
        same_end = sorted((p for p in matches if q.endswith("/" + p)), key=len)
        if same_end or len(matches) == 1 and len(names) >= 3:
            found[q.replace("/", ".")] = {(same_end[-1] if same_end else matches.pop()).replace("/", ".")}
    return found


def derelocate(name, mapping):
    """The original names of an imported name, by the longest relocated package
    it is in, and again for each (a bundle in a bundle); up to 10, since a
    mapping can grow a name for ever. MAPPING: relocations()."""
    found, todo = [], [name]
    while todo and len(found) < 10:
        parts = todo.pop(0).split(".")
        for i in range(len(parts) - 1, 0, -1):
            package = ".".join(parts[:i])
            if package in mapping:
                for original in sorted(mapping[package]):
                    new = ".".join([original] + parts[i:])
                    if new != name and new not in found:  # a loop stops here
                        found.append(new)
                        todo.append(new)
                break
    return found


def java_imports(text):
    """(package or None, [(static, imported name)]) of a .java file's text,
    from its header only (before the first type declaration), without
    comments, so strings and text blocks in the code can't add imports."""
    text = COMMENTS.sub(" ", text.lstrip("\ufeff"))  # a byte-order mark can't hide "package"
    end = JAVA_TYPE.search(text)
    header = text[:end.start()] if end else text
    package = JAVA_PACKAGE.search(header)
    return (package.group(1) if package else None,
            [(bool(m.group(1)), m.group(2)) for m in JAVA_IMPORT.finditer(header)])


def module_root(path):
    """The nearest folder above a source file with a pom.xml, else the scan's
    root: Mend's reachability analysis reads each module's sources on their own."""
    folder = os.path.dirname(path)
    while folder and not os.path.isfile(os.path.join(folder, "pom.xml")):
        folder = os.path.dirname(folder)
    return folder or "."


class Scan:
    """One run of the hook: resolve the project, plan every copy, write them,
    then check the tree Maven resolves with them; undo everything on failure."""

    def __init__(self, work, overlay):
        self.work, self.overlay = work, overlay
        self.resolved = os.path.join(work, "resolved.txt")  # resolve()'s output
        self.m2 = ""             # the real local repo, where the scanner fingerprints jars
        self.modules = set()     # (g, a, v) of a reactor's modules
        self.stubs = ""          # the folder of their placeholder jars
        self.patches = {}        # POM g:a:v -> {real, children: {g:a: {v, as, node}}, strip, cls}
        self.claimed = {}        # g:a:v -> the copy (classifier) using its published POM; "" = the project
        self.analysis = {}       # published g:a:v, + ":classifier" for a project jar with one -> analyze()
        self.bundled_all = set()  # g:a of every library found bundled
        self.exclusions = set()  # g:a excluded on the edges of copies with children (verify)
        self.moved = set()       # (g:a, classifier) of the copies an exclusion dropped, declared under SHADED_GROUP
        self.fetched = set()     # artifacts dependency:get ran for
        self.warned = set()      # warnings logged once
        self.written = set()     # the POMs the hook wrote into the overlay: never promoted
        self.binaries = {}       # binary mode: g:a:v -> the jar's path in the repository
        self.wrote_pom = False   # binary mode: the hook wrote pom.xml
        self.config = False      # .mvn/maven.config's bytes before the hook; False: untouched, None: absent
        self.mirrors = set()     # the REACH_DIR folders the hook created
        self.round = 1

    def warn_once(self, msg):
        if msg not in self.warned:
            self.warned.add(msg)
            log(msg)

    def run(self):
        """0 if done or nothing to do, 1 if Maven can't resolve the project or
        everything was rolled back."""
        try:
            if not os.path.isfile("pom.xml") and not self.plan_binaries():
                return 0  # neither a Maven project nor a jar that bundles libraries
            if not self.plan_modules():
                return 1  # Maven can't read the POMs; nothing changed yet (binary mode has no modules)
            if not resolve(self.work, 1, self.repo_tail()):
                if self.config is False:
                    return 1  # nothing changed yet
                raise Rollback("Maven failed with the patched POMs (round 1)")
            arts = [art for art in resolved_artifacts(self.resolved)
                    if (art[0], art[1], art[3]) not in self.modules]  # a module's jar: unbuilt, or stale
            self.m2 = self.m2 or local_repo(arts)  # plan_binaries found it already
            self.plan(arts)
            if not self.copies():
                if self.patches or self.config is not False:
                    self.rollback()
                    log("No bundled library could be reported; the hook's changes are undone")
                return 0
            if self.config is False:  # binary mode configured it already
                self.add_overlay_config()
            self.materialize()
            problems = self.check()
        except Exception as e:
            if not isinstance(e, Rollback):
                traceback.print_exc()
                e = "helper failed (round %d)" % self.round
            self.rollback()
            log("WARNING: %s; removing the overlay - shaded libraries won't be reported" % e)
            return 1
        if problems == 0:
            copies = self.copies()
            log("Verified: all %d bundled dependencies resolve, each as its own copy under the library "
                "that declares it (%d copies)" % (len(copies), len(set(copies))))

        try:  # the scanner fingerprints jars only in the real local repo
            self.promote()
        except Exception:
            traceback.print_exc()
            log("WARNING: couldn't copy downloads into the local repo; they'll be reported without a SHA-1")

        if REACHABILITY:  # best effort: without these files, reachability stays as it was; the tree stays either way
            try:
                self.write_reachability_imports()
            except Exception as e:
                traceback.print_exc()
                for folder in self.mirrors:
                    shutil.rmtree(folder, ignore_errors=True)
                log("WARNING: couldn't write the reachability imports (%s: %s); Mend's reachability of the bundled "
                    "libraries stays as without them" % (e.__class__.__name__, e))

        # the last round's tree, the agent's own (promote only adds files behind the overlay)
        log("Dependency tree:")
        for line in tree_lines(self.resolved):
            log("  " + line)
        return 0

    def plan_binaries(self):
        """A repository without pom.xml: declare each jar in it that bundles
        libraries in a pom.xml written for this scan, as a copy of itself whose
        POM is the hook's, so nothing but the bundled libraries comes in under
        it. Its published POM only serves analyze(). False if there's none."""
        for path, g, a, v in find_binaries() if BINARY_JARS else []:
            self.binaries.setdefault("%s:%s:%s" % (g, a, v), path)  # the same jar twice: once
        if not self.binaries:
            return False
        log("Jars that bundle libraries, in a repository without pom.xml: %s"
            % ", ".join("%s (%s)" % (path, gav) for gav, path in self.binaries.items()))
        self.m2 = settings_local_repo(self.work)
        if not self.m2:
            raise Rollback("couldn't determine the local Maven repository")
        self.add_overlay_config()
        deps, packagings = [], set()
        for gav, path in self.binaries.items():
            g, a, v = gav.split(":")
            packagings.add(own_packaging(path, g, a))
            published = repo_path(self.m2, g, a, v)
            if not os.path.exists(published) and not mvn_run(
                    DEP_PLUGIN + ":get", "-N", "-Dartifact=%s:pom" % gav, "-Dtransitive=false",
                    "-Dmaven.repo.local=" + self.m2, stdin=subprocess.DEVNULL):
                log("WARNING: %s isn't published where Maven looks; only libraries with their own pom.properties "
                    "in %s are reported" % (gav, path))
            self.analysis[gav] = analyze(path, g, a, v, published if os.path.exists(published) else None, [self.m2])
            cls = BINARY_PREFIX + v
            self.claimed[gav] = cls  # the hook's POM: a copy of this version with children gets its own
            self.patches[gav] = {"real": gav, "children": {}, "strip": True, "cls": ""}  # a path starts here
            jar = repo_path(self.overlay, g, a, v, "jar", cls)
            os.makedirs(os.path.dirname(jar), exist_ok=True)
            shutil.copyfile(path, jar)
            for out in (repo_path(self.overlay, g, a, v), os.path.join(self.work, "orig", "%s_%s_%s.pom" % (g, a, v))):
                os.makedirs(os.path.dirname(out), exist_ok=True)
                with open(out, "w") as f:
                    f.write(MINIMAL_POM % (g, a, v))
            self.written.add(repo_path(self.overlay, g, a, v))
            deps.append(DEPENDENCY % (g, a, v, cls))
        packaging = packagings.pop() if len(packagings) == 1 else ""  # jars that disagree: Maven's default
        self.wrote_pom = True  # before writing, so a partial write is rolled back too
        with open("pom.xml", "w") as f:
            f.write(PROJECT_POM % ("  <packaging>%s</packaging>\n" % packaging if packaging else "", "".join(deps)))
        return True

    def plan_modules(self):
        """A reactor's modules, and an empty placeholder jar, for the hook's own
        runs only (repo_tail), for each module another one depends on: nothing
        is built, so dependency:list would fail. False if Maven can't read the POMs."""
        with open("pom.xml", "rb") as f:
            if b"<module>" not in f.read():
                return True  # a single project
        out = os.path.join(self.work, "modules.txt")
        if not mvn_run(DEP_PLUGIN + ":tree", "-DoutputType=text", "-DoutputFile=" + out, "-DappendOutput=true"):
            return False
        tree = read_tree(out)
        self.modules = {(g, a, v) for (g, a, _, v), parent in tree if parent is None}
        needed = sorted({(g, a, cls, v) for (g, a, cls, v), parent in tree if parent and (g, a, v) in self.modules})
        if needed:
            self.stubs = os.path.join(self.work, "stubs")
            for g, a, cls, v in needed:
                path = repo_path(self.stubs, g, a, v, "jar", cls)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                zipfile.ZipFile(path, "w").close()
        log("Multi-module project (%d modules)%s" % (len(self.modules), "; Maven can't resolve a module that isn't "
            "built, so the hook's own Maven runs use an empty placeholder jar for " + ", ".join(
                "%s:%s%s" % (a, v, ":" + cls if cls else "") for _, a, cls, v in needed) if needed else ""))
        return True

    def repo_tail(self):
        """-Dmaven.repo.local.tail for the hook's own runs: the placeholder jars,
        behind the real local repo once the overlay is in front of it."""
        return ",".join(p for p in (self.m2, self.stubs) if p) if self.stubs else ""

    def plan(self, arts):
        """Plan every copy before any is written, level by level: round 1's jars
        ARTS, then the published jars of the libraries they bundle, and so on,
        each level's fetched first. The project's jars in list order, then depth
        first through the copies, so the copy nearest the project keeps the
        published POM."""
        level, planned = {}, set()  # (analysis key, published g:a:v, jar, name in the log) -> copy's (POM, g:a)
        for g, a, cls, v, jar in arts:
            gav = "%s:%s:%s" % (g, a, v)
            self.claimed.setdefault(gav, "")  # the project uses its POM, a classifier's too; a binary keeps its claim
            if jar.endswith(".jar") and os.path.exists(jar):
                key = gav + ":" + cls if cls and gav not in self.binaries else gav  # not the published jar
                level.setdefault((key, gav, jar, os.path.basename(jar)), None)
        for depth in range(1, MAX_ROUNDS + 1):
            bundling = [(item, at) for item, at in level.items() if self.look_inside(*item)[0]]
            if not bundling:
                return
            if depth == MAX_ROUNDS:
                for (_, _, _, name), _ in bundling:
                    log("WARNING: %s - nested deeper than MAX_ROUNDS; not reported" % name)
                return
            if not self.m2:
                raise Rollback("couldn't determine the local Maven repository")
            owners = []  # (POM, analysis key, name), each POM once
            for (key, real, _, name), at in bundling:
                owner = self.owner_of(real, at)
                if owner not in planned:
                    planned.add(owner)
                    owners.append((owner, key, name))
            need = []
            for ga, v in sorted({lib for _, key, _ in owners for lib in self.analysis[key][0].items()}):
                if not self.find_jar(ga, v):
                    need.append("%s:%s" % (ga, v))  # brings its POM and parent POMs
                elif not self.original_pom(*ga.split(":"), v):
                    need.append("%s:%s:pom" % (ga, v))
            self.fetch(need)
            declared = []
            for owner, key, name in owners:
                declared += self.plan_bundle(owner, name, *self.analysis[key])
            level = {}
            for owner, ga in self.tree_order(declared):
                patch, child = self.patches[owner], self.patches[owner]["children"][ga]
                real = ga + ":" + child["v"]
                name = os.path.basename(repo_path("", *ga.split(":"), child["as"], "jar", classifier_for(patch)))
                level[(real, real, self.find_jar(ga, child["v"]), name)] = (owner, ga)

    def look_inside(self, key, real, jar, name):
        """analyze() of a jar, once per key: copies are byte-identical to the published jar."""
        if key not in self.analysis:
            pom = self.original_pom(*real.split(":"))
            self.analysis[key] = (analyze(jar, *real.split(":"), pom, [self.m2, self.overlay], name)
                                  if pom else ({}, {}, []))
        return self.analysis[key]

    def owner_of(self, real, at):
        """The POM that declares what a jar bundles: a project artifact's own; for
        a copy (AT: its parent POM and g:a), its node."""
        if at is None:
            self.patches.setdefault(real, {"real": real, "children": {}, "strip": False, "cls": ""})
            return real
        parent, ga = at
        return self.node_of(self.patches[parent]["children"][ga], real, classifier_for(self.patches[parent]))

    def node_of(self, child, gav, cls):
        """The POM of a copy with children (child: a children entry), made now if it has none."""
        if child["node"] is None:
            child["node"] = self.new_owner(gav, cls)
            child["as"] = child["node"].split(":")[2]
        return child["node"]

    def new_owner(self, gav, cls):
        """The POM (g:a:version) of the copy of gav with classifier cls, which has
        children: the published one for the first such copy (all copies of a
        version share it), else "<version>-own<n>", the smallest n still free."""
        claimant = self.claimed.setdefault(gav, cls)
        owner = gav if claimant == cls else next(
            (o for o, p in self.patches.items() if p["real"] == gav and p["cls"] == cls), None)
        if owner is None:
            n = 2
            while OWN_VERSION % (gav, n) in self.patches:
                n += 1
            owner = OWN_VERSION % (gav, n)
        if owner not in self.patches:
            self.patches[owner] = {"real": gav, "children": {}, "strip": True, "cls": cls}
            if owner != gav:
                log("Own version: %s:%s has children, and %s already uses the published POM; declared as version %s"
                    % (gav, cls, "copy " + claimant if claimant else "the project", owner.split(":")[2]))
        return owner

    def plan_bundle(self, jar_owner, jar_name, bundled, graph, own_deps):
        """Declare what one jar bundles, as a tree: what its own pom.xml declares
        and each library's own dependencies, among the libraries in the jar; the
        jar declares the rest. A copy under each parent, none without a published
        jar. Returns the (POM, g:a) declared."""
        kids_of = {ga: [d for d in graph.get(ga, []) if d in bundled and d != ga] for ga in bundled}
        top = [ga for ga in own_deps if ga in bundled]
        declared = set(top) | {ga for kids in kids_of.values() for ga in kids}
        top += sorted(ga for ga in bundled if ga not in declared)
        log("Edges in %s: %s" % (jar_name, "; ".join(
            "%s -> %s" % (owner.split(":")[1], ", ".join(k.split(":")[1] for k in kids))
            for owner, kids in [(jar_owner, top)] + list(kids_of.items()) if kids)))
        self.bundled_all |= set(bundled)
        found = []

        def declare(owner, kids, path):
            cls, children = classifier_for(self.patches[owner]), self.patches[owner]["children"]
            for ga in kids:
                if ga not in children:  # else declared already, e.g. by the jar of its parent's parent
                    if not self.find_jar(ga, bundled[ga]):
                        log("WARNING: couldn't fetch the published %s:%s jar; it is not reported under %s"
                            % (ga, bundled[ga], owner))
                        continue
                    children[ga] = {"v": bundled[ga], "as": bundled[ga], "node": None}
                    found.append((owner, ga))
                child = children[ga]
                sub = [k for k in kids_of[ga] if k not in path]  # a dependency cycle stops here
                if sub and child["node"] is None:
                    declare(self.node_of(child, ga + ":" + child["v"], cls), sub, path | {ga})
        declare(jar_owner, top, {jar_owner.rsplit(":", 1)[0]})
        return found

    def tree_order(self, pairs):
        """PAIRS (POM, g:a) in tree order: the project's jars in list order, then
        depth first through the copies, as Maven lists them under each."""
        wanted, nodes, order = set(pairs), set(), []
        for patch in self.patches.values():
            nodes |= {child["node"] for child in patch["children"].values() if child["node"]}

        def walk(owner, path):
            for ga, child in self.patches[owner]["children"].items():
                if (owner, ga) in wanted:
                    wanted.discard((owner, ga))
                    order.append((owner, ga))
                if child["node"] and child["node"] not in path:
                    walk(child["node"], path | {child["node"]})
        for owner in [o for o in self.patches if o not in nodes]:
            walk(owner, {owner})
        return order

    def check(self):
        """Rounds 2 ... MAX_ROUNDS: resolve with the copies and verify the tree, and
        another round only after new exclusions. The last round's problems."""
        for n in range(2, MAX_ROUNDS + 1):
            self.round = n
            if not resolve(self.work, n, self.repo_tail()):
                raise Rollback("Maven failed with the patched POMs (round %d)" % n)
            before = len(self.exclusions), len(self.moved)
            problems = self.verify(read_tree(self.resolved), n == MAX_ROUNDS, read_tree(self.resolved, omitted=True))
            if (len(self.exclusions), len(self.moved)) == before:
                return problems
            self.materialize()  # the new exclusions, the moved copies
        return None  # no round left to check them

    def copies(self):
        """[(g:a, published version, classifier, declared version)] of every copy planned."""
        return [(ga, child["v"], classifier_for(patch), child["as"])
                for patch in self.patches.values() for ga, child in patch["children"].items()]

    def group_of(self, ga, cls):
        """The groupId the copy of ga with classifier cls is declared with."""
        g = ga.split(":")[0]
        return SHADED_GROUP % g if (ga, cls) in self.moved else g

    def unwrite(self, ga, cls, child):
        """Remove the copy's jar from the overlay, and its POM if it has children:
        nothing declares them at these coordinates any more."""
        jar = repo_path(self.overlay, self.group_of(ga, cls), ga.split(":")[1], child["as"], "jar", cls)
        if os.path.exists(jar):
            os.remove(jar)
        pom = child["node"] and repo_path(self.overlay, *child["node"].split(":"))
        if pom in self.written:
            if os.path.exists(pom):
                os.remove(pom)
            self.written.discard(pom)

    def move(self, owner, ga):
        """Declare the copy of ga under owner at SHADED_GROUP, which the exclusion
        that removes it doesn't match. A copy with children takes its POM along."""
        cls, child = classifier_for(self.patches[owner]), self.patches[owner]["children"][ga]
        self.unwrite(ga, cls, child)
        self.moved.add((ga, cls))
        g, a = ga.split(":")
        log("%s:%s:%s doesn't resolve under %s: an exclusion on its path removes it. Its copy is declared under "
            "groupId %s instead" % (ga, child["as"], cls, owner, SHADED_GROUP % g))
        if child["node"]:
            node = "%s:%s:%s" % (SHADED_GROUP % g, a, child["as"])
            self.patches[node] = self.patches.pop(child["node"])
            child["node"] = node

    def leave_out(self, owner, ga):
        """Forget the copy of ga under owner, which an exclusion on its path
        removes, and everything under it, as Maven leaves them out."""
        cls, child = classifier_for(self.patches[owner]), self.patches[owner]["children"].pop(ga)
        self.unwrite(ga, cls, child)
        if child["node"] in self.patches:
            for sub in list(self.patches[child["node"]]["children"]):
                self.leave_out(child["node"], sub)
            del self.patches[child["node"]]

    def fetch(self, artifacts):
        """Fetch published jars (with their POM and parent POMs) and POMs into the
        real local repo, once each."""
        for artifact in sorted(set(artifacts) - self.fetched):
            self.fetched.add(artifact)
            if not mvn_run(DEP_PLUGIN + ":get", "-N", "-Dartifact=" + artifact, "-Dtransitive=false",
                           "-Dmaven.repo.local=" + self.m2, stdin=subprocess.DEVNULL):
                log("WARNING: couldn't fetch " + artifact)

    def find_jar(self, ga, v, cls=""):
        """A published jar in the real local repo, where round 1 and fetch put them; None if missing."""
        path = repo_path(self.m2, *ga.split(":"), v, "jar", cls)
        return path if os.path.exists(path) else None

    def original_pom(self, g, a, v):
        """The published POM of g:a:v in the real local repo (a binary's: the
        hook's own, kept in WORK/orig); None if missing."""
        for p in (os.path.join(self.work, "orig", "%s_%s_%s.pom" % (g, a, v)), repo_path(self.m2, g, a, v)):
            if os.path.exists(p):
                return p
        return None

    def materialize(self):
        """Write the copies not written yet, then every patched POM, into the overlay."""
        for ga, v, cls, ver in self.copies():
            g, a = self.group_of(ga, cls), ga.split(":")[1]
            copy = repo_path(self.overlay, g, a, ver, "jar", cls)
            if not os.path.exists(copy):
                os.makedirs(os.path.dirname(copy), exist_ok=True)
                link_or_copy(self.find_jar(ga, v), copy)
                log("Copy: %s:%s:%s:%s (byte-identical to the published %s jar)" % (g, a, ver, cls, v))
            pom = repo_path(self.overlay, g, a, ver)  # a moved copy without children: a POM with nothing in it
            if (ga, cls) in self.moved and "%s:%s:%s" % (g, a, ver) not in self.patches and not os.path.exists(pom):
                with open(pom, "w") as f:
                    f.write(MINIMAL_POM % (g, a, ver))
                self.written.add(pom)
        for owner in self.patches:
            self.write_pom(owner)

    def write_pom(self, owner):
        """The published POM of owner, its children declared as copies (*:* on a
        leaf), its runtime dependencies removed if it is a copy, at its own
        version if it has one. Written, and logged, only when it changes."""
        g, a, ver = owner.split(":")
        patch = self.patches[owner]
        orig = self.original_pom(*patch["real"].split(":"))
        root = None
        if orig is not None:
            with open(orig, "rb") as f:
                root = parse_pom(f.read(), orig)
        if root is None:  # missing, or unreadable even as Maven reads it
            if patch["children"]:
                self.warn_once("WARNING: couldn't get the published POM of %s; its bundled dependencies are not "
                               "reported" % owner)
            return
        ns = ns_of(root)
        deps = root.find(ns + "dependencies")
        removed = 0
        if patch["strip"] and deps is not None:
            for d in list(deps):
                if d.tag == ns + "dependency" and is_runtime(d, ns):
                    deps.remove(d)
                    removed += 1
        own_version = owner != patch["real"]
        if not patch["children"] and not removed and not own_version:
            return  # nothing to change: the published POM stays in use
        if deps is None:
            deps = ET.SubElement(root, ns + "dependencies")
        cls = classifier_for(patch)
        for ga, child in patch["children"].items():
            dep = ET.SubElement(deps, ns + "dependency")
            cg, ca = self.group_of(ga, cls), ga.split(":")[1]
            for tag, val in (("groupId", cg), ("artifactId", ca), ("version", child["as"]), ("classifier", cls)):
                ET.SubElement(dep, ns + tag).text = val
            excls = ET.SubElement(dep, ns + "exclusions")
            for x in sorted(self.exclusions) if child["node"] else ["*:*"]:
                excl = ET.SubElement(excls, ns + "exclusion")
                xg, xa = x.split(":")
                ET.SubElement(excl, ns + "groupId").text = xg
                ET.SubElement(excl, ns + "artifactId").text = xa
            if not len(excls):
                dep.remove(excls)
        data = ET.tostring(root, encoding="UTF-8", xml_declaration=True)
        out = repo_path(self.overlay, g, a, ver)
        if out in self.written and os.path.exists(out):
            with open(out, "rb") as f:
                if f.read() == data:
                    return  # unchanged since the last round
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "wb") as f:
            f.write(data)
        self.written.add(out)
        log("Patched POM: %s declares %s%s%s" % (
            os.path.relpath(out, self.overlay),
            ", ".join("%s:%s:%s:%s" % (self.group_of(ga, cls), ga.split(":")[1], c["as"], cls)
                      for ga, c in patch["children"].items()) or "nothing",
            "; removed its %d runtime dependencies" % removed if removed else "",
            " (the published %s POM, at this copy's own version)" % patch["real"] if own_version else ""))

    def verify(self, tree, last, listed=None):
        """The problems in TREE: a declared copy not resolved under its parent, or
        a stray under a copy with children (from its POM's parents). A copy that
        an exclusion on its path removes (missing under a parent that resolved,
        and not in LISTED, TREE with the nodes Maven omitted) is left out, or with
        REPORT_EXCLUDED moved, unless this is the LAST round. A stray is
        excluded, unless this is the LAST round or it's bundled somewhere."""
        def edges(nodes):
            return {(p[0] + ":" + p[1] + ":" + p[3], g + ":" + a, v, cls) for (g, a, cls, v), p in nodes if p}

        def edge(owner, ga, child, cls):
            return owner, self.group_of(ga, cls) + ":" + ga.split(":")[1], child["as"], cls
        under, shown = edges(tree), edges(tree if listed is None else listed)
        resolved = collections.defaultdict(set)  # g:a:v -> the classifiers it resolved with
        for (g, a, cls, v), _ in tree:
            resolved["%s:%s:%s" % (g, a, v)].add(cls)
        excluded = []
        for owner, patch in self.patches.items():
            cls = classifier_for(patch)
            # its parent resolved: a copy's node with the copy's classifier, a project artifact as any
            here = patch["cls"] in resolved[owner] if patch["cls"] else resolved[owner]
            excluded += [(owner, ga) for ga, child in patch["children"].items()
                         if here and (ga, cls) not in self.moved and edge(owner, ga, child, cls) not in shown]
        moving = REPORT_EXCLUDED and not last and excluded
        for owner, ga in excluded:
            if REPORT_EXCLUDED:
                if moving:
                    self.move(owner, ga)
                continue
            patch = self.patches[owner]
            child = patch["children"][ga]
            log("Not reported: %s:%s:%s under %s: an exclusion on its path removes it%s (REPORT_EXCLUDED = True "
                "reports it)" % (ga, child["as"], classifier_for(patch), owner,
                                 ", with what's under it" if child["node"] else ""))
            self.leave_out(owner, ga)
        problems = 0
        for owner, patch in self.patches.items():
            cls = classifier_for(patch)
            for ga, child in patch["children"].items():
                if edge(owner, ga, child, cls) not in under:
                    problems += 1
                    if not moving:  # else the next round checks them again
                        self.warn_once("WARNING: %s declares %s:%s:%s but Maven doesn't resolve it there"
                                       % (owner, edge(owner, ga, child, cls)[1], child["as"], cls))
        strays = {}  # g:a -> the copy it resolved under
        for (g, a, cls, v), p in tree:
            owner = p and "%s:%s:%s" % (p[0], p[1], p[3])
            patch = self.patches.get(owner) if owner else None
            if not patch or not patch["strip"]:
                continue  # a module, or one of the project's artifacts: its own dependencies are real
            child = next((c for ga, c in patch["children"].items()
                          if self.group_of(ga, classifier_for(patch)) + ":" + ga.split(":")[1] == g + ":" + a), None)
            if not child or (cls, v) != (classifier_for(patch), child["as"]):
                strays.setdefault(g + ":" + a, owner)
        extras = sorted(set(strays) - self.bundled_all - self.exclusions)
        for ga in sorted(set(strays) - set(extras)):
            self.warn_once("WARNING: %s resolves under %s, whose jar doesn't contain it, and can't be excluded there"
                           % (ga, strays[ga]))
        if extras:
            log(("WARNING: resolved but not in any shaded jar: %s" if last else
                 "Excluding libraries the shaded jars don't contain: %s") % ", ".join(extras))
            if not last:
                self.exclusions |= set(extras)
        return problems + len(strays)

    def promote(self):
        """Copy the overlay's new files into the real local repo, never
        overwriting and never a POM the hook wrote. With HARD_LINKS a copy is a
        hard link to its published jar (Maven only renames jars into place);
        nothing else is, as Maven rewrites some files in place."""
        twins = {repo_path(self.overlay, self.group_of(ga, cls), ga.split(":")[1], ver, "jar", cls):
                 repo_path(self.m2, *ga.split(":"), v, "jar")
                 for ga, v, cls, ver in self.copies()}  # overlay copy -> its published jar in the real repo
        srcs = sorted(os.path.join(dirpath, name) for dirpath, _, files in os.walk(self.overlay) for name in files
                      if not name.endswith(".lastUpdated") and name != "resolver-status.properties")
        copied = linked = 0
        for src in srcs:
            dst = os.path.join(self.m2, os.path.relpath(src, self.overlay))
            if os.path.exists(dst) or src in self.written:
                continue
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            twin = twins.get(src) if HARD_LINKS else None
            if twin and os.path.exists(twin) and (  # the same bytes, so the SHA-1 Mend matches
                    os.path.samefile(twin, src) or filecmp.cmp(twin, src, shallow=False)):
                linked += link_or_copy(twin, dst)
            else:
                copy_aside(src, dst)
            copied += 1
        if copied:
            log("Copied %d file(s) into %s, where the scanner fingerprints jars%s" % (
                copied, self.m2,
                "; %d of them are hard links to their published jar (no extra disk space)" % linked if linked else ""))

    def write_reachability_imports(self):
        """Mend's reachability analysis knows a bundled library's classes by their
        original names only. So for each source file that imports relocated
        classes, write one with the same package and file name that imports them
        under those names, at <module>/REACH_DIR/<its path in the module>."""
        sources = []
        for dirpath, dirs, names in os.walk("."):
            dirs[:] = sorted(d for d in dirs if not d.startswith("."))  # .git, .mvn, REACH_DIR
            sources += [os.path.relpath(os.path.join(dirpath, n)) for n in sorted(names) if n.endswith(".java")]
        if not sources:
            return
        # the jars Maven resolved, keyed as self.analysis, a shaded classifier's (-shaded, -all...) too; not copies
        resolved = collections.defaultdict(list)
        for g, a, cls, v, file in resolved_artifacts(self.resolved):
            if not cls.startswith(CLASSIFIER_PREFIX) and file.endswith(".jar") and os.path.isfile(file):
                resolved["%s:%s:%s" % (g, a, v) + (":" + cls if cls else "")].append(file)
        mapping = {}
        for key, (bundled, _, _) in sorted(self.analysis.items()):
            if not bundled:
                continue
            libs = [lib for lib in (self.find_jar(ga, v) for ga, v in sorted(bundled.items())) if lib]
            g, a, v, cls = (key.split(":") + [""])[:4]
            jars = [self.binaries[key]] if key in self.binaries else (
                resolved.get(key) or [self.find_jar(g + ":" + a, v, cls)])
            for jar in jars if libs else []:
                try:
                    found = relocations(jar, libs) if jar else {}
                except (zipfile.BadZipFile, OSError):
                    continue  # one Maven resolved but the hook didn't inspect
                if found:
                    q = min(found)
                    log("Relocated in %s: %d package%s of %s, e.g. %s (originally %s)" % (
                        os.path.basename(jar), len(found), "" if len(found) == 1 else "s",
                        ", ".join(ga.split(":")[1] for ga in sorted(bundled)), q, ", ".join(sorted(found[q]))))
                for q, originals in found.items():
                    mapping.setdefault(q, set()).update(originals)
        roots = []  # the relocated packages a file must mention, a subpackage with its parent
        for q in sorted(mapping):
            if not roots or not q.startswith(roots[-1] + "."):
                roots.append(q)
        written = []
        for path in sources:
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    text = f.read()
                if not any(root in text for root in roots):
                    continue
                package, imports = java_imports(text)
                lines = dict.fromkeys("import %s%s;\n" % ("static " if static else "", original)
                                      for static, name in imports for original in derelocate(name, mapping))
                if not lines:
                    continue
                root = module_root(path)
                folder = os.path.normpath(os.path.join(root, REACH_DIR))
                out = os.path.join(folder, os.path.relpath(path, root))
                if not os.path.exists(folder):
                    self.mirrors.add(folder)  # before writing, so a partial write is removed too
                os.makedirs(os.path.dirname(out), exist_ok=True)
                with open(out, "w", encoding="utf-8") as f:
                    f.write(COMPANION % (path, "package %s;\n\n" % package if package else "", "".join(lines)))
                written.append((path, out))
            except OSError as e:
                log("WARNING: couldn't write the reachability imports of %s (%s); that file is skipped" % (path, e))
        for path, out in written[:20]:
            log("Reachability: %s: its imports of relocated classes, under their original names, in %s" % (path, out))
        if len(written) > 20:
            log("... and %d more" % (len(written) - 20))
        log("Reachability: %d of %d source files import relocated classes" % (len(written), len(sources)))

    def add_overlay_config(self):
        """Append the overlay settings to .mvn/maven.config, so the scanner's own
        Maven runs see the patched POMs; self.config keeps the original."""
        os.makedirs(".mvn", exist_ok=True)
        self.config = None  # kept before appending, so a partial append is rolled back too
        if os.path.exists(CONFIG):
            with open(CONFIG, "rb") as f:
                self.config = f.read()
        with open(CONFIG, "ab") as f:
            # keep any existing config intact, even one without a trailing newline
            if self.config and not self.config.endswith(b"\n"):
                f.write(b"\n")
            f.write(("-Dmaven.repo.local=%s\n-Dmaven.repo.local.tail=%s\n" % (self.overlay, self.m2)).encode())
        log(".mvn/maven.config: overlay repo in front of " + self.m2)
        with open(CONFIG, errors="replace") as f:
            for line in f.read().splitlines():
                log("  " + line)

    def rollback(self):
        shutil.rmtree(self.overlay, ignore_errors=True)
        if self.wrote_pom and os.path.exists("pom.xml"):
            os.remove("pom.xml")  # the hook wrote it (plan_binaries)
        if self.config is None:  # the hook created it
            if os.path.exists(CONFIG):
                os.remove(CONFIG)
        elif self.config is not False:  # restore it byte for byte
            with open(CONFIG, "wb") as f:
                f.write(self.config)


def main(work, overlay):
    return Scan(work, overlay).run()


if __name__ == "__main__":
    repo = os.environ.get("MEND_SCA_REPO_NAME", "")
    scan_dir = os.environ.get("MEND_SCA_SCAN_DIR", "")
    log("repo=%s dir=%s" % (repo, scan_dir))
    if not os.path.isdir(scan_dir):
        sys.exit(0)
    repos = REPOS.split()
    if repos and "*" not in repos and repo not in repos:
        sys.exit(0)  # not one of the repositories in REPOS
    os.chdir(scan_dir)
    overlay = scan_dir + "/.mvn/shaded-overlay-repo"  # excluded from the file scan, deleted with the clone
    work = tempfile.mkdtemp()
    try:
        sys.exit(main(work, overlay))
    finally:
        shutil.rmtree(work, ignore_errors=True)
