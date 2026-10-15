#!/usr/bin/env python3
# shaded_deps_hierarchy.py - Mend SCA pre-build hook: reports the libraries a
# Maven dependency bundles ("shades") inside its jar, each under the library
# that bundles it. A shaded jar's published POM doesn't declare them, so the
# hook finds them in the jar (other libraries' pom.properties, or the jar's own
# pom.xml when it configures maven-shade-plugin) and declares each one through
# a byte-identical copy of its published jar, classified by the library that
# declares it; Mend matches the copies by SHA-1. The patched POMs and the
# copies go into an overlay repo in front of the local repo (.mvn/maven.config).
# pom.xml is never changed, and if Maven fails with the patches, everything is
# rolled back. See README.md. Needs python3 (standard library only; tested
# with 3.10) and Maven 3.9+.
#
# The scanner executes this file directly: keep "#!/usr/bin/env python3" as
# the first line, and Unix (LF) line endings.

REPOS = ""                   # repos to run for, space-separated; "" (or "*") = every Maven repo
MVN_LOG_LEVEL = ""           # Maven output: -X = debug, "" = normal, -q = errors only
MAX_ROUNDS = 10              # bounds re-resolution (nested shading)

import collections, os, re, shutil, subprocess, sys, tempfile, traceback, zipfile
import xml.etree.ElementTree as ET

NS = "http://maven.apache.org/POM/4.0.0"
ET.register_namespace("", NS)
ET.register_namespace("xsi", "http://www.w3.org/2001/XMLSchema-instance")
RELOCATED = re.compile(r"^((?:.*/)?(?:shaded|repackaged|relocated)/[^/]+)/")
CLASSIFIER_PREFIX = "shaded-"
DEP_PLUGIN = "org.apache.maven.plugins:maven-dependency-plugin:3.6.0"
CONFIG = os.path.join(".mvn", "maven.config")
TREE_LINE = re.compile(r"((?:[| ]  )*[+\\]- |)(\(?[^\s:]+(?::\S+){3})")  # (prefix, g:a:type:...)


class Rollback(Exception):
    """Undo everything and exit 1, so the scan runs as if this hook weren't there."""


def log(msg):
    print("[shaded-hook] " + msg, flush=True)


def ns_of(root):
    return "{%s}" % NS if root.tag.startswith("{") else ""


def repo_path(repo, g, a, v, ext="pom", classifier=""):
    name = "%s-%s%s.%s" % (a, v, "-" + classifier if classifier else "", ext)
    return os.path.join(repo, *g.split("."), a, v, name)


def classifier_for(owner):
    """The classifier of the copies a library (g:a:v) declares. Maven's conflict
    key includes it, so no other version or copy of the library can drop them."""
    g, a, v = owner.split(":")
    return CLASSIFIER_PREFIX + a + "-" + v


def coords(s):
    """(g, a, classifier, v) of Maven's g:a:type[:classifier]:version[:scope]."""
    p = s.split(":")
    return (p[0], p[1], p[3], p[4]) if len(p) >= 6 else (p[0], p[1], "", p[3])


def is_runtime(dep, ns):
    """A <dependency> passed on to consumers."""
    get = lambda tag: dep.findtext(ns + tag, "").strip()
    return get("scope") in ("", "compile", "runtime") and get("optional") != "true"


class Pom:
    """A POM plus the properties and managed versions of its parent chain."""

    def __init__(self, data, g, v, repos):
        self.root = ET.fromstring(data)
        self.props, self.managed = {}, {}
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
            node = ET.parse(path).getroot()
            chain.append(node)
        for node in reversed(chain):  # child overrides parent
            for p in node.findall(ns_of(node) + "properties/*"):
                self.props[p.tag.rsplit("}", 1)[-1]] = (p.text or "").strip()
        self.props.update({k: g for k in ("groupId", "project.groupId", "pom.groupId")})
        self.props.update({k: v for k in ("version", "project.version", "pom.version")})
        for node in reversed(chain):
            ns = ns_of(node)
            for d in node.findall("%sdependencyManagement/%sdependencies/%sdependency" % (ns, ns, ns)):
                ga = self.expand(d.findtext(ns + "groupId")) + ":" + self.expand(d.findtext(ns + "artifactId"))
                self.managed[ga] = self.expand(d.findtext(ns + "version"))

    def expand(self, s):
        s = (s or "").strip()
        for _ in range(10):
            new = re.sub(r"\$\{([^}]+)\}", lambda m: self.props.get(m.group(1), m.group(0)), s)
            if new == s:
                break
            s = new
        return s

    def runtime_deps(self):
        """{g:a: version} of the dependencies passed on to consumers, in POM order."""
        ns = ns_of(self.root)
        found = {}
        for d in self.root.findall("%sdependencies/%sdependency" % (ns, ns)):
            if is_runtime(d, ns):
                ga = self.expand(d.findtext(ns + "groupId")) + ":" + self.expand(d.findtext(ns + "artifactId"))
                found[ga] = self.expand(d.findtext(ns + "version")) or self.managed.get(ga, "")
        return found


def analyze(jar, g, a, v, pom_path, repos):
    """({g:a: version} of the libraries a jar bundles, {g:a: [g:a it depends on]}
    among them from their embedded POMs, [g:a] the jar's own original pom.xml
    declares)."""
    name, own = os.path.basename(jar), g + ":" + a
    bundled, own_deps = {}, []
    with zipfile.ZipFile(jar) as z:
        names = set(z.namelist())
        # 1. other libraries' pom.properties
        for entry in sorted(names):
            if not re.fullmatch(r"META-INF/maven/[^/]+/[^/]+/pom\.properties", entry):
                continue
            lines = z.read(entry).decode("utf-8", "replace").splitlines()
            props = dict(l.split("=", 1) for l in lines if "=" in l and not l.startswith("#"))
            lg, la, lv = (props.get(k, "").strip() for k in ("groupId", "artifactId", "version"))
            if lg and la and lv and lg + ":" + la != own:
                bundled[lg + ":" + la] = lv
                log("Shaded in %s: %s:%s:%s" % (name, lg, la, lv))
        # 2. the jar's own pom.xml: runtime deps the published POM dropped
        own_pom = "META-INF/maven/%s/%s/pom.xml" % (g, a)
        if own_pom in names:
            raw = z.read(own_pom)
            declared = Pom(raw, g, v, repos).runtime_deps()
            own_deps = list(declared)
            if b"maven-shade-plugin" in raw:
                with open(pom_path, "rb") as f:
                    kept = Pom(f.read(), g, v, repos).runtime_deps()
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
            deps = Pom(z.read(embedded), lg, ver, repos).runtime_deps() if embedded in names else {}
            graph[ga] = [d for d in deps if "${" not in d]
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


def new_owner(state, gav, cls):
    """The POM identity (g:a:version) of the copy of gav with classifier cls,
    which has children: the published version for the first such copy, else a
    version of its own, "<version>-<cls>" (copies of a version share its POM)."""
    claimant = state["claimed"].setdefault(gav, cls)
    owner = gav if claimant == cls else gav + "-" + cls
    if owner not in state["patches"]:
        state["patches"][owner] = {"real": gav, "children": {}, "strip": True}
        if owner != gav:
            log("Own version: %s:%s has children, and %s already uses the published POM; declared as version %s"
                % (gav, cls, "copy " + claimant if claimant else "the project", owner.split(":")[2]))
    return owner


def plan_bundle(state, jar_owner, jar_name, bundled, graph, own_deps):
    """Record the copies one bundling jar declares, as a tree: the jar declares
    what its own pom.xml declares, each bundled library its own dependencies,
    both only among the libraries in the jar; a library nobody declares is
    declared by the jar. A library with two parents gets a copy, with its own
    children, under each."""
    kids_of = {ga: [d for d in graph.get(ga, []) if d in bundled and d != ga] for ga in bundled}
    top = [ga for ga in own_deps if ga in bundled]
    declared = set(top) | {ga for kids in kids_of.values() for ga in kids}
    top += sorted(ga for ga in bundled if ga not in declared)
    log("Edges in %s: %s" % (jar_name, "; ".join(
        "%s -> %s" % (owner.split(":")[1], ", ".join(k.split(":")[1] for k in kids))
        for owner, kids in [(jar_owner, top)] + list(kids_of.items()) if kids)))
    state["bundled_all"] |= set(bundled)

    def declare(owner, kids, path):
        cls = classifier_for(owner)
        for ga in kids:
            v = bundled[ga]
            child = state["patches"][owner]["children"].setdefault(ga, {"v": v, "as": v, "node": None})
            sub = [k for k in kids_of[ga] if k not in path]  # a dependency cycle stops here
            if sub and child["node"] is None:
                child["node"] = new_owner(state, ga + ":" + v, cls)
                child["as"] = child["node"].split(":")[2]
                declare(child["node"], sub, path | {ga})
            state["copies"].setdefault((ga, v, cls, child["as"]), None)
    declare(jar_owner, top, {jar_owner.rsplit(":", 1)[0]})


def node_owner(state, overlay, gav, cls):
    """The POM identity of a resolved artifact found to bundle libraries: its
    own for the project's artifacts and for copies at a version of their own;
    for a copy at the published version, see new_owner - if that is a version
    of its own, the library declaring the copy now declares that version."""
    if state["patches"].get(gav, {}).get("real", gav) != gav:
        return gav
    g, a, v = gav.split(":")
    parent = next((o for o, p in state["patches"].items() if cls and classifier_for(o) == cls
                   and p["children"].get(g + ":" + a, {}).get("as") == v), None)
    if parent is None:  # one of the project's own artifacts
        state["patches"].setdefault(gav, {"real": gav, "children": {}, "strip": False})
        return gav
    child = state["patches"][parent]["children"][g + ":" + a]
    child["node"] = new_owner(state, gav, cls)
    if child["node"] != gav:
        child["as"] = child["node"].split(":")[2]
        if state["copies"].pop((g + ":" + a, v, cls, v), None):  # the copy at the published version
            os.remove(repo_path(overlay, g, a, v, "jar", cls))
        state["copies"][(g + ":" + a, v, cls, child["as"])] = None
    return child["node"]


def drop_node(state, overlay, owner):
    """Forget a copy's POM and, recursively, its children's copies."""
    patch = state["patches"].pop(owner, None) or {"children": {}}
    cls = classifier_for(owner)
    for ga, child in patch["children"].items():
        if state["copies"].pop((ga, child["v"], cls, child["as"]), None):
            os.remove(repo_path(overlay, *ga.split(":"), child["as"], "jar", cls))
        if child["node"]:
            drop_node(state, overlay, child["node"])


def find_jar(state, overlay, ga, v):
    g, a = ga.split(":")
    return next((p for p in (repo_path(r, g, a, v, "jar") for r in (state["m2"], overlay))
                 if os.path.exists(p)), None)


def original_pom(state, work, overlay, g, a, v):
    """The published POM of g:a:v, kept in WORK/orig because the overlay copy
    may be replaced by a patched one; None if it isn't available locally."""
    saved = os.path.join(work, "orig", "%s_%s_%s.pom" % (g, a, v))
    if os.path.exists(saved):
        return saved
    for p in (repo_path(state["m2"], g, a, v), repo_path(overlay, g, a, v)):
        if os.path.exists(p) and p not in state["written"]:
            os.makedirs(os.path.dirname(saved), exist_ok=True)
            shutil.copyfile(p, saved)
            return saved
    return None


def needed_downloads(state, work, overlay):
    """Published jars needed for copies and POMs needed for patches, not yet fetched."""
    jars = {ga + ":" + v for (ga, v, _, _), done in state["copies"].items()
            if done is None and not find_jar(state, overlay, ga, v)}
    poms = {p["real"] + ":pom" for p in state["patches"].values()
            if p["real"] not in jars and original_pom(state, work, overlay, *p["real"].split(":")) is None}
    need = sorted((jars | poms) - state["fetched"])
    state["fetched"] |= set(need)
    return need


def write_pom(state, work, overlay, owner, patch):
    """The published POM of owner, with its runtime dependencies removed when
    it is a copy and its bundled children declared as copies (those without
    children of their own without transitive dependencies). A copy at a
    version of its own gets it at that version."""
    g, a, ver = owner.split(":")
    orig = original_pom(state, work, overlay, *patch["real"].split(":"))
    if orig is None:
        if patch["children"] and owner not in state["warned"]:
            state["warned"].add(owner)
            log("WARNING: couldn't get the published POM of %s; its bundled dependencies are not reported" % owner)
        return
    tree = ET.parse(orig)
    root = tree.getroot()
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
    cls = classifier_for(owner)
    for ga, child in patch["children"].items():
        dep = ET.SubElement(deps, ns + "dependency")
        cg, ca = ga.split(":")
        for tag, val in (("groupId", cg), ("artifactId", ca), ("version", child["as"]), ("classifier", cls)):
            ET.SubElement(dep, ns + tag).text = val
        excls = ET.SubElement(dep, ns + "exclusions")
        for x in sorted(state["exclusions"]) if child["node"] else ["*:*"]:
            excl = ET.SubElement(excls, ns + "exclusion")
            xg, xa = x.split(":")
            ET.SubElement(excl, ns + "groupId").text = xg
            ET.SubElement(excl, ns + "artifactId").text = xa
        if not len(excls):
            dep.remove(excls)
    out = repo_path(overlay, g, a, ver)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    tree.write(out, xml_declaration=True, encoding="UTF-8")
    state["written"][out] = None if own_version else orig  # None: never copied into the local repo
    summary = (tuple((ga, c["as"], c["node"]) for ga, c in patch["children"].items()),
               removed, tuple(sorted(state["exclusions"])))
    if state["logged"].get(owner) != summary:
        state["logged"][owner] = summary
        log("Patched POM: %s declares %s%s%s" % (
            os.path.relpath(out, overlay),
            ", ".join("%s:%s:%s" % (ga, c["as"], cls) for ga, c in patch["children"].items()) or "nothing",
            "; removed its %d runtime dependencies" % removed if removed else "",
            " (the published %s POM, at this copy's own version)" % patch["real"] if own_version else ""))


def materialize(state, work, overlay):
    """Create the copies whose published jar is available, drop the edges to
    those that aren't, and write every patched POM into the overlay."""
    for key, done in list(state["copies"].items()):
        if key not in state["copies"] or done is not None:
            continue  # dropped below, or already done
        ga, v, cls, ver = key
        jar = find_jar(state, overlay, ga, v)
        if jar is None:
            state["copies"][key] = False
            for owner, patch in list(state["patches"].items()):
                child = patch["children"].get(ga) if classifier_for(owner) == cls else None
                if child and child["as"] == ver:
                    del patch["children"][ga]
                    if child["node"]:
                        drop_node(state, overlay, child["node"])
                    log("WARNING: couldn't fetch the published %s:%s jar; it is not reported under %s"
                        % (ga, v, owner))
            continue
        g, a = ga.split(":")
        copy = repo_path(overlay, g, a, ver, "jar", cls)
        os.makedirs(os.path.dirname(copy), exist_ok=True)
        shutil.copyfile(jar, copy)
        state["copies"][key] = True
        log("Copy: %s:%s:%s (byte-identical to the published %s jar)" % (ga, ver, cls, v))
    for owner, patch in state["patches"].items():
        write_pom(state, work, overlay, owner, patch)


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


def read_tree(path):
    """[(node, its parent node or None)] in tree order, each node (g, a,
    classifier, v), from the tree in PATH. Nodes Maven omitted (in
    parentheses, with -Dverbose) are left out: the agent doesn't send them."""
    tree, stack = [], []
    for line in tree_lines(path):
        prefix, node = TREE_LINE.match(line).groups()
        del stack[len(prefix) // 3:]
        stack.append(None if node.startswith("(") else coords(node))
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


def verify(state, arts, tree, last):
    """Check that every declared copy resolved under the library that declares
    it, and that nothing outside the jars came in with them. Returns True if
    the POMs need rewriting."""
    under = {(p[0] + ":" + p[1] + ":" + p[3], g + ":" + a, v, cls) for (g, a, cls, v), p in tree if p}
    problems = 0
    for owner, patch in state["patches"].items():
        for ga, child in patch["children"].items():
            if (owner, ga, child["as"], classifier_for(owner)) in under:
                continue
            problems += 1
            if (owner, ga) not in state["warned"]:
                state["warned"].add((owner, ga))
                log("WARNING: %s declares %s:%s:%s but Maven doesn't resolve it there"
                    % (owner, ga, child["as"], classifier_for(owner)))
    plain = {g + ":" + a for g, a, cls, _, _ in arts if not cls}
    extras = sorted(plain - state["baseline"] - state["bundled_all"] - state["exclusions"])
    state["problems"] = problems + len(extras)
    if not extras:
        return False
    log(("WARNING: resolved but not in any shaded jar: %s" if last else
         "Excluding libraries the shaded jars don't contain: %s") % ", ".join(extras))
    if last:
        return False
    state["exclusions"] |= set(extras)
    return True


def run_round(state, work, overlay, n, last):
    """Check the copies planned so far against Maven's output in WORK, then look
    inside every jar not seen before, copies too, top-down (so the copy nearest
    the project keeps the published version), and plan the copies each bundling
    jar declares. Returns True if another round is needed."""
    arts = resolved_artifacts(os.path.join(work, "resolved.txt"))
    if n == 1:
        plain = [(g, a, v) for g, a, cls, v, _ in arts if not cls]
        state["baseline"] = {g + ":" + a for g, a, _ in plain}
        state["claimed"] = {"%s:%s:%s" % gav: "" for gav in plain}  # the project uses these POMs
        state["m2"] = local_repo(arts)
    tree = read_tree(os.path.join(work, "resolved.txt"))
    changed = verify(state, arts, tree, n == last) if state["patches"] else False  # none in round 1
    order = {node: i for i, (node, _) in enumerate(tree)}
    arts.sort(key=lambda x: order.get(x[:4], len(order)))

    repos = [state["m2"], overlay]
    for g, a, cls, v, jar in arts:
        gav = "%s:%s:%s" % (g, a, v)
        if (gav, cls) in state["processed"] or not jar.endswith(".jar") or not os.path.exists(jar):
            continue
        state["processed"].add((gav, cls))
        real = state["patches"].get(gav, {}).get("real", gav)  # a copy's published version
        if real not in state["analysis"]:  # copies are byte-identical: look inside once
            pom = original_pom(state, work, overlay, *real.split(":"))
            state["analysis"][real] = analyze(jar, *real.split(":"), pom, repos) if pom else ({}, {}, [])
        bundled, graph, own_deps = state["analysis"][real]
        if not bundled:
            continue
        if n == last:
            log("WARNING: %s - nested deeper than MAX_ROUNDS; not reported" % os.path.basename(jar))
            continue
        owner = node_owner(state, overlay, gav, cls)
        if owner in state["planned"]:
            continue
        state["planned"].add(owner)
        plan_bundle(state, owner, os.path.basename(jar), bundled, graph, own_deps)
        changed = True
    return changed


def promote(state, overlay):
    """Copy files Maven downloaded into OVERLAY, and the copies, into the real
    local repo (never overwriting; original POMs in place of patched ones)."""
    copied = 0
    for dirpath, _, files in os.walk(overlay):
        for name in files:
            if name.endswith(".lastUpdated") or name == "resolver-status.properties":
                continue
            src = os.path.join(dirpath, name)
            dst = os.path.join(state["m2"], os.path.relpath(src, overlay))
            if os.path.exists(dst) or state["written"].get(src, src) is None:
                continue
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(state["written"].get(src, src), dst + ".part")
            os.replace(dst + ".part", dst)
            copied += 1
    if copied:
        log("Copied %d file(s) into %s, where the scanner fingerprints jars" % (copied, state["m2"]))


def mvn_run(*args, stdin=None):
    """Print the full command line, then run it; True if Maven succeeded."""
    log("$ mvn -B %s %s" % (MVN_LOG_LEVEL, " ".join(args)))
    return subprocess.run(["mvn", "-B"] + MVN_LOG_LEVEL.split() + list(args), stdin=stdin).returncode == 0


def resolve(work, n):
    """Every resolved artifact with its file path, across all modules; from
    round 2 on also the tree as the scanner's agent gets it (-Dverbose, text),
    to check each copy sits under its parent. One Maven run, since starting
    Maven is most of its cost: both goals append to the same file."""
    out = os.path.join(work, "resolved.txt")
    if os.path.exists(out):
        os.remove(out)
    tree = [DEP_PLUGIN + ":tree", "-Dverbose", "-DoutputType=text", "-T1"] if n > 1 else []
    return mvn_run(DEP_PLUGIN + ":list", *tree, "-DoutputAbsoluteArtifactFilename=true",
                   "-DoutputFile=" + out, "-DappendOutput=true")


def print_prefixed(path):
    with open(path, errors="replace") as f:
        for line in f.read().splitlines():
            log("  " + line)


def add_overlay_config(state, overlay):
    """Append the overlay settings to .mvn/maven.config, so the scanner's own
    Maven runs see the patched POMs; state["config"] keeps the original."""
    os.makedirs(".mvn", exist_ok=True)
    state["config"] = None  # kept before appending, so a partial append is rolled back too
    if os.path.exists(CONFIG):
        with open(CONFIG, "rb") as f:
            state["config"] = f.read()
    with open(CONFIG, "ab") as f:
        # keep any existing config intact, even one without a trailing newline
        if state["config"] and not state["config"].endswith(b"\n"):
            f.write(b"\n")
        f.write(("-Dmaven.repo.local=%s\n-Dmaven.repo.local.tail=%s\n" % (overlay, state["m2"])).encode())
    log(".mvn/maven.config: overlay repo in front of " + state["m2"])
    print_prefixed(CONFIG)


def rollback(state, overlay):
    shutil.rmtree(overlay, ignore_errors=True)
    if state["config"] is None:  # the hook created it
        if os.path.exists(CONFIG):
            os.remove(CONFIG)
    elif state["config"] is not False:  # restore it byte for byte
        with open(CONFIG, "wb") as f:
            f.write(state["config"])


def main(work, overlay):
    state = {"baseline": set(), "m2": "", "processed": set(), "bundled_all": set(),
             "patches": {}, "copies": {}, "claimed": {}, "analysis": {}, "planned": set(),
             "exclusions": set(), "fetched": set(), "written": {}, "logged": {}, "warned": set(),
             "problems": 0, "config": False}  # config: False = untouched, None = created by the hook
    try:
        for n in range(1, MAX_ROUNDS + 1):
            if not resolve(work, n):
                if n == 1:
                    return 1
                raise Rollback("Maven failed with the patched POMs (round %d)" % n)
            if not run_round(state, work, overlay, n, MAX_ROUNDS):
                break
            if n == 1:
                if not state["m2"]:
                    raise Rollback("couldn't determine the local Maven repository")
                add_overlay_config(state, overlay)
            # published jars for the copies and POMs to patch, fetched into the real local repo
            for artifact in needed_downloads(state, work, overlay):
                if not mvn_run(DEP_PLUGIN + ":get", "-Dartifact=" + artifact, "-Dtransitive=false",
                               "-Dmaven.repo.local=" + state["m2"], stdin=subprocess.DEVNULL):
                    log("WARNING: couldn't fetch " + artifact)
            materialize(state, work, overlay)
    except Exception as e:
        if not isinstance(e, Rollback):
            traceback.print_exc()
            e = "helper failed (round %d)" % n
        rollback(state, overlay)
        log("WARNING: %s; removing the overlay - shaded libraries won't be reported" % e)
        return 1
    if not state["written"] and not any(state["copies"].values()):
        if state["config"] is not False:
            rollback(state, overlay)  # nothing could be reported: leave the project as it was
            log("No bundled library could be reported; .mvn/maven.config restored")
        return 0  # nothing bundled anywhere
    if not state["problems"]:
        edges = sum(len(p["children"]) for p in state["patches"].values())
        log("Verified: all %d bundled dependencies resolve, each as its own copy under the library "
            "that declares it (%d copies)" % (edges, sum(1 for done in state["copies"].values() if done)))

    # the scanner fingerprints jars only in the real local repo
    try:
        promote(state, overlay)
    except Exception:
        traceback.print_exc()
        log("WARNING: couldn't copy downloads into the local repo; they'll be reported without a SHA-1")

    # final hierarchy: the last round's tree, the agent's own (promote only
    # adds files behind the overlay, so it can't change it)
    log("Dependency tree:")
    for line in tree_lines(os.path.join(work, "resolved.txt")):
        log("  " + line)
    return 0


if __name__ == "__main__":
    repo = os.environ.get("MEND_SCA_REPO_NAME", "")
    scan_dir = os.environ.get("MEND_SCA_SCAN_DIR", "")
    log("repo=%s dir=%s" % (repo, scan_dir))
    if not os.path.isfile(os.path.join(scan_dir, "pom.xml")):
        sys.exit(0)  # Maven projects only
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
