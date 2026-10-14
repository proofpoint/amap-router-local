"""Single-rule mutants for the hop identity mounts in `docker/derive-mounts.py`,
each run against the test that names it (`test_docker_hop_mounts`).

Run from the repository root:

    python3 -B router/tests/mutate_derive_mounts.py

Same discipline as `mutate_repoint.py`: one rule per mutant, bytecode
caching OFF and `__pycache__` cleared before each run, the file restored
after, and a mutant is RED only when unittest reports the named test as a
FAILURE (an ERROR is not red). Not a test module itself. It mutates the
checkout in place: run it only in a private worktree.
"""
import os
import pathlib
import shutil
import subprocess
import sys

T = "router.tests.test_docker_hop_mounts.HopMountsTests."
DM = "docker/derive-mounts.py"

M = [
 ("D1 hop.root mounted read-only", DM,
  '    new = [(hop_path(hop.get("root"), "hop.root"), "rw", "hop.root"),\n',
  '    new = [(hop_path(hop.get("root"), "hop.root"), "ro", "hop.root"),\n',
  [T + "test_hop_root_is_mounted_read_write"]),
 ("D2 registry_dir mounted read-write", DM,
  '           (hop_path(doc["registry_dir"], "registry_dir"), "ro", "registry_dir"),\n',
  '           (hop_path(doc["registry_dir"], "registry_dir"), "rw", "registry_dir"),\n',
  [T + "test_registry_dir_is_mounted_read_only"]),
 ("D3 the plugin directory mounted read-write", DM,
  '           (hop_file(plugin["path"], "transport_plugin.path"), "ro",\n',
  '           (hop_file(plugin["path"], "transport_plugin.path"), "rw",\n',
  [T + "test_the_plugin_files_directory_is_mounted_read_only"]),
 ("D4 the D7 directory mounted read-write", DM,
  '        new.append((hop_file(doc["delivered_domains_file"], "delivered_domains_file"), "ro",\n',
  '        new.append((hop_file(doc["delivered_domains_file"], "delivered_domains_file"), "rw",\n',
  [T + "test_the_delivered_domains_files_directory_is_mounted_read_only"]),
 ("D5 hop.root not mounted", DM,
  '    new = [(hop_path(hop.get("root"), "hop.root"), "rw", "hop.root"),\n           (hop_path(doc["registry_dir"]',
  '    hop_path(hop.get("root"), "hop.root")\n    new = [(hop_path(doc["registry_dir"]',
  [T + "test_hop_root_is_mounted_read_write"]),
 ("D6 registry_dir not mounted", DM,
  '           (hop_path(doc["registry_dir"], "registry_dir"), "ro", "registry_dir"),\n', '',
  [T + "test_registry_dir_is_mounted_read_only"]),
 ("D7 the plugin directory not mounted", DM,
  '           (hop_file(plugin["path"], "transport_plugin.path"), "ro",\n            "transport_plugin.path\'s directory")]\n',
  '           ]\n',
  [T + "test_the_plugin_files_directory_is_mounted_read_only"]),
 ("D8 the D7 directory not mounted", DM,
  '    if doc.get("delivered_domains_file") is not None:\n        new.append(',
  '    if False:\n        new.append(',
  [T + "test_the_delivered_domains_files_directory_is_mounted_read_only"]),
 ("D9 a file mounted instead of its directory", DM,
  '        return hop_path(os.path.dirname(value), f"{what}\'s directory")\n',
  '        return value\n',
  [T + "test_the_plugin_files_directory_is_mounted_read_only"]),
 ("D10 not gated on the hop section", DM,
  'hop = doc.get("hop")\nif hop is not None:\n',
  'hop = doc.get("hop") or {"root": doc.get("state_dir")}\nif hop is not None:\n',
  [T + "test_without_hop_the_mount_list_is_byte_identical"]),
 ("D11 a relative path accepted", DM,
  '    def hop_path(value, what):\n        if not isinstance(value, str) or not os.path.isabs(value):\n',
  '    def hop_path(value, what):\n        if not isinstance(value, str):\n',
  [T + "test_a_relative_hop_root_is_refused"]),
 ("D12 normal form unchecked", DM,
  '        if os.path.normpath(value) != value:\n', '        if False:\n',
  [T + "test_a_hop_root_not_in_normal_form_is_refused"]),
 ("D13 a symlinked component accepted", DM,
  '        if os.path.realpath(value) != value:\n', '        if False:\n',
  [T + "test_a_symlinked_hop_root_is_refused", T + "test_a_symlinked_component_of_registry_dir_is_refused"]),
 ("D14 a symlinked file accepted", DM,
  '        if os.path.islink(value):\n', '        if False:\n',
  [T + "test_a_symlinked_plugin_file_is_refused", T + "test_a_symlinked_delivered_domains_file_is_refused"]),
 ("D15 container system trees allowed", DM,
  '        if value in IMAGE_DIRS or any(within(value, t) for t in IMAGE_TREES):\n',
  '        if value in IMAGE_DIRS:\n',
  [T + "test_a_plugin_under_a_container_system_tree_is_refused"]),
 ("D16 container system directories allowed", DM,
  '        if value in IMAGE_DIRS or any(within(value, t) for t in IMAGE_TREES):\n',
  '        if any(within(value, t) for t in IMAGE_TREES):\n',
  [T + "test_a_container_system_directory_itself_is_refused"]),
 ("D17 existing mounts not compared", DM,
  '    others = [(os.path.realpath(p), mode, "an existing mount") for p, mode in roots]\n',
  '    others = []\n',
  [T + "test_hop_root_inside_state_dir_is_refused", T + "test_a_read_only_path_inside_a_read_write_mount_is_refused"]),
 ("D18 only a read-write NEW path is refused", DM,
  '            if mode == "rw" or qmode == "rw":\n', '            if mode == "rw":\n',
  [T + "test_a_read_only_path_inside_a_read_write_mount_is_refused"]),
 ("D19 existing mounts compared as written, not resolved", DM,
  '    others = [(os.path.realpath(p), mode, "an existing mount") for p, mode in roots]\n',
  '    others = [(p, mode, "an existing mount") for p, mode in roots]\n',
  [T + "test_hop_root_inside_a_symlinked_state_dir_is_refused"]),
 ("D20 nesting checked one way only", DM,
  '            if not (within(p, q) or within(q, p)):\n', '            if not within(p, q):\n',
  [T + "test_a_read_only_path_containing_a_read_write_mount_is_refused"]),
 ("D21 nesting by string prefix", DM,
  '        return a == b or a.startswith(b.rstrip("/") + "/")\n',
  '        return a.startswith(b.rstrip("/"))\n',
  [T + "test_a_sibling_sharing_a_name_prefix_is_not_nested"]),
 ("D22 a missing hop directory mounted", DM,
  '        if not os.path.isdir(p):\n            missing.append(f"{what}: {p}")\n        roots.append((p, mode))\n',
  '        roots.append((p, mode))\n',
  [T + "test_a_missing_hop_root_is_refused"]),
 ("D23 a missing plugin file accepted", DM,
  '        if not os.path.isfile(value):\n            missing.append(f"{what}: {value}")\n',
  '',
  [T + "test_a_missing_plugin_file_is_refused"]),
 ("D24 hop without a registry accepted", DM,
  '    if not doc.get("registry_dir"):\n', '    if False:\n',
  [T + "test_hop_without_a_plugin_or_a_registry_is_refused"]),
 ("D25 a shared read-only directory refused", DM,
  '            if mode == "rw" or qmode == "rw":\n', '            if True:\n',
  [T + "test_a_shared_read_only_directory_is_mounted_once", T + "test_a_read_only_path_may_nest_in_another_read_only_one"]),
]


def _red(r) -> bool:
    """RED only when the named test FAILED (an assertion in it did not
    hold); an ERROR proves the mutant broke something, not that the test
    pins the rule."""
    out = r.stdout + r.stderr
    return (r.returncode != 0 and "\nFAIL: " in "\n" + out
            and "FAILED (failures=" in out)


def _clear() -> None:
    for d in list(pathlib.Path("router").rglob("__pycache__")) + list(pathlib.Path("docker").rglob("__pycache__")):
        shutil.rmtree(d, ignore_errors=True)


def main() -> int:
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    ok = True
    _clear()
    named = sorted({t for *_, tests in M for t in tests})
    clean = subprocess.run([sys.executable, "-B", "-m", "unittest", *named],
                           capture_output=True, text=True)
    if clean.returncode != 0:
        print("the named tests are not green on unmutated code:\n" + clean.stderr[-2000:])
        return 1
    for label, f, old, new, tests in M:
        path = pathlib.Path(f)
        orig = path.read_text()
        if orig.count(old) != 1:
            print(f"{label}: ANCHOR FOUND {orig.count(old)} TIMES")
            ok = False
            continue
        path.write_text(orig.replace(old, new))
        _clear()
        try:
            for t in tests:
                r = subprocess.run([sys.executable, "-B", "-m", "unittest", t],
                                   capture_output=True, text=True)
                red = _red(r)
                ok &= red
                verdict = "RED" if red else ("ERROR only (not RED)" if r.returncode
                                             else "GREEN (survived)")
                print(f"{label:52s} {t.split('.')[-1][:58]}: {verdict}")
        finally:
            path.write_text(orig)
    print(f"{len(M)} mutants: " + ("ALL RED" if ok else "SOME SURVIVED OR MISSING"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
