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
K = "router.tests.test_docker_key_mount.KeyMountTests."
RS = "docker/run.sh"
G = "router.tests.test_docker.RunShGroupAddTest."
V = "router.tests.test_docker_hop_volume.DeriveTests."
W = "router.tests.test_docker_hop_volume.RunShTests."

M = [
 ("D1 hop.root mounted read-only", DM,
  '    new = [hop_dir(hop.get("root"), "hop.root", "rw"),\n',
  '    new = [hop_dir(hop.get("root"), "hop.root", "ro"),\n',
  [T + "test_hop_root_is_mounted_read_write"]),
 ("D2 registry_dir mounted read-write", DM,
  '           hop_dir(doc["registry_dir"], "registry_dir", "ro"),\n',
  '           hop_dir(doc["registry_dir"], "registry_dir", "rw"),\n',
  [T + "test_registry_dir_is_mounted_read_only"]),
 ("D3 the plugin and D7 directories mounted read-write", DM,
  '    return (hop_file(value, what), "ro", d)\n',
  '    return (hop_file(value, what), "rw", d)\n',
  [T + "test_the_plugin_files_directory_is_mounted_read_only",
   T + "test_the_delivered_domains_files_directory_is_mounted_read_only"]),
 ("D5 hop.root not mounted", DM,
  '    new = [hop_dir(hop.get("root"), "hop.root", "rw"),\n           hop_dir(doc["registry_dir"]',
  '    hop_dir(hop.get("root"), "hop.root", "rw")\n    new = [hop_dir(doc["registry_dir"]',
  [T + "test_hop_root_is_mounted_read_write"]),
 ("D6 registry_dir not mounted", DM,
  '           hop_dir(doc["registry_dir"], "registry_dir", "ro"),\n', '',
  [T + "test_registry_dir_is_mounted_read_only"]),
 ("D7 the plugin directory not mounted", DM,
  '           hop_file_dir(plugin["path"], "transport_plugin.path")]\n',
  '           ]\n',
  [T + "test_the_plugin_files_directory_is_mounted_read_only"]),
 ("D8 the D7 directory not mounted", DM,
  '    if doc.get("delivered_domains_file") is not None:\n        new.append(',
  '    if False:\n        new.append(',
  [T + "test_the_delivered_domains_files_directory_is_mounted_read_only"]),
 ("D9 a file mounted instead of its directory", DM,
  '    return hop_path(os.path.dirname(value), f"{what}\'s directory", where)\n',
  '    return value\n',
  [T + "test_the_plugin_files_directory_is_mounted_read_only"]),
 ("D10 not gated on the hop section", DM,
  'if hop is not None:\n    if not isinstance(hop, dict):\n',
  'hop = hop or {"root": doc.get("state_dir")}\nif hop is not None:\n    if not isinstance(hop, dict):\n',
  [T + "test_without_hop_the_mount_list_is_byte_identical"]),
 ("D11 a relative path accepted", DM,
  '    if not isinstance(value, str) or not os.path.isabs(value):\n        sys.exit(f"{where}: {what} must be an absolute path, got {value!r}")\n    if os.path.normpath',
  '    if not isinstance(value, str):\n        sys.exit(f"{where}: {what} must be an absolute path, got {value!r}")\n    if os.path.normpath',
  [T + "test_a_relative_hop_root_is_refused"]),
 ("D12 normal form unchecked", DM,
  '    if os.path.normpath(value) != value:\n', '    if False:\n',
  [T + "test_a_hop_root_not_in_normal_form_is_refused"]),
 ("D13 a symlinked component accepted", DM,
  '    if on_host and os.path.realpath(value) != value:\n', '    if False:\n',
  [T + "test_a_symlinked_hop_root_is_refused", T + "test_a_symlinked_component_of_registry_dir_is_refused",
   K + "test_a_symlinked_component_is_refused_never_mounted_where_it_points"]),
 ("D14 a symlinked file accepted", DM,
  '    if os.path.islink(value):\n', '    if False:\n',
  [T + "test_a_symlinked_plugin_file_is_refused", T + "test_a_symlinked_delivered_domains_file_is_refused",
   K + "test_a_symlinked_key_file_is_refused"]),
 ("D15 container system trees allowed", DM,
  '    if value in IMAGE_DIRS or any(within(value, t) for t in IMAGE_TREES):\n',
  '    if value in IMAGE_DIRS:\n',
  [T + "test_a_plugin_under_a_container_system_tree_is_refused"]),
 ("D16 container system directories allowed", DM,
  '    if value in IMAGE_DIRS or any(within(value, t) for t in IMAGE_TREES):\n',
  '    if any(within(value, t) for t in IMAGE_TREES):\n',
  [T + "test_a_container_system_directory_itself_is_refused"]),
 ("D17 existing mounts not compared", DM,
  '    others = [(os.path.realpath(p), mode, "an existing mount") for p, mode in roots]\n',
  '    others = []\n',
  [T + "test_hop_root_inside_state_dir_is_refused", T + "test_a_read_only_path_inside_a_read_write_mount_is_refused",
   K + "test_a_key_directory_inside_a_read_write_mount_is_refused",
   K + "test_a_key_directory_containing_a_read_write_mount_is_refused"]),
 ("D26 the config file not compared", DM,
  '    others.append((os.path.realpath(cfg_path), "ro", "the config file"))\n', '',
  [T + "test_a_config_file_inside_hop_root_is_refused"]),
 ("D18 only a read-write NEW path is refused", DM,
  '            if mode in WRITABLE or qmode in WRITABLE:\n', '            if mode in WRITABLE:\n',
  [T + "test_a_read_only_path_inside_a_read_write_mount_is_refused",
   K + "test_a_key_directory_inside_a_read_write_mount_is_refused"]),
 ("D19 existing mounts compared as written, not resolved", DM,
  '    others = [(os.path.realpath(p), mode, "an existing mount") for p, mode in roots]\n',
  '    others = [(p, mode, "an existing mount") for p, mode in roots]\n',
  [T + "test_hop_root_inside_a_symlinked_state_dir_is_refused"]),
 ("D20 nesting checked one way only", DM,
  '            if not (within(p, q) or within(q, p)):\n', '            if not within(p, q):\n',
  [T + "test_a_read_only_path_containing_a_read_write_mount_is_refused",
   K + "test_a_key_directory_containing_a_read_write_mount_is_refused"]),
 ("D21 nesting by string prefix", DM,
  '    return a == b or a.startswith(b.rstrip("/") + "/")\n',
  '    return a.startswith(b.rstrip("/"))\n',
  [T + "test_a_sibling_sharing_a_name_prefix_is_not_nested"]),
 ("D22 a missing hop directory mounted", DM,
  '        if mode not in CONTAINER_ONLY and not os.path.isdir(p):\n            missing.append(f"{what}: {p}")\n        roots.append((p, mode))\n',
  '        roots.append((p, mode))\n',
  [T + "test_a_missing_hop_root_is_refused"]),
 ("D23 a missing plugin file accepted", DM,
  '    if not os.path.isfile(value):\n        missing.append(f"{what}: {value}")\n',
  '',
  [T + "test_a_missing_plugin_file_is_refused", K + "test_a_missing_key_file_is_refused"]),
 ("K1 no key mount with delegation", DM,
  'delegation = doc.get("delegation")\nif delegation is not None:\n',
  'delegation = None\nif delegation is not None:\n',
  [K + "test_delegation_adds_exactly_the_key_directory_read_only",
   K + "test_the_bind_needs_delegation_alone_not_hop"]),
 ("K2 the key directory mounted read-write", DM,
  '    check_nesting([(key_dir, "ro", "the signing key\'s directory")], "key mount")\n',
  '    check_nesting([(key_dir, "rw", "the signing key\'s directory")], "key mount")\n',
  [K + "test_delegation_adds_exactly_the_key_directory_read_only"]),
 ("K3 the key file mounted instead of its directory", DM,
  '    check_nesting([(key_dir, "ro", "the signing key\'s directory")], "key mount")\n',
  '    check_nesting([(key_path, "ro", "the signing key\'s directory")], "key mount")\n',
  [K + "test_the_key_file_itself_is_never_a_bind_line"]),
 ("K5 the key directory's other entries ignored", DM,
  '        if extra:\n            sys.exit(f"key mount: the signing key\'s directory',
  '        if False:\n            sys.exit(f"key mount: the signing key\'s directory',
  [K + "test_the_key_directory_holds_only_the_key"]),
 ("K4 the key mount gated on hop too", DM,
  'delegation = doc.get("delegation")\nif delegation is not None:\n',
  'delegation = doc.get("delegation")\nif delegation is not None and hop is not None:\n',
  [K + "test_the_bind_needs_delegation_alone_not_hop"]),
 ("D24 hop without a registry accepted", DM,
  '    if not doc.get("registry_dir"):\n', '    if False:\n',
  [T + "test_hop_without_a_plugin_or_a_registry_is_refused"]),
 ("R1 the no-hop registry mounted read-write", DM,
  '    check_nesting([(hop_path(doc["registry_dir"], "registry_dir", "registry mount"), "ro",\n',
  '    check_nesting([(hop_path(doc["registry_dir"], "registry_dir", "registry mount"), "rw",\n',
  [T + "test_registry_dir_without_hop_is_mounted_read_only"]),
 ("R2 the no-hop registry not mounted", DM,
  'elif "registry_dir" in doc:\n', 'elif False:\n',
  [T + "test_registry_dir_without_hop_is_mounted_read_only"]),
 ("R3 the no-hop registry spared the path rules", DM,
  '    check_nesting([(hop_path(doc["registry_dir"], "registry_dir", "registry mount"), "ro",\n',
  '    check_nesting([(doc["registry_dir"], "ro",\n',
  [T + "test_registry_dir_without_hop_keeps_the_hop_paths_rules"]),
 ("R4 the no-hop registry spared the nesting check", DM,
  '                    "registry_dir")], "registry mount")\n',
  '                    "registry_dir")], "registry mount") if False else roots.append((doc["registry_dir"], "ro"))\n',
  [T + "test_registry_dir_without_hop_inside_a_read_write_mount_is_refused",
   T + "test_a_missing_registry_dir_without_hop_is_refused"]),
 ("G1 run.sh --group-add ignored", RS,
  '[ -z "$GROUP_ADD" ] || COMMON+=(--group-add "$GROUP_ADD")\n', ':\n',
  [G + "test_the_gid_is_added_once_directly_after_user"]),
 ("G2 run.sh --group-add unvalidated", RS,
  "        ''|0*|*[!0-9]*) echo", "        x__never__) echo",
  [G + "test_a_bad_gid_is_refused_before_docker_runs"]),
 ("G3 run.sh --group-add 0 accepted", RS,
  "        ''|0*|*[!0-9]*) echo", "        ''|*[!0-9]*) echo",
  [G + "test_a_bad_gid_is_refused_before_docker_runs"]),
 ("G4 run.sh --group-add repeat accepted", RS,
  '      [ -z "$GROUP_ADD" ] || { echo "run.sh: --group-add given twice"',
  '      true || { echo "run.sh: --group-add given twice"',
  [G + "test_a_bad_gid_is_refused_before_docker_runs"]),
 ("G5 run.sh --group-add not directly after --user", RS,
  '[ -z "$GROUP_ADD" ] || COMMON+=(--group-add "$GROUP_ADD")\nCOMMON+=(\n  -e "ROUTER_CONFIG=$CONFIG_ABS"\n  -e "ROUTER_INTERVAL=$INTERVAL"\n  "${MOUNTS[@]}"\n)\n', 'COMMON+=(\n  -e "ROUTER_CONFIG=$CONFIG_ABS"\n  -e "ROUTER_INTERVAL=$INTERVAL"\n  "${MOUNTS[@]}"\n)\n[ -z "$GROUP_ADD" ] || COMMON+=(--group-add "$GROUP_ADD")\n',
  [G + "test_the_gid_is_added_once_directly_after_user"]),
 ("G6 run.sh --group-add length unchecked", RS,
  '      [ "${#2}" -le 10 ] ||', '      true ||',
  [G + "test_a_bad_gid_is_refused_before_docker_runs"]),
 ("D25 a shared read-only directory refused", DM,
  '            if mode in WRITABLE or qmode in WRITABLE:\n', '            if True:\n',
  [T + "test_a_shared_read_only_directory_is_mounted_once", T + "test_a_read_only_path_may_nest_in_another_read_only_one",
   V + "test_two_read_only_volumes_may_share_one_path"]),
 # --- --volume (derive-mounts.py) ---
 ("V1 a hop.root volume mounted read-only", DM,
  '        return (as_volume(p, what), VOLUME_RW if mode == "rw" else VOLUME_RO, what)\n',
  '        return (as_volume(p, what), VOLUME_RO, what)\n',
  [V + "test_hop_root_as_a_volume_is_read_write"]),
 ("V2 the plugin and D7 volumes mounted read-write", DM,
  '        return (as_volume(p, d), VOLUME_RO, d)\n', '        return (as_volume(p, d), VOLUME_RW, d)\n',
  [V + "test_the_plugin_and_d7_directories_as_volumes_are_read_only"]),
 ("V3 a registry volume mounted read-write", DM,
  '        return (as_volume(p, what), VOLUME_RW if mode == "rw" else VOLUME_RO, what)\n',
  '        return (as_volume(p, what), VOLUME_RW, what)\n',
  [V + "test_registry_dir_as_a_volume_is_read_only"]),
 ("V4 a volume directory resolved on the host", DM,
  '        p = hop_path(value, what, on_host=False)\n', '        p = hop_path(value, what)\n',
  [V + "test_a_volume_path_is_never_looked_for_on_the_host"]),
 ("V5 a volume path required to exist on the host", DM,
  '        if mode not in CONTAINER_ONLY and not os.path.isdir(p):\n', '        if not os.path.isdir(p):\n',
  [V + "test_a_volume_path_is_never_looked_for_on_the_host"]),
 ("V6 a volume file directory taken as a bind", DM,
  '    if isinstance(value, str) and os.path.isabs(value) and os.path.dirname(value) in VOLUMES:\n',
  '    if False:\n',
  [V + "test_a_volume_path_is_never_looked_for_on_the_host"]),
 ("V7 mount syntax in a volume path accepted", DM,
  '    if any(c in path for c in MOUNT_SYNTAX):\n', '    if False:\n',
  [V + "test_mount_syntax_in_a_volume_path_is_refused"]),
 ("V8 mounts not compared as written", DM,
  '        others += [(p, mode, "an existing mount") for p, mode in roots]\n', '',
  [V + "test_a_volume_is_compared_with_each_mount_as_written"]),
 ("V9 the config file not compared as written", DM,
  '        others.append((os.path.abspath(cfg_path), "ro", "the config file"))\n', '',
  [V + "test_a_config_file_inside_a_volume_as_written_is_refused"]),
 ("V10 a --volume this config does not mount ignored", DM,
  'if unused:\n', 'if False:\n',
  [V + "test_a_path_this_config_does_not_mount_from_its_hop_section_is_refused",
   V + "test_a_named_plugin_or_d7_file_rather_than_its_directory_is_refused"]),
 ("V11 --volume without a hop section accepted", DM,
  'if hop is None and VOLUMES:\n', 'if False:\n',
  [V + "test_volume_needs_a_hop_section"]),
 ("V12 a repeated --volume accepted", DM,
  '    if _rest[1] in VOLUMES:\n', '    if False:\n',
  [V + "test_a_bad_or_repeated_argument_is_refused"]),
 ("V13 a hop.root volume not treated as writable", DM,
  'WRITABLE = ("rw", VOLUME_RW)\n', 'WRITABLE = ("rw",)\n',
  [V + "test_a_volume_hop_root_is_nested_with_no_other_mount"]),
 ("V14 an argument other than --volume accepted", DM,
  '    if _rest[0] != "--volume" or len(_rest) < 2:\n', '    if len(_rest) < 2:\n',
  [V + "test_a_bad_or_repeated_argument_is_refused"]),
 # --- --volume (run.sh) ---
 ("W1 run.sh: every volume read-write", RS,
  '      ro=""; [ "$mode" = volume-rw ] || ro=",readonly"\n', '      ro=""\n',
  [W + "test_each_volume_is_mounted_by_name_with_its_role"]),
 ("W2 run.sh: volume-nocopy dropped", RS,
  'dst=$path$ro,volume-nocopy")', 'dst=$path$ro")',
  [W + "test_each_volume_is_mounted_by_name_with_its_role"]),
 ("W3 run.sh: volume existence unchecked", RS,
  'for i in ${VOL_NAMES[@]+"${!VOL_NAMES[@]}"}; do\n  vn="${VOL_NAMES[$i]}"\n',
  'for i in; do\n  vn="${VOL_NAMES[$i]}"\n',
  [W + "test_a_missing_volume_is_refused_before_docker_run"]),
 ("W4 run.sh: driver and options unchecked", RS,
  '    "$vn local null"|"$vn local {}") ;;\n', '    *) ;;\n',
  [W + "test_a_volume_with_driver_options_or_another_driver_is_refused"]),
 ("W5 run.sh: volume name unvalidated", RS,
  "        ''|[!A-Za-z0-9]*|*[!A-Za-z0-9_.-]*) echo \"run.sh: --volume",
  "        x__never__) echo \"run.sh: --volume",
  [W + "test_a_bad_volume_argument_is_refused_before_any_docker_call"]),
 ("W6 run.sh: a repeated path accepted", RS,
  '        [ "${VOL_PATHS[$i]}" != "$vp" ] || { echo', '        true || { echo',
  [W + "test_a_bad_volume_argument_is_refused_before_any_docker_call"]),
 ("W7 run.sh: a repeated volume accepted", RS,
  '        [ "${VOL_NAMES[$i]}" != "$vn" ] || { echo', '        true || { echo',
  [W + "test_a_bad_volume_argument_is_refused_before_any_docker_call"]),
 ("W8 run.sh: volume name length unchecked", RS,
  '      [ "${#vn}" -le 128 ] ||', '      true ||',
  [W + "test_a_bad_volume_argument_is_refused_before_any_docker_call"]),
 ("W9 run.sh: a volume line not mapped to its volume", RS,
  '    volume-rw|volume-ro)\n', '    volume-never)\n',
  [W + "test_each_volume_is_mounted_by_name_with_its_role"]),
 ("W10 run.sh: volume paths not passed to derive-mounts", RS,
  'for vp in ${VOL_PATHS[@]+"${VOL_PATHS[@]}"}; do DERIVE_ARGS+=(--volume "$vp"); done\n', ':\n',
  [W + "test_each_volume_is_mounted_by_name_with_its_role"]),
 ("W11 run.sh: a relative path accepted", RS,
  '        /*=*) ;;\n', '        *=*) ;;\n',
  [W + "test_a_bad_volume_argument_is_refused_before_any_docker_call"]),
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
