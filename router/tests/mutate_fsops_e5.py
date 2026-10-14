"""Single-rule mutants for contract amendment E5 in `router/fsops.py` and
`router/transport.py` (`router/tests/test_fsops_e5.py`,
`router/tests/test_transport.py`), each run against the test that names it.

Run from the repository root:

    python3 -B router/tests/mutate_fsops_e5.py

Same discipline as `mutate_reuse.py`: one rule per mutant, bytecode caching
OFF and `__pycache__` cleared before each run, the file restored after;
every named test must pass unmutated first, and a mutant is RED only when
unittest reports a FAILURE of the named test (an ERROR is printed and is
not red). Exit 0 only when every mutant turns every named test red. Not a
test module itself (its name keeps it out of discovery).
"""
import os
import pathlib
import shutil
import subprocess
import sys

E = "router.tests.test_fsops_e5."
F = "router/fsops.py"

M = [
 # -- construction and the private stage ---------------------------------
 ('P1 roots need not be disjoint', F,
  '        _check_disjoint(([self._hop_root] if self._hop_root is not None else [])\n'
  '                        + list(self._private_roots))\n', '',
  [E + 'PrivateRefusalTests.test_roots_that_are_not_disjoint_are_refused_at_construction']),
 ('P2 any private directory may hold a stage', F,
  '        if root.kind != PRIVATE or root.rel != ():\n',
  '        if root.kind != PRIVATE:\n',
  [E + 'PrivateRefusalTests.test_only_the_private_root_itself']),
 ('P3 the private stage mode is not checked', F,
  '            if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:\n'
  '                raise BindingError(\n                    f"private stage',
  '            if st.st_uid != os.geteuid():\n'
  '                raise BindingError(\n                    f"private stage',
  [E + 'PrivateRefusalTests.test_a_wrong_mode_stage_is_refused_never_repaired']),
 ('P3b the private stage owner is not checked', F,
  '            if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:\n'
  '                raise BindingError(\n                    f"private stage',
  '            if stat.S_IMODE(st.st_mode) != 0o700:\n'
  '                raise BindingError(\n                    f"private stage',
  [E + 'PrivateRefusalTests.test_a_stage_of_another_owner_is_refused']),
 ('P4 the private root is fsynced only on creation', F,
  '            os.fsync(root_fd)\n            self._register(fd, PRIVATE, root.tree, (".stage",))\n',
  '            if created:\n                os.fsync(root_fd)\n'
  '            self._register(fd, PRIVATE, root.tree, (".stage",))\n',
  [E + 'PrivateRootBarrierTests.test_fsynced_on_creation_and_when_found']),
 ('P5 a private root has no stage', F,
  '        if self.kind in (INTAKE, PRIVATE):\n            return self.rel == (".stage",)\n',
  '        if self.kind == INTAKE:\n            return self.rel == (".stage",)\n',
  [E + 'PrivateStageTests.test_commit_into_the_private_root_and_a_per_item_directory']),
 ('P6 NOT_YET on a private binding', F,
  '        return self.kind in (GENERATION, INTAKE, DISPOSED)\n',
  '        return self.kind in (GENERATION, INTAKE, DISPOSED, PRIVATE)\n',
  [E + 'PrivateStageTests.test_an_interrupted_private_commit_raises_on_read_and_recovers']),
 ('P7 the private stage may be a destination', F,
  '    if b.kind in (INTAKE, PRIVATE):\n        return b.rel[:1] == (".stage",)\n',
  '    if b.kind == INTAKE:\n        return b.rel[:1] == (".stage",)\n',
  [E + 'PrivateStageTests.test_the_stage_is_never_a_destination']),
 # -- the refusal vocabulary ---------------------------------------------
 ('V1 ELOOP and ENXIO are not mapped', F,
  '_KIND_ERRNOS = frozenset({errno.ELOOP, errno.ENXIO})\n', '_KIND_ERRNOS = frozenset()\n',
  [E + 'RefusalVocabularyTests.test_a_symlink_is_not_regular_with_eloop_as_the_cause',
   E + 'RefusalVocabularyTests.test_the_kind_changed_between_the_stat_and_the_open']),
 ('V2 ENXIO is not mapped', F,
  '_KIND_ERRNOS = frozenset({errno.ELOOP, errno.ENXIO})\n',
  '_KIND_ERRNOS = frozenset({errno.ELOOP})\n',
  [E + 'RefusalVocabularyTests.test_a_socket_is_not_regular_with_enxio_as_the_cause']),
 ('V3 every OSError becomes UnsafeRead', F,
  '            if e.errno in _KIND_ERRNOS:\n'
  '                raise UnsafeRead("not_regular", f"{name!r}: {os.strerror(e.errno)}") from e\n'
  '            raise\n',
  '            raise UnsafeRead("not_regular", f"{name!r}: {os.strerror(e.errno)}") from e\n',
  [E + 'RefusalVocabularyTests.test_any_other_error_propagates_as_itself']),
 ('V4 a missing name becomes UnsafeRead', F,
  '        except FileNotFoundError:\n            raise\n        except OSError as e:\n'
  '            if e.errno in _KIND_ERRNOS:\n                raise UnsafeRead(',
  '        except OSError as e:\n'
  '            if e.errno in _KIND_ERRNOS | {errno.ENOENT}:\n                raise UnsafeRead(',
  [E + 'RefusalVocabularyTests.test_a_missing_name_is_a_raw_file_not_found']),
 ('V5 a link count refusal carries the wrong reason', F,
  '                raise UnsafeRead("link_count", f"{name!r} has link count {st.st_nlink}")\n',
  '                raise UnsafeRead("too_large", f"{name!r} has link count {st.st_nlink}")\n',
  [E + 'RefusalVocabularyTests.test_link_counts',
   E + 'RefusalVocabularyTests.test_link_count_zero_on_a_generation_tree']),
 ('V6 no UnsafeRead attribute on the port', F,
  '    NOT_YET = NOT_YET\n    UnsafeRead = UnsafeRead\n', '    NOT_YET = NOT_YET\n',
  [E + 'RefusalVocabularyTests.test_the_attribute_is_the_class']),
 ('V7 any reason string is accepted', F,
  '        if reason not in UNSAFE_READ_REASONS:\n'
  '            raise ValueError(f"unknown UnsafeRead reason {reason!r}")\n', '',
  [E + 'RefusalVocabularyTests.test_an_unknown_reason_cannot_be_constructed']),
 # -- dependencies --------------------------------------------------------
 ('D1 no entry check', F,
  '        self._check_deps(deps)\n        if self._exists(dfd, name):\n',
  '        if self._exists(dfd, name):\n',
  [E + 'DependencyTests.test_the_dir_swapped_before_the_sentinel_is_refused_before_the_link']),
 ('D2 no check after the link', F,
  '        self._check_deps(deps)     # after the link, before the barrier\n', '',
  [E + 'DependencyTests.test_a_swap_between_the_entry_check_and_the_link_is_caught_after_it']),
 ('D3 no check after the exists_same compare', F,
  '                same = self._read_all(fd, len(data)) == data\n'
  '                self._check_deps(deps)     # after the compare, before the barrier\n'
  '                if not same:\n                    return self._different(dfd, name, "different bytes", fd)\n',
  '                same = self._read_all(fd, len(data)) == data\n'
  '                if not same:\n                    return self._different(dfd, name, "different bytes", fd)\n',
  [E + 'DependencyTests.test_the_post_compare_check_on_exists_same']),
 ('D4 no check after the F1 recovery compare', F,
  '                same = self._read_all(fd, len(data)) == data\n'
  '                self._check_deps(deps)     # after the compare, before the barrier\n'
  '                if not same:\n                    return self._different(dfd, name, "interrupted',
  '                same = self._read_all(fd, len(data)) == data\n'
  '                if not same:\n                    return self._different(dfd, name, "interrupted',
  [E + 'DependencyTests.test_the_post_compare_check_on_f1_recovery']),
 ('D4b exists_different does not observe the deps again', F,
  '        evidence."""\n        self._check_deps(deps)\n        if fd is not None:\n',
  '        evidence."""\n        if fd is not None:\n',
  [E + 'DependencyTests.test_the_post_check_on_an_exists_different_fast_path']),
 ('D4c a dependency in another tree is accepted', F,
  '            if d.kind != dest.kind or d.tree != dest.tree:\n'
  '                raise BindingError(f"dependency {i} ({dep_name!r}) is in another tree")\n', '',
  [E + 'DependencyTests.test_dependency_scope_is_the_destinations_tree']),
 ('D4d a dependency inside a stage is accepted', F,
  '            if _inside_stage(d):\n'
  '                raise BindingError(f"dependency {i} ({dep_name!r}) is inside a stage directory")\n', '',
  [E + 'DependencyTests.test_dependency_scope_is_the_destinations_tree']),
 ('D3b the exists_same post-compare check is past the different-bytes return', F,
  '                same = self._read_all(fd, len(data)) == data\n'
  '                self._check_deps(deps)     # after the compare, before the barrier\n'
  '                if not same:\n                    return self._different(dfd, name, "different bytes", fd)\n',
  '                same = self._read_all(fd, len(data)) == data\n'
  '                if not same:\n                    return self._different(dfd, name, "different bytes", fd)\n'
  '                self._check_deps(deps)     # after the compare, before the barrier\n',
  [E + 'DependencyTests.test_the_post_compare_check_precedes_exists_different']),
 ('D4e the recovery post-compare check is past the different-bytes return', F,
  '                self._check_deps(deps)     # after the compare, before the barrier\n'
  '                if not same:\n                    return self._different(dfd, name, "interrupted commit with different bytes",\n'
  '                                           fd)\n',
  '                if not same:\n                    return self._different(dfd, name, "interrupted commit with different bytes",\n'
  '                                           fd)\n'
  '                self._check_deps(deps)     # after the compare, before the barrier\n',
  [E + 'DependencyTests.test_the_post_compare_check_precedes_exists_different_in_recovery']),
 ('D12 any cause string is accepted', F,
  '        if cause not in DEPENDENCY_CAUSES:\n'
  '            raise ValueError(f"unknown dependency anomaly cause {cause!r}")\n', '',
  [E + 'DependencyTests.test_an_unknown_cause_cannot_be_constructed']),
 ('D5 the binding guard trusts the pinned descriptor', F,
  '        here = self._canonical_dir(b)\n', '        here = self._live_fd(b)\n',
  [E + 'DependencyTests.test_the_dir_swapped_before_the_sentinel_is_refused_before_the_link',
   E + 'DependencyTests.test_a_dep_in_another_directory_whose_directory_moved']),
 ('D5b the walk up does not check the tree root', F,
  '                    if (st.st_dev, st.st_ino) != b.tree:\n',
  '                    if False:\n',
  [E + 'DependencyTests.test_a_dep_directory_moved_into_another_tree_at_the_same_path']),
 ('D5c every walk error is a move', F,
  '                    if e.errno in _WALK_MOVED:\n', '                    if True:\n',
  [E + 'DependencyTests.test_walk_errors_that_say_moved_and_those_that_say_nothing']),
 ('D5d a move on the walk propagates as a fault', F,
  '                    if e.errno in _WALK_MOVED:\n', '                    if False:\n',
  [E + 'DependencyTests.test_walk_errors_that_say_moved_and_those_that_say_nothing']),
 ('D1b no entry check when the final exists', F,
  '        self._check_deps(deps)\n        if self._exists(dfd, name):\n'
  '            return self._on_exists(sfd, dfd, name, sname, data, mode, deps)\n',
  '        if self._exists(dfd, name):\n'
  '            return self._on_exists(sfd, dfd, name, sname, data, mode, deps)\n'
  '        self._check_deps(deps)\n',
  [E + 'DependencyTests.test_the_entry_check_comes_before_any_recovery_compare']),
 ('D6 a dependency link count is not checked', F,
  '                if st.st_nlink != 1:\n'
  '                    raise DependencyAnomaly("link_count", i, name, f"link count {st.st_nlink}")\n', '',
  [E + 'DependencyTests.test_link_count_two_or_a_hardlink_is_an_anomaly_never_a_skip']),
 ('D7 the digest is not checked', F,
  '        if hashlib.sha256(got).hexdigest() != digest:\n', '        if False:\n',
  [E + 'DependencyTests.test_wrong_digest_size_missing']),
 ('D8 the size is not checked', F,
  '        if len(got) != size:\n', '        if False:\n',
  [E + 'DependencyTests.test_wrong_digest_size_missing']),
 ('D9 the dependency read is unbounded', F,
  '                got = self._read_all(fd, size)\n', '                got = self._read_all(fd, st.st_size)\n',
  [E + 'DependencyTests.test_an_oversized_planted_dep_is_read_bounded']),
 ('D10 a symlinked dependency is not mapped', F,
  '                if e.errno in _KIND_ERRNOS:\n'
  '                    raise DependencyAnomaly("not_regular", i, name, os.strerror(e.errno)) from e\n', '',
  [E + 'DependencyTests.test_a_symlink_dep_is_not_regular']),
 ('D11 malformed deps are not refused', F,
  '        deps = _check_deps_shape(deps)\n', '        deps = tuple(deps)\n',
  [E + 'DependencyTests.test_malformed_deps_are_refused_before_anything']),
 # -- mkdir_and_pin -------------------------------------------------------
 ('K1 no predicate', F,
  '            _mkdir_predicate(os.fstat(fd), want, os.fstat(parent_fd), name)\n', '',
  [E + 'MkdirPredicateTests.test_a_pre_existing_mismatch_is_refused_never_repaired']),
 ('K2 the setgid clause is dropped', F,
  '    elif (final.st_mode & stat.S_ISGID) != (parent.st_mode & stat.S_ISGID):\n'
  '        why = "setgid bit differs from the parent\'s"\n', '',
  [E + 'MkdirPredicateTests.test_a_pre_existing_mismatch_is_refused_never_repaired']),
 ('K3 the setuid/sticky clause is dropped', F,
  '    elif final.st_mode & (stat.S_ISUID | stat.S_ISVTX):\n        why = "setuid or sticky bit set"\n', '',
  [E + 'MkdirPredicateTests.test_a_pre_existing_mismatch_is_refused_never_repaired']),
 ('K4 the fchmod drops the inherited setgid', F,
  '                    os.fchmod(fd, (st.st_mode & stat.S_ISGID) | want)\n',
  '                    os.fchmod(fd, want)\n',
  [E + 'MkdirPredicateTests.test_an_own_group_setgid_parent_strict_umask_keeps_setgid']),
 ('K5 the predicate reads by name', F,
  '            _mkdir_predicate(os.fstat(fd), want, os.fstat(parent_fd), name)\n',
  '            _mkdir_predicate(os.stat(name, dir_fd=parent_fd, follow_symlinks=False), want,\n'
  '                             os.fstat(parent_fd), name)\n',
  [E + 'MkdirPredicateTests.test_the_check_is_on_the_pinned_descriptor']),
 ('K6 a requested setgid bit is honoured', F,
  '        want = mode & 0o777\n', '        want = mode & 0o7777\n',
  [E + 'MkdirPredicateTests.test_a_requested_setgid_bit_means_nothing']),
 ('K8 the owner is not compared', F,
  '    elif final.st_uid != os.geteuid():\n        why = f"owned by uid {final.st_uid}"\n', '',
  [E + 'MkdirPredicateTests.test_a_directory_of_another_owner_is_refused']),
 ('K9 the predicate only on pre-existing directories', F,
  '            _mkdir_predicate(os.fstat(fd), want, os.fstat(parent_fd), name)\n',
  '            if not created:\n'
  '                _mkdir_predicate(os.fstat(fd), want, os.fstat(parent_fd), name)\n',
  [E + 'MkdirPredicateTests.test_a_new_directory_is_checked_too']),
 ('K10 a new directory is always fchmodded', F,
  '                if stat.S_IMODE(st.st_mode) & 0o777 != want:\n', '                if True:\n',
  [E + 'MkdirPredicateTests.test_no_fchmod_when_the_umask_removed_nothing']),
 ('K7 the permission bits are not compared', F,
  '    elif stat.S_IMODE(final.st_mode) & 0o777 != want:\n', '    elif False:\n',
  [E + 'MkdirPredicateTests.test_a_pre_existing_mismatch_is_refused_never_repaired']),
 # -- PLUGIN_API -----------------------------------------------------------
 ('A1 the major is not compared', 'router/transport.py',
  '    if got[0] != api[0] or got[1] < required_minor:\n', '    if got[1] < required_minor:\n',
  ['router.tests.test_transport.LoaderTests.test_an_older_major_plugin_is_refused_by_this_major_3_runtime',
   'router.tests.test_transport.LoaderTests.test_a_major_3_plugin_is_refused_by_an_older_major_runtime']),
 ('A2 the runtime stays at an older major', 'router/transport.py',
  'PLUGIN_API: Tuple[int, int] = (3, 4)\n', 'PLUGIN_API: Tuple[int, int] = (2, 4)\n',
  ['router.tests.test_transport.LoaderTests.test_an_older_major_plugin_is_refused_by_this_major_3_runtime']),
]


def _red(r) -> bool:
    out = r.stdout + r.stderr
    return (r.returncode != 0 and "\nFAIL: " in "\n" + out
            and "FAILED (failures=" in out)


def main() -> int:
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    ok = True
    for d in pathlib.Path("router").rglob("__pycache__"):
        shutil.rmtree(d, ignore_errors=True)
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
        for d in pathlib.Path("router").rglob("__pycache__"):
            shutil.rmtree(d, ignore_errors=True)
        try:
            for t in tests:
                r = subprocess.run([sys.executable, "-B", "-m", "unittest", t],
                                   capture_output=True, text=True)
                red = _red(r)
                ok &= red
                verdict = "RED" if red else ("ERROR only (not RED)" if r.returncode else "GREEN (survived)")
                print(f"{label:48s} {t.split('.')[-1][:62]}: {verdict}")
        finally:
            path.write_text(orig)
    print(f"{len(M)} mutants: " + ("ALL RED" if ok else "SOME SURVIVED OR MISSING"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
