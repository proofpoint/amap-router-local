"""router.tests — the suite, and the two names another repo may import.

THIS PACKAGE IS NOT INTERNAL, and saying so is the point of this file.

`router/__init__.py` partitions the top-level modules three ways, computed
from `_PKG.glob("*.py")` — top level only. So this subpackage was neither
public, internal nor unclassified: it was UNCONSIDERED, and nothing asserted
anything about it. It acquired a consumer anyway. A host adapter's
layout-agreement test imports `RouterTestCase` and calls `make_config`,
which is the right way to build that test — its whole claim is that two
repos agree about a directory layout, and a second copy of the layout here
would agree right up until it didn't. One fixture, derived where the layout
is derived, is the mechanism rather than a shortcut around it.

The gap was not theoretical. Retiring `approve` renamed `make_config`'s
`approve=` keyword to `seen=` and `_auto_approve` to `_mark_seen` — both
call-time `TypeError`s in an out-of-package caller, neither an import error,
and both made without knowing a caller existed. That caller happened not to
pass the keyword, so nothing broke; it stayed possible for an hour and
nothing in this repo could have said so.

`PUBLIC_TEST_SURFACE` is therefore deliberately TINY. It is not an invitation
to lean on the fixtures — everything else here, including `_mark_seen`,
`write_request`, every helper's internals and every module named `test_*`, may
change without notice. It is the exact set one external test uses, pinned so
that renaming any of it goes red in THIS suite instead of silently in
someone else's.

Changing anything named here is a cross-repo change and owes that caller
notice BEFORE the commit, the same obligation carried by
`firstsight.FIRST_SEEN_FILENAME`, `util.open_child_pinned` /
`reset._open_child`, and `router/reset.py`'s continued existence as a
checkout sentinel.
"""

#: The only names in this package another repository may import, and the
#: only ones `test_public_surface.py` defends. See the module docstring for
#: why it is this small and what it costs to grow it.
#:
#: DOTTED, because the shape matters: `make_config` is not a module-level
#: function, it is a METHOD reached through the class, which is exactly how
#: the external caller reaches it (`self.make_config(...)` from a subclass).
#: The first version of this tuple said `"make_config"` flat and the
#: existence check went red on its first run — a declaration that did not
#: match the thing it declared. Keeping the dotted form means the assertion
#: resolves the name the same way a caller does.
PUBLIC_TEST_SURFACE = ("RouterTestCase", "RouterTestCase.make_config")

#: Keyword arguments of `RouterTestCase.make_config` that are part of the
#: declared surface. `mode` is what the external caller passes; `seen` is
#: named because it is the one that has already been renamed once, and a
#: surface that pinned only the names and not the keywords would not have
#: caught that.
PUBLIC_MAKE_CONFIG_KWARGS = ("mode", "seen")
