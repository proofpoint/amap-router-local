# Registry fixtures: provenance

Both files are the host registry's own test material, copied byte for byte
and not edited. The registry is written by a separate host-level component;
this router only reads it (`router/registry.py`).

- `skeleton_vectors.json`: the host registry's name-skeleton test vectors,
  copied verbatim at source commit
  `3f28c782b41df5b701e259c535732e859553ddef`. sha256
  `7d4088dc1686aa8daa9a65a4a820ec118bf214ebd51ed112880a81a2955a6d1c`. It is
  the shared contract for `skeleton()`: the registry's model and this
  router's `router/registry.py` must give the same answers.
- `snapshot.json`: a registry snapshot written by the registry's own writer
  at that commit, from synthetic inputs (two `sandy` registrations under
  `/srv/work/`, the second then retired; a fixed clock). It pins the format
  this router reads, as the writer's documentation defines what a consumer
  may rely on.

Their text is owned upstream and is kept as it came, including the
`description` line in `skeleton_vectors.json` and the `schema` value in
`snapshot.json`. The schema token (see `SUPPORTED_SCHEMAS` in
`router/registry.py`) is an opaque wire identifier: it is compared for
membership, never interpreted.

`router/tests/test_registry.py` checks both hashes, so an edit here fails
loudly.
