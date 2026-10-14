# Registry fixtures: provenance

Both files are the host registry's own test material, copied byte for byte
and not edited. The registry is written by a separate host-level component;
this router only reads it (`router/registry.py`).

- `skeleton_vectors.json`: the host registry's name-skeleton test vectors,
  copied verbatim at source commit
  `4993eec9ab765343ab5832ea24bd4dad0d67baf9`. sha256
  `bb46836da795b4c35c190bb98b144c50b099eb7630337d509ebb57e6875a8a3f`. The
  copy before it, at source commit
  `3f28c782b41df5b701e259c535732e859553ddef`, differed in its `description`
  line alone: the source reworded that line to name only "the host
  registry", and every vector is unchanged (the test hashes them). It is
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
