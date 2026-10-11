# Registry fixtures: provenance

Both files come from the public amap-host repository and are not edited.

- `skeleton_vectors.json`: copied verbatim from amap-host at commit
  `3f28c782b41df5b701e259c535732e859553ddef`,
  `tests/fixtures/skeleton_vectors.json`. sha256
  `7d4088dc1686aa8daa9a65a4a820ec118bf214ebd51ed112880a81a2955a6d1c`. It is
  the shared contract for `skeleton()`: amap-host's model and this router's
  `router/registry.py` must give the same answers.
- `snapshot.json`: a registry snapshot written by amap-host's own writer at
  that commit, from synthetic inputs (two `sandy` registrations under
  `/srv/work/`, the second then retired; a fixed clock). It pins the format
  this router reads (amap-host `docs/registry-writer.md`, "What a consumer
  may rely on").

`router/tests/test_registry.py` checks both hashes, so an edit here fails
loudly.
