# PS4 14.00 WebKit / NexHEN launch diagnostics

Read-only diagnosis based on the current uploaded runtime logs and public upstream
source. This note does not change exploit, kernel-hook, FSELF/FPKG, or payload
loading behavior.

## Current test: NexHEN build 118

The latest log set is in commit
[6ac5ef3](https://github.com/CrispyKilledIt/afterglow/commit/6ac5ef3b6bd16baad8a7bd840e4ec1b47f1a8936).

### Confirmed startup

- Bootstrapper starts as NexHEN PS4 v1.00 build 118.
- All 38 icons are extracted.
- The native `elfldr` service starts on port 9021.
- The daemon starts on IPC port 9028.
- `binsrv` starts on port 9090 and `ftpsrv` starts on port 2121.
- The package installer listens on port 12800.
- The daemon discovers 11 packages, 8 payloads, and 4 plugins.
- ShellUI injection completes: its managed worker acknowledges startup, the UI
  frame hook installs, and 34 debug/toolbox hooks are installed.

### Primary failure: 14.00 PFS call-target mismatch

The bootstrapper log reports:

```
[Kstuff] Hook conflict at +0x6a39f9
(target=0xffffffff9ddf7270 expected=0xffffffff9ddf72b0); unchanged
[Kstuff] Kernel FSELF/FPKG hooks skipped: errno=16 (Device busy)
[Kstuff] Verified 16 ShellCore package/version patches
[Boot] kstuff incomplete: errno=16 (Device busy); continuing
nexHEN PS4: package patches incomplete; check bootstrapper log
```

The public `ItsJokerZz/ps4-kstuff` source contains the matching diagnostic in
`source/kpayload.cpp` (`check_calls()`). Its 14.00 row in
`source/firmware_table.inc` currently records:

- call site `0x6a39f9` -> target `0x6272b0`
- call site `0x6a3c2a` -> target `0x6272b0`
- `sceSblPfsSetKeys_addr = 0x6272b0`

Afterglow's own `TECHNICAL.md` documents that, for the 14.00 image, the
function entry is `0x627270`; `0x6272b0` is inside the function. The
Afterglow README also documents that its bundled ps4-hen build has the
14.00 offset correction from `0x006272B0` to `0x00627270`.

This is a strong source-level match for the observed conflict: the running
Kstuff component appears to expect the pre-correction call target while the
kernel contains the corrected target. Its `check_calls()` rejects the
mismatch with `EBUSY`, and `kstuff_apply()` consequently reports that the
FSELF/FPKG kernel hooks were skipped.

**Important provenance qualification:** the log's wording and values match
the public kstuff implementation, but the exact NexHEN-linked binary revision
has not yet been independently identified. Confirm that build provenance
before changing or replacing any payload.

Relevant public references:

- [ps4-kstuff source: kpayload.cpp](https://github.com/ItsJokerZz/ps4-kstuff/blob/main/source/kpayload.cpp)
- [ps4-kstuff 14.00 firmware table](https://github.com/ItsJokerZz/ps4-kstuff/blob/main/source/firmware_table.inc)
- [Afterglow technical note](https://github.com/CrispyKilledIt/afterglow/blob/main/TECHNICAL.md)
- [ps4-hen 14.00 offset correction](https://github.com/Scene-Collective/ps4-hen/commit/006b38bc17b36f4e55c4b9b5118a03c2e5477320)

## Secondary observations

- `klogsrv` is forwarded but its process does not appear. The daemon continues
  running its other services, so this is a diagnostics-service failure rather
  than proof that the whole HEN failed.
- The bootstrapper says ShellUI startup was not acknowledged, but the daemon
  subsequently logs a successful ShellUI worker acknowledgement and injection.
  Treat the bootstrapper's early status as incomplete/stale relative to the
  later daemon evidence, not as proof that ShellUI never loaded.
- The bootstrapper and daemon entries in this newest set both begin around
  timestamp `1794543398`, so they are consistent with the same boot. The
  timestamp mismatch documented for the earlier `Logs` commit should not be
  applied to this newer set.

## Next safe diagnostic boundary

1. Identify the exact NexHEN build/source revision that supplies its Kstuff
   component and compare its 14.00 firmware table with the public source above.
2. Confirm the PFS call-target correction is represented consistently in the
   source and binary that NexHEN actually links.
3. Keep the working WebKit/Afterglow entry and native loader unchanged while
   validating the separate HEN patch component.
4. Do not test a rebuilt kernel-hook payload until its source, firmware table,
   and build identity have been checked against the console's exact 14.00 image.

No exploit offsets, hook targets, kernel patch routines, or FSELF/FPKG behavior
are modified by this diagnostic note.

## Cross-check: the public ps4-hen fix is not a NexHEN Kstuff fix

A second source comparison confirms that the same address correction was
committed upstream in **Scene-Collective/ps4-hen**:

- Commit `006b38bc17b36f4e55c4b9b5118a03c2e5477320`, titled
  “Fix sceSblPfsSetKeys_addr offset”, changes the 14.00 value from
  `0x006272B0` to `0x00627270`.
- Afterglow's README records the patched `hen.bin` MD5 as
  `6417a84a72f9c7988f0e33b3ae190542` and explicitly warns against the
  upstream unpatched MD5 `9aff7544eddef2f8202f72fc633d2be3`.

However, the failing check in the NexHEN log is emitted by the separate
Kstuff component. The public `ItsJokerZz/ps4-kstuff` 14.00 firmware table
still lists both PFS call sites with target `0x6272b0`. Therefore, finding
the ps4-hen correction does **not** prove that NexHEN build 118's Kstuff
binary contains that correction. The two components must not be conflated.

This narrows the likely mismatch to the Kstuff build/configuration linked into
NexHEN, but it still does not identify the exact binary revision. No payload
was changed and no replacement binary is approved by this review.

Additional reference:
- [Upstream ps4-hen correction commit](https://github.com/Scene-Collective/ps4-hen/commit/006b38bc17b36f4e55c4b9b5118a03c2e5477320)

## Stronger provenance lead: public kstuff snapshot is pinned before the fix

The public `ItsJokerZz/ps4-kstuff` repository's `UPSTREAM` file pins
ps4-hen to commit `d077fb4031cf0e089fb7a233cebeebcd1ed3c68e`
(“Add 14.00 support”). Its checked-in `source/firmware_table.inc` has
both PFS call targets set to `0x6272b0`, matching the NexHEN log's
`expected=0xffffffff9ddf72b0`.

The later ps4-hen correction commit
`006b38bc17b36f4e55c4b9b5118a03c2e5477320` changes
`sceSblPfsSetKeys_addr` to `0x00627270`. The kstuff repository's
generator imports this symbol and both `mountpfs__sceSblPfsSetKeys`
call targets from ps4-hen, so a kstuff sync/build based on the corrected
ps4-hen revision should carry the corrected target into its generated table.

This is now a concrete, reproducible source-provenance explanation for why
the public kstuff table and the console log agree on the stale target. It
still does not prove that NexHEN build 118 embeds this exact public kstuff
snapshot; the log's matching diagnostic and table values make it a strong
candidate, not a verified binary identity.

The public kstuff repository documents a source build, but no verified,
drop-in replacement for NexHEN build 118 was found. A standalone kstuff
library is not interchangeable with the full NexHEN payload. Since only
compiled NexHEN is available, do not replace or patch its binary blindly;
the safe next step is to obtain a maintainer-built NexHEN revision that
integrates the corrected kstuff table, or an authenticated build manifest
that identifies the embedded kstuff revision.

References:
- [kstuff upstream pin](https://github.com/ItsJokerZz/ps4-kstuff/blob/main/UPSTREAM)
- [kstuff generated 14.00 firmware table](https://github.com/ItsJokerZz/ps4-kstuff/blob/main/source/firmware_table.inc)
- [kstuff table generator](https://github.com/ItsJokerZz/ps4-kstuff/blob/main/tools/generate.py)
- [ps4-hen 14.00 offset correction](https://github.com/Scene-Collective/ps4-hen/commit/006b38bc17b36f4e55c4b9b5118a03c2e5477320)

