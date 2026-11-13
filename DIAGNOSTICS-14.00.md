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
