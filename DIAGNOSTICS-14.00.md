# PS4 14.00 WebKit launch diagnostics

Read-only review of the public `main` branch logs and upstream project documentation.
This note records observations; it does not change exploit, kernel-hook, FSELF/FPKG,
or payload-loading behavior.

## Findings from the uploaded runtime logs

- The WebKit/Afterglow stage reaches the NexHEN bootstrapper.
- The bootstrapper reports a conflict while preparing the PS4HEN-related package
  patch stage, then reports that the FSELF/FPKG hooks were skipped with
  `errno=16` (`Device busy`).
- The bootstrapper explicitly reports that package patches are incomplete and
  continues startup. This is the clearest logged explanation for why a
  successful browser jailbreak does not imply successful application launches.
- The ShellUI log reports successful injection and installation of its UI
  hooks. The daemon log reports 11 packages discovered. Those facts show that
  the shell interface and package scan can work while the separate launch
  patch stage is incomplete.
- The bootstrapper's daemon-launch failure is timestamped at
  `1794534303`; the daemon log starts at `1794536411`. These are different
  timestamps, so they should not be treated as one continuous boot attempt
  without matching console-side session identifiers.
- In the later daemon log, `klogsrv` fails to appear, but the daemon itself,
  binsrv, ftpsrv, elfldr, package installer, and ShellUI injection continue.
  The klogsrv failure is therefore a secondary diagnostics-service issue, not
  evidence by itself that the HEN kernel stage failed.

## Upstream context

- The public `ps4-hen` history contains a 14.00 PFS-function offset correction
  in the change titled **“Fix sceSblPfsSetKeys_addr offset”**:
  https://github.com/Scene-Collective/ps4-hen/commit/006b38bc17b36f4e55c4b9b5118a03c2e5477320
- The public `ps4-kstuff` project documents 14.00 support and describes itself
  as a separate patch library:
  https://github.com/ItsJokerZz/ps4-kstuff
- The Afterglow WebKit host and its browser-side kernel entry are a separate
  layer from the NexHEN bootstrapper/daemon components:
  https://github.com/well0nez/afterglow-web

These references establish that upstream components have evolved, but they do
not prove that the runtime component reporting the conflict is using the same
revision or binary as any particular public release.

## Safe next diagnostic boundary

Before any code or binary replacement, identify the exact provenance and build
identity of the component that emits the `[Kstuff]` messages, and match it to
the corresponding upstream release/commit. Also correlate bootstrapper and
daemon timestamps to a single boot. Do not infer that the committed Afterglow
WebKit files are responsible for a log emitted by a separately loaded
NexHEN component.

No offsets, hook targets, kernel patch routines, or FSELF/FPKG behavior are
modified by this note.
