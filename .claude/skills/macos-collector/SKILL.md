---
name: macos-collector
description: Reference for the macOS APIs the Ieso sensor observes an app with from outside its process - kqueue NOTE_EXIT, FSEvents on DiagnosticReports (.ips), the AX responsiveness probe and AXObserver dialogs, log stream ndjson, libproc sampling, sample and log config - with the permissions each needs and the pitfalls already hit. Use when writing or debugging any code in sensor/platform/macos/ or the macOS actors (process_watcher, resource_sampler, log_collector, ui_observer).
---

# macOS collectors: how the sensor observes an app it doesn't own

The rule is to observe from outside the process, with no injection, no SDK and no kexts. Every blocking API runs
in an `IEventSource` thread with a stop flag and bounded waits. C objects are owned by `CfRef<T>`
(`ieso/macos/cf_ref.hpp`), and subprocesses go through `Subprocess` (`ieso/macos/subprocess.hpp`).

| Signal | API | Where | Permission |
| --- | --- | --- | --- |
| Launch / exit | `proc_listallpids` (`list_pids`) + `CFBundle` id/version (`bundle_info`); `kqueue` `EVFILT_PROC` `NOTE_EXIT \| NOTE_EXITSTATUS` (`EV_ONESHOT`) | `actors/process_watcher` | none |
| Crash | FSEvents on `~/Library/Logs/DiagnosticReports` and `/Library/Logs/DiagnosticReports`, `kFSEventStreamCreateFlagFileEvents \| NoDefer`; parse `.ips` | `process_watcher` + `core/ips_parser` | none (FDA for other users' reports) |
| Resources | `proc_pidinfo(PROC_PIDTASKINFO)`, `PROC_PIDLISTFDS` (size query only), `statfs` | `platform/macos/proc_info`, `actors/resource_sampler` | none for same-user processes |
| Hang | AX probe: `AXUIElementCopyAttributeValue(app, kAXFocusedWindowAttribute)` under `AXUIElementSetMessagingTimeout` | `actors/ui_observer` (`AxProbeSource`) | **Accessibility** |
| Error dialogs | `AXObserverCreate` + `kAXWindowCreatedNotification` / `kAXSheetCreatedNotification`, then read role, subrole and texts | `ui_observer` (`AxDialogSource`) | **Accessibility** |
| App logs | `/usr/bin/log stream --style ndjson --level debug --predicate 'process == "<app>" OR (process == "tccd" AND eventMessage CONTAINS "<app>")'` | `actors/log_collector` | none |
| Log escalation | `/usr/bin/log config --subsystem <s> --mode level:debug` and `--reset` | `macos_diagnostics_platform` | **root** |
| Stacks | `/usr/bin/sample <pid> <seconds>` | `macos_diagnostics_platform::capture_stacks` | same user (root for others) |

## Pitfalls already hit (keep these behaviours)
- **`.ips` files appear before they're complete.** ReportCrash writes them in stages. A parse that returns
  `CorruptData` is retried every 250 ms, up to `kMaxParseAttempts` (40, so 10 s). Keep the `seen_` and `pending_`
  dedupe sets, because FSEvents fires several times per file.
- **macOS moves reports after writing them**, for example into `DiagnosticReports/Retired/`. The FSEvents stream is
  recursive, so a moved file looks new. Deduplicate crashes by the report header's `incident_id` (a bounded set of
  512), never by path. Paths under `/Retired/` are skipped outright. Test: `ProcessWatcher.MovedReportPostsOnce`.
- **macOS rewrites old reports, and stops writing new ones for an app that crashes often.** After a couple of dozen
  crashes in a day, a crash may produce no new `.ips` at all, and macOS touches an *old* report instead. So:
  - accept a report only if the crash time in its header (`timestamp`) falls within this sensor's lifetime and the
    last 10 minutes (`max_report_age`);
  - when the target exits on a crash signal (SIGSEGV, SIGBUS, SIGABRT, SIGILL, SIGFPE, SIGTRAP) and no fresh report
    arrives within 30 s (`report_grace`), post `ProcessCrashDetected` from the exit signal. Its signature reads
    `"<app> <signal> (no crash report)"`;
  - mark that pid, so a report that arrives late can't become a second incident.

  Tests: `StaleReportIgnored`, `CrashExitTracker`, `LateReportAfterFallbackDropped`.
- **The hang signal is `kAXErrorCannotComplete`.** That's the AX reply missing within the messaging timeout, meaning
  the main run loop isn't servicing events. A hang is declared after 3 consecutive timeouts (`AnomalyOptions`).
  `kAXErrorAPIDisabled` means there's no Accessibility permission: report it as `permitted=false`, never as a hang.
- **AX attach on a just-launched app fails** with an error that looks like `PermissionDenied`. Retry every 500 ms for
  up to 10 s (`kMaxAttachAttempts`) when `AXIsProcessTrusted()` is true. When it's false, give up at once and log a
  warning.
- **Set a messaging timeout on every AX element read** (`AXUIElementSetMessagingTimeout`). Otherwise reading a hung
  app blocks the sensor's own thread.
- **The AX observer's run loop belongs to its thread.** Add the observer source to `CFRunLoopGetCurrent()` on the
  `AxDialogSource` thread and pump `CFRunLoopRunInMode(…, 0.25, false)`. Callbacks only queue windows; they're
  inspected after `dialog_settle` (300 ms), once their texts have been filled in.
- **Dialog text is unsanitized user data.** It goes into a `free_text` field and stays out of INFO+ traces. Log only
  its length.
- **Never escalate log levels without root.** If `geteuid() != 0`, return `PermissionDenied`. Never trigger an
  authorization prompt on the user's screen. Every escalation has an expiry and a `--reset`.
- **Run `sample` within budget.** At most 1 per incident and 4 per hour (`CaptureBudget`), because it pauses the
  target briefly. Hang reports rely on it, so don't waste the budget in tests against a live app.
- **`log stream` takes a second or two to start streaming.** When testing against a live app, give the sensor a few
  seconds before triggering the fault; the scripts use `--after 4`. Parser tests (`LogStream.*`) run on fixed ndjson
  lines.
- **CFNetwork never proxies loopback.** A proxy-based demo needs a non-loopback hostname. The netdemo app talks to
  `app-backend` through the proxy, and the probe's direct path maps that name to `localhost:9443` with libcurl
  `CURLOPT_CONNECT_TO`.
- **TCC denials show up in `tccd` log lines,** not in the app's own logs. That's why the log predicate includes
  `tccd` messages that mention the app.

## Permissions in production (DESIGN §2, privilege tiers)
An MDM PPPC profile grants Accessibility (and FDA if a probe needs it) to the sensor binary silently. In the demo,
grant Accessibility by hand to Terminal or VS Code, whichever runs the sensor. Root is optional: without it, log
escalation is skipped with a warning and everything else works.

## Testing macOS code
- **Tests:** `ieso_macos_tests` in `sensor/tests/` uses the real APIs: libproc on the test process, subprocesses,
  kqueue on a child, and a `log stream` round trip.
- **AX:** tests skip, or assert `permitted=false`, when Accessibility isn't granted.
- **Real-app check:** run `scripts/smoke_test.sh hang crash leak network permission` against DemoApp, then
  `/build-test`.
