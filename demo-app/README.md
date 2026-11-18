# demo-app

`DemoApp`: a small "business-critical" macOS app (Swift + AppKit, a single file) used as the black-box target.
The sensor never links against it; it observes it from outside only.

```sh
demo-app/build.sh                                         # -> build/demo-app/DemoApp.app (bundle id com.ieso.demoapp)
open build/demo-app/DemoApp.app                           # click a fault button
open -n build/demo-app/DemoApp.app --args --fault crash --after 4   # automation
```

| Fault | What the app does | What the sensor should see |
| --- | --- | --- |
| `hang` | blocks the main thread for 30 s | AX probe timeouts → `ProcessHangDetected`, bundle with `sample` stacks |
| `crash` | writes through pointer 0x8 | kqueue exit + `.ips` → `ProcessCrashDetected` `DemoApp+0x… EXC_BAD_ACCESS` |
| `leak` | retains +20 MB/s | `ResourceAnomalyDetected` `rss_growth` |
| `network` | calls an unroutable backend, shows "Cannot reach server" | error `LogRecordObserved`, `UserVisibleErrorObserved` |
| `permission` | reads a privacy-protected file, shows "Permission denied" | `UserVisibleErrorObserved` with the home path redacted |

The app logs through `os.Logger(subsystem: "com.ieso.demoapp")`. Its `debug` heartbeat shows up only when the
sensor escalates the subsystem's log level (needs root).
