# Project skills (Claude Code)

[`CLAUDE.md`](../../CLAUDE.md) holds this project's rules. These skills hold its repeatable procedures. Claude Code
loads them from this folder; invoke one by typing `/<name>`.

| Skill | Invoke | Use it when | Encodes |
| --- | --- | --- | --- |
| [build-test](build-test/SKILL.md) | `/build-test` | after any change, before calling a task done, when a build or test fails | CMake presets, the compact test runner, ASan/TSan, Python suites, e2e scripts, how to read failures |
| [add-actor](add-actor/SKILL.md) | `/add-actor` | adding a sensor capability that needs its own actor | bus-only messaging, the `Actor` base, events from the ontology, the STYLEGUIDE checklist, tests, host registration, doc updates |
| [add-event](add-event/SKILL.md) | `/add-event` | an actor needs to emit something no existing event describes | class/overflow/egress traits, `AllEvents`, PII-safe `fields()` (redact / free text / verbatim), downstream consumers, DESIGN §7 |
| [add-probe](add-probe/SKILL.md) | `/add-probe` | the investigator needs a new kind of evidence from an endpoint | read-only implementation, all three allowlists, parser + reasoner support, tests, docs |
| [macos-collector](macos-collector/SKILL.md) | loaded automatically | writing or debugging macOS collector code | kqueue, FSEvents/.ips, AX probe and observer, log stream, libproc, sample, log config, permissions, pitfalls |
| [run-demo](run-demo/SKILL.md) | `/run-demo` | rehearsing or giving the live demo, checking a change in the real UI | backend + sensor + DemoApp faults, what to show in Grafana, investigator modes, pitfalls, teardown |
| [cause-crash](cause-crash/SKILL.md) · [cause-hang](cause-hang/SKILL.md) · [cause-leak](cause-leak/SKILL.md) · [cause-network](cause-network/SKILL.md) · [cause-permission](cause-permission/SKILL.md) | `/cause-crash` … `/cause-permission` | during the demo, to break DemoApp on cue | one fault each, through `scripts/demo_fault.sh`: launch, wait for the incident, wait for the watcher's report, print the root cause and the Grafana links; what to expect and the caveats per fault |
| [stop-demo](stop-demo/SKILL.md) | `/stop-demo` | after a demo, rehearsal or e2e session | stops DemoApp, every sensor (SIGTERM, so it checkpoints), the watcher first (no more paid Claude calls), then the whole stack; checks that nothing is left; `-v` wipe only on request |

`run-demo` and the `cause-*` skills start things and can make paid Claude calls, and `stop-demo` shuts everything
down, so only a person can invoke them (`disable-model-invocation: true`). Claude may load the others on its own when they apply.
