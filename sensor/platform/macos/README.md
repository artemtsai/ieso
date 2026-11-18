# sensor/platform/macos

macOS OS helpers used by the actors in `sensor/actors/`: `proc_info` (libproc, sysctl, statfs, CFBundle), `subprocess` (posix_spawn with pipes and timeouts), `cf_ref` (CoreFoundation RAII) and `macos_diagnostics_platform` (`sample`, `log config`, environment; implements `IDiagnosticsPlatform`).
