# sim

A simulated fleet of 200 macOS endpoints running DemoApp 1.4.2, with three injected root causes. All names are
fictional.

| Symptom | Injected cause | Rate on cause / elsewhere |
| --- | --- | --- |
| "Cannot reach server" (TLS trust failure) | proxy `corpguard-swg 5.2` (TLS inspection) | ~90% / ~2% |
| crash `DemoApp+0x6455 EXC_BAD_ACCESS` | DLP extension `datashield 4.2` | ~85% / ~2% |
| main-thread hang | OS build `24G90` | ~70% / ~3% |

```sh
docker compose -f backend/docker-compose.yml run --rm sim            # import into the control plane
python3 -m ieso_sim --out /tmp/fleet.json                           # or just write the JSON
cd sim && python3 -m pytest -q
```
