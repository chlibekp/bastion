# Benchmarks

```sh
scripts/bench.sh --target host  --scenario static-small
./dev scripts/bench.sh --target local --scenario static-small
```

Scenarios: `static-small` (1 KiB file) and `static-large` (64 MiB file) work now. `tls`, `h2`,
`h3`, `proxy` and `cache` exit with status 3 until the phase that adds the feature.

The script starts Bastion from `build/$BUILD/bastion` (default `release`) with
`bench/bastion.conf`, and nginx with `bench/nginx.conf` when `nginx` is installed. Both use two
workers, an open file cache, long keep-alive and no access log. Load comes from `wrk`, or
`h2load --h1` when `wrk` is missing. Results go to `bench/results/<date>-<scenario>.json`.

## Reading results

Each file carries a `label`. `docker-not-comparable` marks runs inside the `./dev` container or
`--target local`: the numbers prove the harness works and nothing else. Compare Bastion with
nginx only from `comparable` runs taken on one bare-metal host with the same kernel, CPU
governor and NIC settings.

Tunables: `DURATION`, `CONNS`, `REQS`, `BUILD`, `BAST_PORT`, `NGX_PORT` (environment).
