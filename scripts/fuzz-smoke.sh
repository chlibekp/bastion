#!/usr/bin/env bash
# Run libFuzzer harnesses: scripts/fuzz-smoke.sh SECS [name...]
# With no names, runs every fuzz/fuzz_*.c. Names may omit the "fuzz_" prefix. Each run
# uses a scratch copy of fuzz/corpus/<name>/ (deleted afterwards), so the checked-in
# corpus is never modified. Failures do not stop the run; the exit status is non-zero if
# any harness crashed, timed out, tripped a sanitizer or could not be built or found.
# Env: FUZZ_SRC_DIR (harness sources, default fuzz), FUZZ_CRASH_DIR (reproducers,
# default fuzz/crashes), FUZZ_TIMEOUT (per-input seconds, default 20), FUZZ_RSS_MB.
set -u
cd "$(dirname "$0")/.."

secs=${1:?usage: fuzz-smoke.sh SECS [name...]}
shift
src=${FUZZ_SRC_DIR:-fuzz}
crashes=${FUZZ_CRASH_DIR:-fuzz/crashes}
timeout=${FUZZ_TIMEOUT:-20}
rss=${FUZZ_RSS_MB:-2048}

names=()
if [ $# -eq 0 ]; then
	for f in "$src"/fuzz_*.c; do
		[ -e "$f" ] && names+=("$(basename "$f" .c)")
	done
else
	for n in "$@"; do
		case $n in fuzz_*) names+=("$n") ;; *) names+=("fuzz_$n") ;; esac
	done
fi
if [ ${#names[@]} -eq 0 ]; then
	echo "fuzz: no harness found in $src" >&2
	exit 2
fi

failed=()
runnable=()
for n in "${names[@]}"; do
	if [ -f "$src/$n.c" ]; then
		runnable+=("$n")
	else
		echo "fuzz: no harness $src/$n.c" >&2
		failed+=("$n (no harness)")
	fi
done

mkdir -p "$crashes"
built=()
for n in "${runnable[@]}"; do
	if make -s fuzz-build FUZZ_SRC_DIR="$src" FUZZ_NAMES="$n"; then
		built+=("$n")
	else
		echo "fuzz: build of $n failed" >&2
		failed+=("$n (build failed)")
	fi
done

seed=${FUZZ_SEED:-1}
for n in "${built[@]+"${built[@]}"}"; do
	case $n in
	fuzz_json) maxlen=65536 ;;
	*) maxlen=4096 ;;
	esac
	scratch=$(mktemp -d)
	corpus=fuzz/corpus/${n#fuzz_}
	[ -d "$corpus" ] && cp -R "$corpus"/. "$scratch"/
	echo "== $n: ${secs}s, corpus $(find "$scratch" -type f | wc -l) files"
	before=$(ls "$crashes")
	args=(-seed="$seed" -max_total_time="$secs" -timeout="$timeout" -rss_limit_mb="$rss"
		-max_len="$maxlen" -artifact_prefix="${crashes%/}/${n}-")
	build/fuzz/bin/"$n" "${args[@]}" "$scratch"
	rc=$?
	rm -rf "$scratch"
	if [ $rc -ne 0 ]; then
		sig=""
		[ $rc -gt 128 ] && sig=", killed by signal $((rc - 128)) ($(kill -l $((rc - 128)) 2>/dev/null))"
		if [ "$(ls "$crashes")" != "$before" ]; then
			failed+=("$n (exit $rc$sig; reproducer in ${crashes%/}/)")
		else
			failed+=("$n (exit $rc$sig; no reproducer was written; re-run: build/fuzz/bin/$n ${args[*]} ${corpus})")
		fi
	fi
done

if [ ${#failed[@]} -gt 0 ]; then
	echo "fuzz: ${#failed[@]} failure(s):" >&2
	printf '  %s\n' "${failed[@]}" >&2
	exit 1
fi
echo "fuzz: ${#built[@]} harness(es) clean"
