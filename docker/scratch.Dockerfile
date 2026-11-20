# Minimal image: the static binary and nothing else (no shell, no libc, no passwd file).
# Built by scripts/build-release.sh with BIN=<outdir>/bastion-<v>-linux-<arch>.
#   docker run -p 8080:8080 -v "$PWD/site:/www:ro" bastion:<v>-<arch> serve /www
# Runs as uid/gid 65534 (nobody). To listen below 1024, add --cap-add NET_BIND_SERVICE; the
# binary has no file capabilities.
FROM scratch
ARG BIN
COPY --chmod=0755 ${BIN} /usr/bin/bastion
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/usr/bin/bastion"]
CMD ["--help"]
