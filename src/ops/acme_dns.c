/* DNS-01 (RFC 8555 section 8.4) through the `dns_hook` program. The ACME job forks this runner
 * before its sandbox (the job itself may neither fork nor exec); the job asks it over a socket
 * pair, one line per request: "set|clear <name> <value>". The runner checks both arguments (a
 * host name and a base64url digest), runs the hook with execve, never a shell, as
 *   <hook> set|clear <name> <value>
 * with a fixed environment, waits at most BST_ACME_DNS_TIMEOUT_S, and answers with the exit
 * status. It ends when the job closes its end. */
#include "ops/acme.h"

#include "core/log.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define BST_ACME_DNS_TIMEOUT_S 120

static int dns_fd = -1;
static pid_t dns_pid;

static bool name_ok(const char *s)
{
	size_t n = strlen(s);
	if (n == 0 || n > 253)
		return false;
	for (size_t i = 0; i < n; i++) {
		char c = s[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
		      c == '.' || (c == '*' && i == 0)))
			return false;
	}
	return s[0] != '-' && s[0] != '.';
}

static bool value_ok(const char *s)
{
	size_t n = strlen(s);
	if (n == 0 || n > 128)
		return false;
	for (size_t i = 0; i < n; i++) {
		char c = s[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
		      c == '_'))
			return false;
	}
	return true;
}

static int run_hook(const char *hook, char *verb, char *name, char *value)
{
	pid_t p = fork();
	if (p < 0)
		return -1;
	if (p == 0) {
		char *argv[] = { (char *)(uintptr_t)hook, verb, name, value, NULL };
		char *envp[] = { "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				 "LANG=C", NULL };
		int nul = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (nul >= 0) {
			dup2(nul, 0);
			dup2(nul, 1); /* the hook's output never reaches the log: it may print secrets */
		}
		sigset_t none;
		sigemptyset(&none);
		sigprocmask(SIG_SETMASK, &none, NULL);
		execve(hook, argv, envp);
		_exit(127);
	}
	struct timespec tick = { 0, 50 * 1000 * 1000 };
	for (int i = 0; i < BST_ACME_DNS_TIMEOUT_S * 20; i++) {
		int st;
		pid_t r = waitpid(p, &st, WNOHANG);
		if (r == p)
			return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + (WIFSIGNALED(st) ? WTERMSIG(st) : 0);
		if (r < 0 && errno != EINTR)
			return -1;
		nanosleep(&tick, NULL);
	}
	kill(p, SIGKILL);
	(void)waitpid(p, NULL, 0);
	return 124;
}

/* Only a name the configuration asks a certificate for (a wildcard as its base name, the way
 * the job asks): a job that went wrong cannot have the hook touch any other DNS record. */
static bool configured(const bst_config *cfg, const char *name)
{
	for (size_t i = 0; cfg != NULL && i < cfg->global.nservers; i++) {
		const bst_cfg_server *s = cfg->global.servers[i];
		if (!s->tls_auto)
			continue;
		for (size_t k = 0; k < s->nnames; k++) {
			const char *n = s->names[k];
			if (n[0] == '*' && n[1] == '.')
				n += 2;
			if (strcasecmp(n, name) == 0)
				return true;
		}
	}
	return false;
}

static void runner(int fd, const char *hook, const bst_config *cfg)
{
	char line[512];
	size_t len = 0;
	for (;;) {
		ssize_t n = read(fd, line + len, sizeof line - 1 - len);
		if (n <= 0)
			_exit(0);
		len += (size_t)n;
		char *nl = memchr(line, '\n', len);
		if (nl == NULL) {
			if (len >= sizeof line - 1)
				_exit(1);
			continue;
		}
		*nl = '\0';
		char *verb = strtok(line, " "), *name = strtok(NULL, " "), *value = strtok(NULL, " ");
		int rc = -1;
		if (verb != NULL && name != NULL && value != NULL && strtok(NULL, " ") == NULL &&
		    (strcmp(verb, "set") == 0 || strcmp(verb, "clear") == 0) && name_ok(name) && value_ok(value) &&
		    configured(cfg, name))
			rc = run_hook(hook, verb, name, value);
		char out[16];
		int ol = snprintf(out, sizeof out, "%d\n", rc);
		if (write(fd, out, (size_t)ol) != ol)
			_exit(1);
		len = 0;
	}
}

int bst_acme_dns_start(const char *hook, const bst_config *cfg)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
		return -1;
	pid_t p = fork();
	if (p < 0) {
		close(sv[0]);
		close(sv[1]);
		return -1;
	}
	if (p == 0) {
		close(sv[0]);
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		prctl(PR_SET_NAME, "acme-dns-hook");
		runner(sv[1], hook, cfg);
		_exit(0);
	}
	close(sv[1]);
	dns_fd = sv[0];
	dns_pid = p;
	return 0;
}

int bst_acme_dns_run(const char *verb, const char *name, const char *value)
{
	if (dns_fd < 0)
		return -1;
	char line[512];
	int n = snprintf(line, sizeof line, "%s %s %s\n", verb, name, value);
	if (n <= 0 || (size_t)n >= sizeof line || write(dns_fd, line, (size_t)n) != n)
		return -1;
	char out[16];
	size_t len = 0;
	while (len < sizeof out - 1) {
		ssize_t r = read(dns_fd, out + len, 1);
		if (r <= 0)
			return -1;
		if (out[len] == '\n')
			break;
		len++;
	}
	out[len] = '\0';
	return atoi(out);
}

void bst_acme_dns_stop(void)
{
	if (dns_fd >= 0)
		close(dns_fd); /* the runner reads EOF and ends; the job's exit reaps nothing: init does */
	dns_fd = -1;
	(void)dns_pid;
}
