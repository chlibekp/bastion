/* Command line: option parsing and dispatch only. Printing the effective config and the
 * schema lives in dump.c.
 *
 *   bastion [-c file] [-t] [-T]       check (-t), print effective config (-T), or run
 *   bastion serve <dir> [--port n]    quick static server, no config file
 *   bastion proxy <url> [--port n]    quick reverse proxy, no config file
 *   bastion --dump-schema | --help | --version
 *   bastion --test-listeners N [--test-accept-ms MS]   test builds only (io/test_listeners.c)
 *
 * Every mode goes through bst_cfg_compile, so `-t` and a real start accept and reject the
 * same files. Exit codes: 0 ok, 1 config error, 2 usage (and, until Phase 3, a valid
 * config that has no server runtime to start). Errors print as `file:line:col: message`
 * on stderr, control bytes escaped. */
#ifndef BST_CONFIG_CLI_H
#define BST_CONFIG_CLI_H

#include "config/parser.h"
#include "core/arena.h"
#include "core/err.h"

#include <stdint.h>

#define BST_DEFAULT_CONFIG "/etc/bastion/bastion.conf"
#define BST_QUICK_PORT 8080 /* serve and proxy default, as in the config-language example */

int bst_cli_main(int argc, char **argv);

/* The AST for `serve` (verb "serve", arg the directory) or `proxy` (verb "proxy", arg the
 * URL): `server { listen <port>; root|proxy <arg>; }`, built in memory. The argument is
 * stored as one single-quoted-style argument (no `$` expansion), never as config text, so
 * no value can add directives. NULL with err set on failure. */
bst_ast *bst_cli_build_ast(const char *verb, const char *arg, uint16_t port, bst_arena *a,
			   bst_err *err);

#endif
