/* The sandbox { } block (architecture section 8). A singleton block, so every default applies when
 * the block is not written: omitted config gives a sandboxed worker. */
#include "config/compile.h"
#include "config/values.h"
#include "core/str.h"

#include <string.h>

static bst_str as_str(const bst_ast_arg *a)
{
	return (bst_str){ a->text, (uint32_t)a->len };
}

static int ap_sandbox(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)c, (void)d, (void)n, (void)e; /* the scope is c->global->sandbox; children fill it */
	return 0;
}

static const char *const seccomp_modes[] = { "off", "on", "log", NULL };
_Static_assert(BST_SECCOMP_OFF == 0 && BST_SECCOMP_ON == 1 && BST_SECCOMP_LOG == 2,
	       "seccomp_modes follows the enum");

static int no_require_off(const bst_directive *d, bst_err *e)
{
	bst_err_set(e, "\"%s off require\" asks for nothing: drop one of the two", d->name);
	return -1;
}

static int ap_seccomp(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	size_t idx = 0;
	bst_cfg_sandbox *s = &c->global->sandbox;
	if (bst_parse_enum(as_str(bst_dir_pos(d, n, 0)), seccomp_modes, &idx)) /* validated */
		s->seccomp = (bst_seccomp_mode)idx;
	s->seccomp_require = bst_dir_has_require(d, n);
	if (s->seccomp == BST_SECCOMP_OFF && s->seccomp_require)
		return no_require_off(d, e);
	if (s->seccomp == BST_SECCOMP_OFF)
		bst_cfg_warn(c, n, "seccomp off: a compromised worker can make any syscall");
	if (s->seccomp == BST_SECCOMP_LOG)
		bst_cfg_warn(c, n, "seccomp log: forbidden syscalls run and are only recorded; "
			     "this is for debugging");
	return 0;
}

/* on|off [require] */
static int step(const bst_directive *d, const bst_ast_node *n, bool *on, bool *require, bst_err *e)
{
	bool v = false;
	if (bst_parse_bool(as_str(bst_dir_pos(d, n, 0)), &v)) /* validated */
		*on = v;
	*require = bst_dir_has_require(d, n);
	return !*on && *require ? no_require_off(d, e) : 0;
}

static int ap_landlock(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_sandbox *s = &c->global->sandbox;
	return step(d, n, &s->landlock, &s->landlock_require, e);
}

static int ap_namespaces(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_sandbox *s = &c->global->sandbox;
	return step(d, n, &s->namespaces, &s->namespaces_require, e);
}

static int ap_drop_caps(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_sandbox *s = &c->global->sandbox;
	return step(d, n, &s->drop_caps, &s->drop_caps_require, e);
}

static int add_path(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
		    const char ***arr, size_t *cnt, size_t *cap, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	if (a->text[0] != '/') {
		bst_err_set(e, "\"%s\" needs an absolute path", d->name);
		return -1;
	}
	const char *copy = bst_cfg_strdup(c, a->text, a->len, e);
	if (copy == NULL)
		return -1;
	return bst_cfg_push_owned(c, arr, cnt, cap, sizeof copy, &copy, e);
}

static int ap_extra_read(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_sandbox *s = &c->global->sandbox;
	return add_path(c, d, n, &s->extra_read, &s->nextra_read, &s->extra_read_cap_, e);
}

static int ap_extra_write(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_sandbox *s = &c->global->sandbox;
	return add_path(c, d, n, &s->extra_write, &s->nextra_write, &s->extra_write_cap_, e);
}

#define SB1(...) .args = { .min_args = 1, .max_args = 1, .pos = { __VA_ARGS__ } }

static const bst_directive sandbox_dirs[] = {
	{ .name = "sandbox", .contexts = BST_CTX_GLOBAL, .apply = ap_sandbox, .singleton = true,
	  .child_ctx = BST_CTX_SANDBOX,
	  .doc = "What contains a compromised worker or helper; master stays outside it. Every "
		 "default applies when the block is absent.",
	  .args = { .block = BST_BLOCK_REQUIRED } },
	{ .name = "seccomp", .contexts = BST_CTX_SANDBOX, .apply = ap_seccomp, .default_value = "on",
	  .require = true,
	  .doc = "Syscall allowlist, per role, on every thread. on kills the process on anything "
		 "else; log lets it run and records it in the kernel audit log, for debugging a "
		 "missing entry; off has no filter. On a kernel without seccomp filters it warns "
		 "and starts; add `require` to make that a startup error.",
	  SB1({ .kind = BST_T_ENUM, .enum_values = seccomp_modes }) },
	{ .name = "landlock", .contexts = BST_CTX_SANDBOX, .apply = ap_landlock,
	  .default_value = "on", .require = true,
	  .doc = "Limits file access to the serving roots and extra_read, read only, and the cache, "
		 "temp and extra_write directories, read and write. Log files need no rule: each "
		 "process holds its own open description. On a kernel without Landlock it warns and "
		 "starts; add `require` to make that a startup error.",
	  SB1({ .kind = BST_T_BOOL }) },
	{ .name = "namespaces", .contexts = BST_CTX_SANDBOX, .apply = ap_namespaces,
	  .default_value = "off", .require = true,
	  .doc = "Runs each worker and the helper in mount, PID, IPC and UTS namespaces of its own, "
		 "with a private root holding only the serving roots, the cache and temp directories "
		 "and the extra_ paths. Needs root in master. Log lines from a child then say pid 1. "
		 "Where a namespace is not permitted it warns and starts; add `require` to make that "
		 "a startup error.",
	  SB1({ .kind = BST_T_BOOL }) },
	{ .name = "drop_capabilities", .contexts = BST_CTX_SANDBOX, .apply = ap_drop_caps,
	  .default_value = "on", .require = true,
	  .doc = "Clears every capability set of every thread, bounding, ambient and inheritable "
		 "included, whether or not `user` changes the uid. Emptying the bounding set needs "
		 "master to start as root; otherwise it warns, and `require` makes that a startup "
		 "error.",
	  SB1({ .kind = BST_T_BOOL }) },
	{ .name = "extra_read", .contexts = BST_CTX_SANDBOX, .apply = ap_extra_read,
	  .repeatable = true,
	  .doc = "An absolute path workers and the helper may read, on top of the serving roots. A "
		 "path that does not exist at start gets no access, with a warning.",
	  SB1({ .kind = BST_T_PATH }) },
	{ .name = "extra_write", .contexts = BST_CTX_SANDBOX, .apply = ap_extra_write,
	  .repeatable = true,
	  .doc = "An absolute path workers and the helper may read and write, on top of the cache "
		 "and temp directories. A path that does not exist at start gets no access, with a "
		 "warning.",
	  SB1({ .kind = BST_T_PATH }) },
};
BST_DIRECTIVES(sandbox_dirs);
