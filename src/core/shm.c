#include "core/shm.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef MFD_NOEXEC_SEAL
#define BST_MFD_NOEXEC_SEAL MFD_NOEXEC_SEAL
#else
#define BST_MFD_NOEXEC_SEAL 0x0008U
#endif

void *bst_shm_create(const char *name, size_t size, int *fd_out)
{
	if (size == 0) {
		errno = EINVAL;
		return NULL;
	}
	/* MFD_NOEXEC_SEAL (Linux 6.3) keeps the memory from ever becoming executable; a 6.1
	 * kernel rejects the unknown flag with EINVAL, so fall back to the plain call. */
	int fd = memfd_create(name, MFD_CLOEXEC | MFD_ALLOW_SEALING | BST_MFD_NOEXEC_SEAL);
	if (fd < 0 && errno == EINVAL)
		fd = memfd_create(name, MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (fd < 0)
		return NULL;
	/* F_SEAL_SEAL last: nobody, including a process that receives the fd, can add seals
	 * or lift the size guarantee later. */
	if (ftruncate(fd, (off_t)size) != 0 ||
	    fcntl(fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) != 0)
		goto fail;
	void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED)
		goto fail;
	if (fd_out)
		*fd_out = fd;
	else
		close(fd);
	return p;
fail:;
	int e = errno;
	close(fd);
	errno = e;
	return NULL;
}

void *bst_shm_attach(int fd, size_t size)
{
	struct stat st;
	if (size == 0 || fstat(fd, &st) != 0)
		return NULL;
	if (st.st_size < 0 || (unsigned long long)st.st_size != size) {
		errno = EINVAL;
		return NULL;
	}
	void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	return p == MAP_FAILED ? NULL : p;
}

/* ---- regions that survive a reload ---- */

typedef struct kept {
	char name[32];
	int fd;
	bool used; /* inherited: taken by a create */
} kept;

static kept g_kept[BST_SHM_KEPT_MAX];
static size_t g_nkept;
static const void *g_kept_at[BST_SHM_KEPT_MAX]; /* where each kept region is mapped */
static kept g_inh[BST_SHM_KEPT_MAX];
static size_t g_ninh;

static void copy_name(char *dst, const char *src)
{
	size_t i = 0;
	for (; src[i] != 0 && i + 1 < sizeof g_kept[0].name; i++)
		dst[i] = src[i];
	dst[i] = 0;
}

void bst_shm_inherited_add(const char *name, int fd)
{
	if (g_ninh == BST_SHM_KEPT_MAX) {
		close(fd);
		return;
	}
	copy_name(g_inh[g_ninh].name, name);
	g_inh[g_ninh].fd = fd;
	g_inh[g_ninh++].used = false;
}

void bst_shm_inherited_close_untaken(void)
{
	for (size_t i = 0; i < g_ninh; i++)
		if (!g_inh[i].used && g_inh[i].fd >= 0) {
			close(g_inh[i].fd);
			g_inh[i].fd = -1;
		}
}

static bool same_name(const char *a, const char *b)
{
	char c[sizeof g_kept[0].name];
	copy_name(c, b);
	for (size_t i = 0;; i++) {
		if (a[i] != c[i])
			return false;
		if (a[i] == 0)
			return true;
	}
}

void *bst_shm_create_kept(const char *name, size_t size, bool *reused)
{
	*reused = false;
	if (g_nkept == BST_SHM_KEPT_MAX) {
		errno = ENOSPC;
		return NULL;
	}
	void *p = NULL;
	int fd = -1;
	for (size_t i = 0; i < g_ninh; i++) {
		if (g_inh[i].used || g_inh[i].fd < 0 || !same_name(g_inh[i].name, name))
			continue;
		p = bst_shm_attach(g_inh[i].fd, size);
		if (p == NULL)
			continue; /* another size: the layout changed, start fresh */
		g_inh[i].used = true;
		fd = g_inh[i].fd;
		(void)fcntl(fd, F_SETFD, FD_CLOEXEC);
		*reused = true;
		break;
	}
	if (p == NULL)
		p = bst_shm_create(name, size, &fd);
	if (p == NULL)
		return NULL;
	copy_name(g_kept[g_nkept].name, name);
	g_kept_at[g_nkept] = p;
	g_kept[g_nkept].fd = fd;
	g_kept[g_nkept++].used = true;
	return p;
}

bool bst_shm_kept_get(size_t i, const char **name, int *fd)
{
	if (i >= g_nkept)
		return false;
	*name = g_kept[i].name;
	*fd = g_kept[i].fd;
	return true;
}

int bst_shm_kept_fd(const void *p)
{
	for (size_t i = 0; i < g_nkept; i++)
		if (g_kept_at[i] == p)
			return g_kept[i].fd;
	return -1;
}

/* ---- regions children only read ---- */

typedef struct ro_region {
	void *rw;
	size_t size;
	bool helper_writes;
} ro_region;

static ro_region g_ro[BST_SHM_RO_MAX];
static size_t g_nro;

const void *bst_shm_ro_view(void *rw, int fd, size_t size, bool helper_writes)
{
	if (rw == NULL || fd < 0 || size == 0) {
		errno = EINVAL;
		return NULL;
	}
	if (g_nro == BST_SHM_RO_MAX) {
		errno = ENOSPC;
		return NULL;
	}
	char path[48];
	snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
	int rfd = open(path, O_RDONLY | O_CLOEXEC);
	if (rfd < 0)
		return NULL;
	void *ro = mmap(NULL, size, PROT_READ, MAP_SHARED, rfd, 0);
	int e = errno;
	close(rfd);
	if (ro == MAP_FAILED) {
		errno = e;
		return NULL;
	}
	g_ro[g_nro++] = (ro_region){ .rw = rw, .size = size, .helper_writes = helper_writes };
	return ro;
}

void bst_shm_child_readonly(bool helper)
{
	for (size_t i = 0; i < g_nro; i++) {
		if (helper && g_ro[i].helper_writes)
			continue;
		if (g_ro[i].rw != NULL)
			(void)munmap(g_ro[i].rw, g_ro[i].size);
		g_ro[i].rw = NULL;
	}
}
