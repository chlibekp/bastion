/* Fixed thread pool. All job nodes are allocated once (queue-depth of them), so submit
 * never allocates and the pool can never hold more than that many jobs. A node moves
 * free -> pending -> (running, owned by a worker) -> finished -> free. */
#include "io/aio.h"

#include "io/loop_priv.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

typedef struct aio_job {
	struct aio_job *next;
	void (*work)(void *);
	void (*done)(void *);
	void *arg;
} aio_job;

typedef struct {
	aio_job *head, *tail;
} jlist;

struct bst_aio {
	bst_loop *loop;
	pthread_mutex_t mu;
	pthread_cond_t cv;
	aio_job *nodes;
	aio_job *free;
	jlist pending, finished;
	pthread_t *th;
	unsigned started;
	unsigned ready; /* threads past fault_setup (under mu) */
	pthread_cond_t up;
	bool stopping;
	/* bst_aio_each_thread, under mu: a new generation is one call of fn on every thread */
	void (*each_fn)(void *);
	void *each_arg;
	unsigned each_gen, each_done;
};

#ifdef BST_TEST
/* Test seams: BST_TEST_AIO_SETUP_DELAY_MS holds each thread back before its setup, and the
 * counter is how many finished it, so a test can see bst_aio_new_ returning too early. */
atomic_uint bst_test_aio_setup_done;
static void test_setup_delay(void)
{
	const char *d = getenv("BST_TEST_AIO_SETUP_DELAY_MS");
	if (d != NULL) {
		struct timespec ts = {.tv_sec = 0, .tv_nsec = atol(d) * 1000000L};
		nanosleep(&ts, NULL);
	}
}
#endif

static void push(jlist *q, aio_job *j)
{
	j->next = NULL;
	if (q->tail != NULL)
		q->tail->next = j;
	else
		q->head = j;
	q->tail = j;
}

static aio_job *pop(jlist *q)
{
	aio_job *j = q->head;
	if (j != NULL) {
		q->head = j->next;
		if (q->head == NULL)
			q->tail = NULL;
	}
	return j;
}

/* Pool threads block every signal, and a fault taken while blocked is forced to the default
 * disposition, past the crash handler. So a thread lets faults through, and has a stack of its
 * own for the handler: a stack overflow here must be reported too. All disk and CPU-heavy work
 * runs on these threads. Nothing to do when the process installed no handler. */
static void *fault_setup(stack_t *old)
{
	sigset_t faults;
	sigemptyset(&faults);
	sigaddset(&faults, SIGSEGV);
	sigaddset(&faults, SIGBUS);
	sigaddset(&faults, SIGILL);
	sigaddset(&faults, SIGFPE);
	sigaddset(&faults, SIGABRT);
	pthread_sigmask(SIG_UNBLOCK, &faults, NULL);
	void *mem = mmap(NULL, BST_AIO_ALTSTACK, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED)
		return NULL;
	stack_t ss = {.ss_sp = mem, .ss_size = BST_AIO_ALTSTACK, .ss_flags = 0};
	if (sigaltstack(&ss, old) != 0) {
		munmap(mem, BST_AIO_ALTSTACK);
		return NULL;
	}
	return mem;
}

/* Back to what the thread had: a sanitizer's own stack, which it frees at thread exit. */
static void fault_teardown(void *mem, const stack_t *old)
{
	if (mem == NULL)
		return;
	sigaltstack(old, NULL);
	munmap(mem, BST_AIO_ALTSTACK);
}

static void *worker(void *p)
{
	struct bst_aio *a = p;
	stack_t old_stack;
#ifdef BST_TEST
	test_setup_delay();
#endif
	void *fault_stack = fault_setup(&old_stack);
#ifdef BST_TEST
	atomic_fetch_add(&bst_test_aio_setup_done, 1);
#endif
	unsigned each_seen = 0;
	pthread_mutex_lock(&a->mu);
	a->ready++;
	pthread_cond_broadcast(&a->up);
	for (;;) {
		if (each_seen != a->each_gen) {
			each_seen = a->each_gen;
			void (*fn)(void *) = a->each_fn;
			void *arg = a->each_arg;
			pthread_mutex_unlock(&a->mu);
			fn(arg);
			pthread_mutex_lock(&a->mu);
			a->each_done++;
			pthread_cond_broadcast(&a->up);
			continue;
		}
		aio_job *j = pop(&a->pending);
		if (j == NULL) {
			if (a->stopping)
				break; /* the queue is drained before a worker exits */
			pthread_cond_wait(&a->cv, &a->mu);
			continue;
		}
		pthread_mutex_unlock(&a->mu);
		j->work(j->arg);
		pthread_mutex_lock(&a->mu);
		push(&a->finished, j);
		pthread_mutex_unlock(&a->mu);
		bst_loop_wake(a->loop);
		pthread_mutex_lock(&a->mu);
	}
	pthread_mutex_unlock(&a->mu);
	fault_teardown(fault_stack, &old_stack);
	return NULL;
}

/* Runs on the loop thread (bst_loop_woken_) and from bst_aio_free_. Each node goes back to
 * the free list before its done runs, so done may submit again. */
void bst_aio_drain_(struct bst_aio *a)
{
	for (;;) {
		pthread_mutex_lock(&a->mu);
		aio_job *j = pop(&a->finished);
		void (*done)(void *) = NULL;
		void *arg = NULL;
		if (j != NULL) {
			done = j->done;
			arg = j->arg;
			j->next = a->free;
			a->free = j;
		}
		pthread_mutex_unlock(&a->mu);
		if (j == NULL)
			return;
		if (done != NULL)
			done(arg);
	}
}

struct bst_aio *bst_aio_new_(bst_loop *l, const bst_loop_cfg *cfg, bst_err *err)
{
	unsigned nt = cfg != NULL ? cfg->aio_threads : 0;
	unsigned nq = cfg != NULL ? cfg->aio_queue : 0;
	nt = nt == 0 ? BST_AIO_THREADS_DEFAULT : (nt > BST_AIO_THREADS_MAX ? BST_AIO_THREADS_MAX : nt);
	nq = nq == 0 ? BST_AIO_QUEUE_DEFAULT : (nq > BST_AIO_QUEUE_MAX ? BST_AIO_QUEUE_MAX : nq);
	struct bst_aio *a = calloc(1, sizeof *a);
	if (a == NULL) {
		bst_err_set(err, "out of memory");
		return NULL;
	}
	a->loop = l;
	a->nodes = calloc(nq, sizeof *a->nodes);
	a->th = calloc(nt, sizeof *a->th);
	if (a->nodes == NULL || a->th == NULL) {
		bst_err_set(err, "out of memory");
		goto fail_mem;
	}
	for (unsigned i = 0; i < nq; i++) {
		a->nodes[i].next = a->free;
		a->free = &a->nodes[i];
	}
	pthread_mutex_init(&a->mu, NULL);
	pthread_cond_init(&a->cv, NULL);
	pthread_cond_init(&a->up, NULL);
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, BST_AIO_STACK_SIZE);
	/* Workers must not take process signals: create them with everything blocked. A fault is the
	 * exception, and each thread lets those through when it starts (fault_setup). */
	sigset_t all, old;
	sigfillset(&all);
	pthread_sigmask(SIG_SETMASK, &all, &old);
	int rc = 0;
	for (; a->started < nt; a->started++) {
		rc = pthread_create(&a->th[a->started], &attr, worker, a);
		if (rc != 0)
			break;
	}
	pthread_sigmask(SIG_SETMASK, &old, NULL);
	pthread_attr_destroy(&attr);
	if (rc != 0) {
		bst_err_set(err, "pthread_create: %s", strerror(rc));
		bst_aio_free_(a);
		return NULL;
	}
	/* A sandbox follows this call and forbids mmap and sigaltstack: every thread must be done
	 * with its setup first. Bounded, so a wedged thread is an error, not a hang. */
	struct timespec dl;
	clock_gettime(CLOCK_REALTIME, &dl);
	dl.tv_sec += BST_AIO_READY_TIMEOUT_S;
	pthread_mutex_lock(&a->mu);
	while (a->ready < a->started && rc == 0)
		rc = pthread_cond_timedwait(&a->up, &a->mu, &dl);
	pthread_mutex_unlock(&a->mu);
	if (rc != 0) {
		bst_err_set(err, "pool threads not ready: %s", strerror(rc));
		bst_aio_free_(a);
		return NULL;
	}
	return a;
fail_mem:
	free(a->nodes);
	free(a->th);
	free(a);
	return NULL;
}

int bst_aio_each_thread(bst_loop *l, void (*fn)(void *), void *arg)
{
	struct bst_aio *a = l->aio;
	if (a == NULL)
		return 0;
	struct timespec dl;
	clock_gettime(CLOCK_REALTIME, &dl);
	dl.tv_sec += BST_AIO_READY_TIMEOUT_S;
	int rc = 0;
	pthread_mutex_lock(&a->mu);
	a->each_fn = fn;
	a->each_arg = arg;
	a->each_done = 0;
	a->each_gen++;
	pthread_cond_broadcast(&a->cv);
	while (a->each_done < a->started && rc == 0)
		rc = pthread_cond_timedwait(&a->up, &a->mu, &dl);
	pthread_mutex_unlock(&a->mu);
	return -rc;
}

void bst_aio_free_(struct bst_aio *a)
{
	if (a == NULL)
		return;
	pthread_mutex_lock(&a->mu);
	a->stopping = true;
	pthread_cond_broadcast(&a->cv);
	pthread_mutex_unlock(&a->mu);
	for (unsigned i = 0; i < a->started; i++)
		pthread_join(a->th[i], NULL);
	/* Workers finished every queued job; their done callbacks run here. */
	bst_aio_drain_(a);
	pthread_mutex_destroy(&a->mu);
	pthread_cond_destroy(&a->cv);
	pthread_cond_destroy(&a->up);
	free(a->nodes);
	free(a->th);
	free(a);
}

int bst_aio_submit(bst_loop *l, void (*work)(void *), void (*done)(void *), void *arg)
{
	struct bst_aio *a = l->aio;
	if (work == NULL)
		return -EINVAL;
	if (a == NULL)
		return -ESHUTDOWN;
	pthread_mutex_lock(&a->mu);
	if (a->stopping) {
		pthread_mutex_unlock(&a->mu);
		return -ESHUTDOWN;
	}
	aio_job *j = a->free;
	if (j == NULL) {
		pthread_mutex_unlock(&a->mu);
		return -EAGAIN;
	}
	a->free = j->next;
	j->work = work;
	j->done = done;
	j->arg = arg;
	push(&a->pending, j);
	pthread_cond_signal(&a->cv);
	pthread_mutex_unlock(&a->mu);
	return 0;
}
