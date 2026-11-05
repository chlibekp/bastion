/* Fixed thread pool. All job nodes are allocated once (queue-depth of them), so submit
 * never allocates and the pool can never hold more than that many jobs. A node moves
 * free -> pending -> (running, owned by a worker) -> finished -> free. */
#include "io/aio.h"

#include "io/loop_priv.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

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
	bool stopping;
};

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

static void *worker(void *p)
{
	struct bst_aio *a = p;
	pthread_mutex_lock(&a->mu);
	for (;;) {
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
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, BST_AIO_STACK_SIZE);
	/* Workers must not take process signals: create them with everything blocked. */
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
	return a;
fail_mem:
	free(a->nodes);
	free(a->th);
	free(a);
	return NULL;
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
