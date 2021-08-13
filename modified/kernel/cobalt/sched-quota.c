/*
 * Copyright (C) 2013 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include <linux/bitmap.h>
#include <cobalt/kernel/sched.h>
#include <cobalt/kernel/arith.h>
#include <cobalt/uapi/sched.h>
#include <trace/events/cobalt-core.h>

/*
 * With this policy, each per-CPU scheduler slot maintains a list of
 * active thread groups, picking from the sched_rt runqueue.
 *
 * Each time a thread is picked from the runqueue, we check whether we
 * still have budget for running it, looking at the group it belongs
 * to. If so, a timer is armed to elapse when that group has no more
 * budget, would the incoming thread run unpreempted until then
 * (i.e. xnsched_quota->limit_timer).
 *
 * Otherwise, if no budget remains in the group for running the
 * candidate thread, we move the latter to a local expiry queue
 * maintained by the group. This process is done on the fly as we pull
 * from the runqueue.
 *
 * Updating the remaining budget is done each time the Cobalt core
 * asks for replacing the current thread with the next runnable one,
 * i.e. xnsched_quota_pick(). There we charge the elapsed run time of
 * the outgoing thread to the relevant group, and conversely, we check
 * whether the incoming thread has budget.
 *
 * Finally, a per-CPU timer (xnsched_quota->refill_timer) periodically
 * ticks in the background, in accordance to the defined quota
 * interval. Thread group budgets get replenished by its handler in
 * accordance to their respective share, pushing all expired threads
 * back to the run queue in the same move.
 *
 * NOTE: since the core logic enforcing the budget entirely happens in
 * xnsched_quota_pick(), applying a budget change can be done as
 * simply as forcing the rescheduling procedure to be invoked asap. As
 * a result of this, the Cobalt core will ask for the next thread to
 * run, which means calling xnsched_quota_pick() eventually.
 *
 * CAUTION: xnsched_quota_group->nr_active does count both the threads
 * from that group linked to the sched_rt runqueue, _and_ the threads
 * moved to the local expiry queue. As a matter of fact, the expired
 * threads - those for which we consumed all the per-group budget -
 * are still seen as runnable (i.e. not blocked/suspended) by the
 * Cobalt core. This only means that the SCHED_QUOTA policy won't pick
 * them until the corresponding budget is replenished.
 */

static DECLARE_BITMAP(group_map, CONFIG_XENO_OPT_SCHED_QUOTA_NR_GROUPS);

//diamo una mano al caching e al compilatore ... quel codice non verrà mai usato
static inline void replenish_budget(struct xnsched_quota_group *tg)
{
	tg->run_budget_ns = tg->quota_ns;
}

static void quota_refill_handler(struct xntimer *timer)
{
	struct xnsched_quota_group *tg, *tmp;
	struct xnsched_quota *qs;
	struct xnsched *sched;

	qs = container_of(timer, struct xnsched_quota, refill_timer);
	XENO_BUG_ON(COBALT, list_empty(&qs->groups));
	sched = container_of(qs, struct xnsched, quota);
	qs->replenished = true;

	trace_cobalt_schedquota_refill(0);

	list_for_each_entry(tg, &qs->groups, next) {
		/* Allot a new runtime budget for the group. */
		replenish_budget(tg);
	}
	/*
	* For each group living on this CPU, move all groups
	* back to the runqueue. Since those groups
	* were moved out of the runqueue as we were
	* considering them for execution, we push them back
	* in LIFO order to their respective priority group.
	* The expiry queue is FIFO to keep ordering right
	* among expired groups.
	*/
	if(!list_empty(&qs->expired)) {
		list_for_each_entry_safe_reverse(tg, tmp, &qs->expired, quota_expired) {
			list_del_init(&tg->quota_expired);
			list_add_prilf(tg, &qs->runnable, cprio, rlink);
		}
	}

	xnsched_set_self_resched(timer->sched);
}

static void quota_limit_handler(struct xntimer *timer)
{
	struct xnsched *sched;

	sched = container_of(timer, struct xnsched, quota.limit_timer);
	/*
	 * Force a rescheduling on the return path of the current
	 * interrupt, so that the budget is re-evaluated for the
	 * current group in xnsched_quota_pick().
	 */
	xnsched_set_self_resched(sched);
}

static int quota_sum_all(struct xnsched_quota *qs)
{
	struct xnsched_quota_group *tg;
	int sum;

	if (list_empty(&qs->groups))
		return 0;

	sum = 0;
	list_for_each_entry(tg, &qs->groups, next)
		sum += tg->quota_percent;

	return sum;
}

static void xnsched_quota_init(struct xnsched *sched)
{
	char limiter_name[XNOBJECT_NAME_LEN], refiller_name[XNOBJECT_NAME_LEN];
	struct xnsched_quota *qs = &sched->quota;

	qs->period_ns = CONFIG_XENO_OPT_SCHED_QUOTA_PERIOD * 1000ULL;
	qs->replenished = false;
	INIT_LIST_HEAD(&qs->groups);
	INIT_LIST_HEAD(&qs->expired);
	INIT_LIST_HEAD(&qs->runnable);

#ifdef CONFIG_SMP
	ksformat(refiller_name, sizeof(refiller_name),
		 "[quota-refill/%u]", sched->cpu);
	ksformat(limiter_name, sizeof(limiter_name),
		 "[quota-limit/%u]", sched->cpu);
#else
	strcpy(refiller_name, "[quota-refill]");
	strcpy(limiter_name, "[quota-limit]");
#endif
	xntimer_init(&qs->refill_timer,
		     &nkclock, quota_refill_handler, sched,
		     XNTIMER_IGRAVITY);
	xntimer_set_name(&qs->refill_timer, refiller_name);

	xntimer_init(&qs->limit_timer,
		     &nkclock, quota_limit_handler, sched,
		     XNTIMER_IGRAVITY);
	xntimer_set_name(&qs->limit_timer, limiter_name);
}

static bool xnsched_quota_setparam(struct xnthread *thread,
				   const union xnsched_policy_param *p)
{
	struct xnsched_quota_group *tg;
	struct xnsched_quota *qs;
	bool effective;

	xnthread_clear_state(thread, XNWEAK);
	effective = xnsched_set_effective_priority(thread, p->quota.prio);

	qs = &thread->sched->quota;
	list_for_each_entry(tg, &qs->groups, next) {
		if (tg->tgid != p->quota.tgid)
			continue;
		if (thread->quota) {
			/* Dequeued earlier by our caller. */
			list_del(&thread->quota_next);
			thread->quota->nr_threads--;
		}

		trace_cobalt_schedquota_add_thread(tg, thread);

		thread->quota = tg;
		list_add(&thread->quota_next, &tg->members);
		tg->nr_threads++;
		return effective;
	}

	XENO_BUG(COBALT);

	return false;
}

static void xnsched_quota_getparam(struct xnthread *thread,
				   union xnsched_policy_param *p)
{
	p->quota.prio = thread->cprio;
	p->quota.tgid = thread->quota->tgid;
}

static void xnsched_quota_trackprio(struct xnthread *thread,
				    const union xnsched_policy_param *p)
{
	if (p) {
		/* We should not cross groups during PI boost. */
		XENO_WARN_ON(COBALT,
			     thread->base_class == &xnsched_class_quota &&
			     thread->quota->tgid != p->quota.tgid);
		thread->cprio = p->quota.prio;
	} else
		thread->cprio = thread->bprio;
}

static void xnsched_quota_protectprio(struct xnthread *thread, int prio)
{
	if (prio > XNSCHED_QUOTA_MAX_PRIO)
		prio = XNSCHED_QUOTA_MAX_PRIO;

	thread->cprio = prio;
}

static int xnsched_quota_chkparam(struct xnthread *thread,
				  const union xnsched_policy_param *p)
{
	struct xnsched_quota_group *tg;
	struct xnsched_quota *qs;
	int tgid;

	if (p->quota.prio < XNSCHED_QUOTA_MIN_PRIO ||
	    p->quota.prio > XNSCHED_QUOTA_MAX_PRIO)
		return -EINVAL;

	tgid = p->quota.tgid;
	if (tgid < 0 || tgid >= CONFIG_XENO_OPT_SCHED_QUOTA_NR_GROUPS)
		return -EINVAL;

	/*
	 * The group must be managed on the same CPU the thread
	 * currently runs on.
	 */
	qs = &thread->sched->quota;
	list_for_each_entry(tg, &qs->groups, next) {
		if (tg->tgid == tgid)
			return 0;
	}

	/*
	 * If that group exists nevertheless, we give userland a
	 * specific error code.
	 */
	if (test_bit(tgid, group_map))
		return -EPERM;

	return -EINVAL;
}

static void xnsched_quota_forget(struct xnthread *thread)
{
	trace_cobalt_schedquota_remove_thread(thread->quota, thread);

	thread->quota->nr_threads--;
	XENO_BUG_ON(COBALT, thread->quota->nr_threads < 0);
	list_del(&thread->quota_next);
	thread->quota = NULL;
}

static void xnsched_quota_enqueue(struct xnthread *thread)
{
	struct xnsched_quota_group *tg = thread->quota;
	struct xnsched *sched = thread->sched;

	xnsched_addq_tail(&tg->runnable, thread); 
	/* 
	* if the group wasn't active and now it becomes active, either it has 
	* budget to run (likely) thus we enqueue to runnable queue, or it's 
	* expired because of a former execution, thus	we add to expired list
	*/
	if ((!tg->nr_active) && (!tg->enqueued)) {
		tg->enqueued = 1;
		if(tg->run_budget_ns > 0) {
			list_add_priff(tg, &sched->quota.runnable, cprio, rlink);
		} else {
			list_add_tail(&tg->quota_expired, &sched->quota.expired);
		}
	}
	tg->nr_active++;
}

static void xnsched_quota_dequeue(struct xnthread *thread)
{
	struct xnsched_quota_group *tg = thread->quota;

	xnsched_delq(&tg->runnable, thread);

	tg->nr_active--;
	/* 
	* if there was a thread active in the group and now it's empty it means 
	* that either the group was active and waiting for the CPU, thus we remove 
	* it from the runnable queue or it's expired , thus we remove  it from 
	* expired list. To be expired, group expire_quota must be not empty 
	*/ 
	if ((!tg->nr_active) && (tg->enqueued)) {
		tg->enqueued = 0;
		if(!list_empty(&tg->quota_expired)) {
			list_del_init(&tg->quota_expired);
		} else {
			list_del(&tg->rlink);
		}
	}
}

static void xnsched_quota_requeue(struct xnthread *thread)
{
	struct xnsched_quota_group *tg = thread->quota;
	struct xnsched *sched = thread->sched;

	xnsched_addq(&tg->runnable, thread);

	if ((!tg->nr_active) && (!tg->enqueued)) {
		tg->enqueued = 1;
		if(tg->run_budget_ns) {
			list_add_prilf(tg, &sched->quota.runnable, cprio, rlink);
		} else {
			list_add_tail(&tg->quota_expired, &sched->quota.expired);
		}
	}
	tg->nr_active++;
}

#define xnsched_first_entry_group(__q)							\
	({									\
		struct xnsched_quota_group *__t = NULL;					\
		if (!list_empty(__q))						\
			__t = list_first_entry(__q, struct xnsched_quota_group, rlink);	\
		__t;								\
	})

static struct xnthread *xnsched_quota_pick(struct xnsched *sched)
{
	struct xnthread *next, *curr = sched->curr;
	struct xnsched_quota *qs = &sched->quota;
	struct xnsched_quota_group *otg, *tg;
	xnticks_t now, elapsed;
	int ret;

	now = xnclock_read_monotonic(&nkclock);
	otg = curr->quota;
	if (otg == NULL || qs->replenished)
		goto pick;
	/*
	 * Charge the time consumed by the outgoing thread to the
	 * group it belongs to.
	 */
	elapsed = now - otg->run_start_ns;
	if (elapsed < otg->run_budget_ns)
		otg->run_budget_ns -= elapsed;
	else
		otg->run_budget_ns = 0;

pick:
	tg = xnsched_first_entry_group(&qs->runnable);

	if (unlikely(tg == NULL)) {
		xntimer_stop(&qs->limit_timer);
		return NULL;
	}

	if (tg-> nr_active == 0) {
		list_del(&tg->rlink);
		tg->enqueued = 0;
		goto pick;
	}

	if (tg->run_budget_ns == 0) {
		/* Flush expired group as we go. */
		list_del(&tg->rlink);
		list_add_tail(&tg->quota_expired, &qs->expired);
		goto pick;
	}

	tg->run_start_ns = now;
	next = xnsched_getq(&tg->runnable);

	if (otg == tg && xntimer_running_p(&qs->limit_timer) && (!qs->replenished))
		/* Same group, leave the running timer untouched. */
		goto out;

	qs->replenished = false;
	/* Arm limit timer for the new running group. */
	ret = xntimer_start(&qs->limit_timer, now + tg->run_budget_ns,
			    XN_INFINITE, XN_ABSOLUTE);
	if (ret) {
		/* Budget exhausted: deactivate this group, requeue took thread and move group. */
		tg->run_budget_ns = 0;
		xnsched_addq(&tg->runnable, next);
		list_del(&tg->rlink);
		list_add_tail(&tg->quota_expired, &qs->expired);
		goto pick;
	}
out:
	tg->nr_active--;

	return next;
}

static void xnsched_quota_migrate(struct xnthread *thread, struct xnsched *sched)
{
	union xnsched_policy_param param;
	/*
	 * Runtime quota groups are defined per-CPU, so leaving the
	 * current CPU means exiting the group. We do this by moving
	 * the target thread to the plain RT class.
	 */
	param.rt.prio = thread->cprio;
	__xnthread_set_schedparam(thread, &xnsched_class_rt, &param);
}

/**
 * @ingroup cobalt_core_sched
 * @defgroup sched_quota SCHED_QUOTA scheduling policy
 *
 * The SCHED_QUOTA policy enforces a limitation on the CPU consumption
 * of threads over a globally defined period, known as the quota
 * interval. This is done by pooling threads with common requirements
 * in groups, and giving each group a share of the global period
 * (CONFIG_XENO_OPT_SCHED_QUOTA_PERIOD).
 *
 * When threads have entirely consumed the quota allotted to the group
 * they belong to, the latter is suspended as a whole, until the next
 * quota interval starts. At this point, a new runtime budget is
 * given to each group, in accordance with its share.
 *
 *@{
 */
int xnsched_quota_create_group(struct xnsched_quota_group *tg,
			       struct xnsched *sched,
			       int *quota_sum_r)
{
	int tgid, nr_groups = CONFIG_XENO_OPT_SCHED_QUOTA_NR_GROUPS;
	struct xnsched_quota *qs = &sched->quota;

	atomic_only();

	tgid = find_first_zero_bit(group_map, nr_groups);
	if (tgid >= nr_groups)
		return -ENOSPC;

	__set_bit(tgid, group_map);
	tg->tgid = tgid;
	tg->sched = sched;
	tg->run_budget_ns = qs->period_ns;
	tg->run_credit_ns = 0;
	tg->quota_percent = 100;
	tg->quota_peak_percent = 100;
	tg->quota_ns = qs->period_ns;
	tg->quota_peak_ns = qs->period_ns;
	tg->nr_active = 0;
	tg->nr_threads = 0;
	tg->cprio = XNSCHED_QUOTA_MIN_PRIO;
	tg->enqueued = 0;

	INIT_LIST_HEAD(&tg->members);
	xnsched_initq(&tg->runnable);
	INIT_LIST_HEAD(&tg->quota_expired);

	trace_cobalt_schedquota_create_group(tg);

	if (list_empty(&qs->groups))
		xntimer_start(&qs->refill_timer,
			      qs->period_ns, qs->period_ns, XN_RELATIVE);

	list_add(&tg->next, &qs->groups);
	*quota_sum_r = quota_sum_all(qs);

	return 0;
}
EXPORT_SYMBOL_GPL(xnsched_quota_create_group);

int xnsched_quota_destroy_group(struct xnsched_quota_group *tg,
				int force, int *quota_sum_r)
{
	struct xnsched_quota *qs = &tg->sched->quota;
	union xnsched_policy_param param;
	struct xnthread *thread, *tmp;

	atomic_only();

	if (!list_empty(&tg->members)) {
		if (!force)
			return -EBUSY;
		/* Move group members to the rt class. */
		list_for_each_entry_safe(thread, tmp, &tg->members, quota_next) {
			param.rt.prio = thread->cprio;
			__xnthread_set_schedparam(thread, &xnsched_class_rt, &param);
		}
	}

	trace_cobalt_schedquota_destroy_group(tg);

	list_del(&tg->next);
	__clear_bit(tg->tgid, group_map);

	if (list_empty(&qs->groups))
		xntimer_stop(&qs->refill_timer);

	if (quota_sum_r)
		*quota_sum_r = quota_sum_all(qs);

	return 0;
}
EXPORT_SYMBOL_GPL(xnsched_quota_destroy_group);

void xnsched_quota_set_limit(struct xnsched_quota_group *tg,
			     int quota_percent, int quota_peak_percent,
			     int *quota_sum_r)
{
	struct xnsched *sched = tg->sched;
	struct xnsched_quota *qs = &sched->quota;
	xnticks_t old_quota_ns = tg->quota_ns;
	struct xnthread *curr;
	xnticks_t now, elapsed, consumed;

	atomic_only();

	trace_cobalt_schedquota_set_limit(tg, quota_percent,
					  quota_peak_percent);

	if (quota_percent < 0 || quota_percent > 100) { /* Quota off. */
		quota_percent = 100;
		tg->quota_ns = qs->period_ns;
	} else
		tg->quota_ns = xnarch_div64(qs->period_ns * quota_percent, 100);

	if (quota_peak_percent < quota_percent)
		quota_peak_percent = quota_percent;

	if (quota_peak_percent < 0 || quota_peak_percent > 100) {
		quota_peak_percent = 100;
		tg->quota_peak_ns = qs->period_ns;
	} else
		tg->quota_peak_ns = xnarch_div64(qs->period_ns * quota_peak_percent, 100);

	tg->quota_percent = quota_percent;
	tg->quota_peak_percent = quota_peak_percent;

	curr = sched->curr;
	if (curr->quota == tg &&
	    xnthread_test_state(curr, XNREADY|XNTHREAD_BLOCK_BITS) == 0) {
		now = xnclock_read_monotonic(&nkclock);

		elapsed = now - tg->run_start_ns;
		if (elapsed < tg->run_budget_ns)
			tg->run_budget_ns -= elapsed;
		else
			tg->run_budget_ns = 0;

		tg->run_start_ns = now;

		xntimer_stop(&qs->limit_timer);
	}

	if (tg->run_budget_ns <= old_quota_ns)
		consumed = old_quota_ns - tg->run_budget_ns;
	else
		consumed = 0;
	if (tg->quota_ns >= consumed)
		tg->run_budget_ns = tg->quota_ns - consumed;
	else
		tg->run_budget_ns = 0;

	tg->run_credit_ns = 0;	/* Drop accumulated credit. */

	*quota_sum_r = quota_sum_all(qs);
	
	/* we know for sure group is enqueued, either in expired list or in runtime 
	* queue we just need to understand where is 
	*/
	if ((tg->run_budget_ns > 0) && (tg->enqueued)) {
		if(!list_empty(&tg->quota_expired)) {
			list_del_init(&tg->quota_expired);
			list_add_priff(tg, &sched->quota.runnable, cprio, rlink);
		} else {
			list_del(&tg->rlink);
			list_add_priff(tg, &sched->quota.runnable, cprio, rlink);
		}
	}

	/*
	 * Apply the new budget immediately, in case a member of this
	 * group is currently running.
	 */

	xnsched_set_resched(sched);
	xnsched_run();
}
EXPORT_SYMBOL_GPL(xnsched_quota_set_limit);

void xnsched_quota_set_prio(struct xnsched_quota_group *tg,
			     unsigned short int prio)
{	
	if(tg == NULL)
		return;

	if(prio < XNSCHED_QUOTA_MIN_PRIO_GROUP || prio > XNSCHED_QUOTA_MAX_PRIO_GROUP)
		prio = XNSCHED_QUOTA_MIN_PRIO_GROUP;
	tg->cprio = prio;
}
EXPORT_SYMBOL_GPL(xnsched_quota_set_prio);

struct xnsched_quota_group *
xnsched_quota_find_group(struct xnsched *sched, int tgid)
{
	struct xnsched_quota_group *tg;

	atomic_only();

	if (list_empty(&sched->quota.groups))
		return NULL;

	list_for_each_entry(tg, &sched->quota.groups, next) {
		if (tg->tgid == tgid)
			return tg;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(xnsched_quota_find_group);

int xnsched_quota_sum_all(struct xnsched *sched)
{
	struct xnsched_quota *qs = &sched->quota;

	atomic_only();

	return quota_sum_all(qs);
}
EXPORT_SYMBOL_GPL(xnsched_quota_sum_all);

/** @} */

#ifdef CONFIG_XENO_OPT_VFILE

struct xnvfile_directory sched_quota_vfroot;

struct vfile_sched_quota_priv {
	struct xnthread *curr;
};

struct vfile_sched_quota_data {
	int cpu;
	pid_t pid;
	int prio;
	int tgid;
	xnticks_t budget;
	char name[XNOBJECT_NAME_LEN];
	int tgid_prio;
};

static struct xnvfile_snapshot_ops vfile_sched_quota_ops;

static struct xnvfile_snapshot vfile_sched_quota = {
	.privsz = sizeof(struct vfile_sched_quota_priv),
	.datasz = sizeof(struct vfile_sched_quota_data),
	.tag = &nkthreadlist_tag,
	.ops = &vfile_sched_quota_ops,
};

static int vfile_sched_quota_rewind(struct xnvfile_snapshot_iterator *it)
{
	struct vfile_sched_quota_priv *priv = xnvfile_iterator_priv(it);
	int nrthreads = xnsched_class_quota.nthreads;

	if (nrthreads == 0)
		return -ESRCH;

	priv->curr = list_first_entry(&nkthreadq, struct xnthread, glink);

	return nrthreads;
}

static int vfile_sched_quota_next(struct xnvfile_snapshot_iterator *it,
				  void *data)
{
	struct vfile_sched_quota_priv *priv = xnvfile_iterator_priv(it);
	struct vfile_sched_quota_data *p = data;
	struct xnthread *thread;

	if (priv->curr == NULL)
		return 0;	/* All done. */

	thread = priv->curr;
	if (list_is_last(&thread->glink, &nkthreadq))
		priv->curr = NULL;
	else
		priv->curr = list_next_entry(thread, glink);

	if (thread->base_class != &xnsched_class_quota)
		return VFILE_SEQ_SKIP;

	p->cpu = xnsched_cpu(thread->sched);
	p->pid = xnthread_host_pid(thread);
	memcpy(p->name, thread->name, sizeof(p->name));
	p->tgid = thread->quota->tgid;
	p->prio = thread->cprio;
	p->budget = thread->quota->run_budget_ns;
	p->tgid_prio = thread->quota->cprio;
	return 1;
}

static int vfile_sched_quota_show(struct xnvfile_snapshot_iterator *it,
				  void *data)
{
	struct vfile_sched_quota_data *p = data;
	char buf[16];

	if (p == NULL)
		xnvfile_printf(it, "%-3s  %-6s %-4s %-4s %-10s %-10s %s\n",
			       "CPU", "PID", "TGID", "PRI", "BUDGET", "GPRI", "NAME");
	else {
		xntimer_format_time(p->budget, buf, sizeof(buf));
		xnvfile_printf(it, "%3u  %-6d %-4d %-4d %-10s %-10d %s\n",
			       p->cpu,
			       p->pid,
			       p->tgid,
			       p->prio,
			       buf,
				   p->tgid_prio,
			       p->name);
	}

	return 0;
}

static struct xnvfile_snapshot_ops vfile_sched_quota_ops = {
	.rewind = vfile_sched_quota_rewind,
	.next = vfile_sched_quota_next,
	.show = vfile_sched_quota_show,
};

static int xnsched_quota_init_vfile(struct xnsched_class *schedclass,
				    struct xnvfile_directory *vfroot)
{
	int ret;

	ret = xnvfile_init_dir(schedclass->name, &sched_quota_vfroot, vfroot);
	if (ret)
		return ret;

	return xnvfile_init_snapshot("threads", &vfile_sched_quota,
				     &sched_quota_vfroot);
}

static void xnsched_quota_cleanup_vfile(struct xnsched_class *schedclass)
{
	xnvfile_destroy_snapshot(&vfile_sched_quota);
	xnvfile_destroy_dir(&sched_quota_vfroot);
}

#endif /* CONFIG_XENO_OPT_VFILE */

struct xnsched_class xnsched_class_quota = {
	.sched_init		=	xnsched_quota_init,
	.sched_enqueue		=	xnsched_quota_enqueue,
	.sched_dequeue		=	xnsched_quota_dequeue,
	.sched_requeue		=	xnsched_quota_requeue,
	.sched_pick		=	xnsched_quota_pick,
	.sched_tick		=	NULL,
	.sched_rotate		=	NULL,
	.sched_migrate		=	xnsched_quota_migrate,
	.sched_chkparam		=	xnsched_quota_chkparam,
	.sched_setparam		=	xnsched_quota_setparam,
	.sched_getparam		=	xnsched_quota_getparam,
	.sched_trackprio	=	xnsched_quota_trackprio,
	.sched_protectprio	=	xnsched_quota_protectprio,
	.sched_forget		=	xnsched_quota_forget,
	.sched_kick		=	NULL,
#ifdef CONFIG_XENO_OPT_VFILE
	.sched_init_vfile	=	xnsched_quota_init_vfile,
	.sched_cleanup_vfile	=	xnsched_quota_cleanup_vfile,
#endif
	.weight			=	XNSCHED_CLASS_WEIGHT(3),
	.policy			=	SCHED_QUOTA,
	.name			=	"quota"
};
EXPORT_SYMBOL_GPL(xnsched_class_quota);
