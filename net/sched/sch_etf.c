// SPDX-License-Identifier: GPL-2.0

/* net/sched/sch_etf.c  Earliest TxTime First queueing discipline.
 *
 * Authors:	Jesus Sanchez-Palencia <jesus.sanchez-palencia@intel.com>
 *		Vinicius Costa Gomes <vinicius.gomes@intel.com>
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/rbtree.h>
#include <linux/skbuff.h>
#include <linux/posix-timers.h>
#include <net/netlink.h>
#include <net/sch_generic.h>
#include <net/pkt_sched.h>
#include <net/sock.h>

#define DEADLINE_MODE_IS_ON(x) ((x)->flags & TC_ETF_DEADLINE_MODE_ON)

struct etf_sched_data {
	bool deadline_mode;
	int clockid;
	int queue;
	s32 delta; /* in ns */
	ktime_t last; /* The txtime of the last skb sent to the netdevice. */
	struct rb_root head;
	struct qdisc_watchdog watchdog;
	ktime_t (*get_time)(void);
};

static const struct nla_policy etf_policy[TCA_ETF_MAX + 1] = {
	[TCA_ETF_PARMS]	= { .len = sizeof(struct tc_etf_qopt) },
};

static inline int validate_input_params(struct tc_etf_qopt *qopt,
					struct netlink_ext_ack *extack)
{
	/* Check if params comply to the following rules:
	 *	* Clockid and delta must be valid.
	 *
	 *	* Dynamic clockids are not supported.
	 *
	 *	* Delta must be a positive integer.
	 */
	if (qopt->clockid < 0) {
		NL_SET_ERR_MSG(extack, "Dynamic clockids are not supported");
		return -ENOTSUPP;
	}

	if (qopt->clockid != CLOCK_TAI) {
		NL_SET_ERR_MSG(extack, "Invalid clockid. CLOCK_TAI must be used");
		return -EINVAL;
	}

	if (qopt->delta < 0) {
		NL_SET_ERR_MSG(extack, "Delta must be positive");
		return -EINVAL;
	}

	return 0;
}

static bool is_packet_valid(struct Qdisc *sch, struct sk_buff *nskb)
{
	struct etf_sched_data *q = qdisc_priv(sch);
	ktime_t txtime = nskb->tstamp;
	struct sock *sk = nskb->sk;
	ktime_t now;

	if (!sk)
		return false;

	if (!sock_flag(sk, SOCK_TXTIME))
		return false;

	/* We don't perform crosstimestamping.
	 * Drop if packet's clockid differs from qdisc's.
	 */
	if (sk->sk_clockid != q->clockid)
		return false;

	if (sk->sk_txtime_deadline_mode != q->deadline_mode)
		return false;

	now = q->get_time();
	if (ktime_before(txtime, now) || ktime_before(txtime, q->last))
		return false;

	return true;
}

static struct sk_buff *etf_peek_timesortedlist(struct Qdisc *sch)
{
	struct etf_sched_data *q = qdisc_priv(sch);
	struct rb_node *p;

	p = rb_first(&q->head);
	if (!p)
		return NULL;

	return rb_to_skb(p);
}

static void reset_watchdog(struct Qdisc *sch)
{
	struct etf_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb = etf_peek_timesortedlist(sch);
	ktime_t next;

	if (!skb)
		return;

	next = ktime_sub_ns(skb->tstamp, q->delta);
	qdisc_watchdog_schedule_ns(&q->watchdog, ktime_to_ns(next));
}

static int etf_enqueue_timesortedlist(struct sk_buff *nskb, struct Qdisc *sch,
				      struct sk_buff **to_free)
{
	struct etf_sched_data *q = qdisc_priv(sch);
	struct rb_node **p = &q->head.rb_node, *parent = NULL;
	ktime_t txtime = nskb->tstamp;

	if (!is_packet_valid(sch, nskb))
		return qdisc_drop(nskb, sch, to_free);

	while (*p) {
		struct sk_buff *skb;

		parent = *p;
		skb = rb_to_skb(parent);
		if (ktime_after(txtime, skb->tstamp))
			p = &parent->rb_right;
		else
			p = &parent->rb_left;
	}
	rb_link_node(&nskb->rbnode, parent, p);
	rb_insert_color(&nskb->rbnode, &q->head);

	qdisc_qstats_backlog_inc(sch, nskb);
	sch->q.qlen++;

	/* Now we may need to re-arm the qdisc watchdog for the next packet. */
	reset_watchdog(sch);

	return NET_XMIT_SUCCESS;
}

static void timesortedlist_erase(struct Qdisc *sch, struct sk_buff *skb,
				 bool drop)
{
	struct etf_sched_data *q = qdisc_priv(sch);

	rb_erase(&skb->rbnode, &q->head);

	/* The rbnode field in the skb re-uses these fields, now that
	 * we are done with the rbnode, reset them.
	 */
	skb->next = NULL;
	skb->prev = NULL;
	skb->dev = qdisc_dev(sch);

	qdisc_qstats_backlog_dec(sch, skb);

	if (drop) {
		struct sk_buff *to_free = NULL;

		qdisc_drop(skb, sch, &to_free);
		kfree_skb_list(to_free);
		qdisc_qstats_overlimit(sch);
	} else {
		qdisc_bstats_update(sch, skb);

		q->last = skb->tstamp;
	}

	sch->q.qlen--;
}

static struct sk_buff *etf_dequeue_timesortedlist(struct Qdisc *sch)
{
	struct etf_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	ktime_t now, next;

	skb = etf_peek_timesortedlist(sch);
	if (!skb)
		return NULL;

	now = q->get_time();

	/* Drop if packet has expired while in queue. */
	/* FIXME: Must return error on the socket's error queue */
	if (ktime_before(skb->tstamp, now)) {
		timesortedlist_erase(sch, skb, true);
		skb = NULL;
		goto out;
	}

	/* When in deadline mode, dequeue as soon as possible and change the
	 * txtime from deadline to (now + delta).
	 */
	if (q->deadline_mode) {
		timesortedlist_erase(sch, skb, false);
		skb->tstamp = now;
		goto out;
	}

	next = ktime_sub_ns(skb->tstamp, q->delta);

	/* Dequeue only if now is within the [txtime - delta, txtime] range. */
	if (ktime_after(now, next))
		timesortedlist_erase(sch, skb, false);
	else
		skb = NULL;

out:
	/* Now we may need to re-arm the qdisc watchdog for the next packet. */
	reset_watchdog(sch);

	return skb;
}

static int etf_init(struct Qdisc *sch, struct nlattr *opt,
		    struct netlink_ext_ack *extack)
{
	struct etf_sched_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	struct nlattr *tb[TCA_ETF_MAX + 1];
	struct tc_etf_qopt *qopt;
	int err;

	if (!opt) {
		NL_SET_ERR_MSG(extack,
			       "Missing ETF qdisc options which are mandatory");
		return -EINVAL;
	}

	err = nla_parse_nested(tb, TCA_ETF_MAX, opt, etf_policy, extack);
	if (err < 0)
		return err;

	if (!tb[TCA_ETF_PARMS]) {
		NL_SET_ERR_MSG(extack, "Missing mandatory ETF parameters");
		return -EINVAL;
	}

	qopt = nla_data(tb[TCA_ETF_PARMS]);

	pr_debug("delta %d clockid %d deadline %s\n",
		 qopt->delta, qopt->clockid,
		 DEADLINE_MODE_IS_ON(qopt) ? "on" : "off");

	err = validate_input_params(qopt, extack);
	if (err < 0)
		return err;

	q->queue = sch->dev_queue - netdev_get_tx_queue(dev, 0);

	/* Everything went OK, save the parameters used. */
	q->delta = qopt->delta;
	q->clockid = qopt->clockid;
	q->deadline_mode = DEADLINE_MODE_IS_ON(qopt);

	switch (q->clockid) {
	case CLOCK_REALTIME:
		q->get_time = ktime_get_real;
		break;
	case CLOCK_MONOTONIC:
		q->get_time = ktime_get;
		break;
	case CLOCK_BOOTTIME:
		q->get_time = ktime_get_boottime;
		break;
	case CLOCK_TAI:
		q->get_time = ktime_get_clocktai;
		break;
	default:
		NL_SET_ERR_MSG(extack, "Clockid is not supported");
		return -ENOTSUPP;
	}

	qdisc_watchdog_init_clockid(&q->watchdog, sch, q->clockid);

	return 0;
}

static void timesortedlist_clear(struct Qdisc *sch)
{
	struct etf_sched_data *q = qdisc_priv(sch);
	struct rb_node *p = rb_first(&q->head);

	while (p) {
		struct sk_buff *skb = rb_to_skb(p);

		p = rb_next(p);

		rb_erase(&skb->rbnode, &q->head);
		rtnl_kfree_skbs(skb, skb);
		sch->q.qlen--;
	}
}

static void etf_reset(struct Qdisc *sch)
{
	struct etf_sched_data *q = qdisc_priv(sch);

	/* Only cancel watchdog if it's been initialized. */
	if (q->watchdog.qdisc == sch)
		qdisc_watchdog_cancel(&q->watchdog);

	/* No matter which mode we are on, it's safe to clear both lists. */
	timesortedlist_clear(sch);
	__qdisc_reset_queue(&sch->q);

	sch->qstats.backlog = 0;
	sch->q.qlen = 0;

	q->last = 0;
}

static void etf_destroy(struct Qdisc *sch)
{
	struct etf_sched_data *q = qdisc_priv(sch);

	/* Only cancel watchdog if it's been initialized. */
	if (q->watchdog.qdisc == sch)
		qdisc_watchdog_cancel(&q->watchdog);
}

static int etf_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct etf_sched_data *q = qdisc_priv(sch);
	struct tc_etf_qopt opt = { };
	struct nlattr *nest;

	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (!nest)
		goto nla_put_failure;

	opt.delta = q->delta;
	opt.clockid = q->clockid;
	if (q->deadline_mode)
		opt.flags |= TC_ETF_DEADLINE_MODE_ON;

	if (nla_put(skb, TCA_ETF_PARMS, sizeof(opt), &opt))
		goto nla_put_failure;

	return nla_nest_end(skb, nest);

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

static struct Qdisc_ops etf_qdisc_ops __read_mostly = {
	.id		=	"etf",
	.priv_size	=	sizeof(struct etf_sched_data),
	.enqueue	=	etf_enqueue_timesortedlist,
	.dequeue	=	etf_dequeue_timesortedlist,
	.peek		=	etf_peek_timesortedlist,
	.init		=	etf_init,
	.reset		=	etf_reset,
	.destroy	=	etf_destroy,
	.dump		=	etf_dump,
	.owner		=	THIS_MODULE,
};

static int __init etf_module_init(void)
{
	return register_qdisc(&etf_qdisc_ops);
}

static void __exit etf_module_exit(void)
{
	unregister_qdisc(&etf_qdisc_ops);
}
module_init(etf_module_init)
module_exit(etf_module_exit)
MODULE_LICENSE("GPL");
