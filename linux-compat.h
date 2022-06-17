/* SPDX-License-Identifier: GPL-2.0-only */
/* OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020-2023 OpenVPN, Inc.
 *
 *  Author:	Lev Stipakov <lev@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_LINUX_COMPAT_H_
#define _NET_OVPN_DCO_LINUX_COMPAT_H_

#include <linux/kconfig.h>
#include <linux/version.h>

/* not part of any kernel yet */
#ifndef NLA_POLICY_MAX_LEN
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
#define NLA_POLICY_MAX_LEN(_len) { .type = NLA_BINARY, .len = _len }
#else
#define NLA_POLICY_MAX_LEN(_len) NLA_POLICY_MAX(NLA_BINARY, _len)
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0)

#define genl_split_ops genl_ops

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)

/**
 * commit 58caed3dacb4 renamed to netif_napi_add_tx_weight,
 * commit c3f760ef1287 removed netif_tx_napi_add
 */
#define netif_napi_add_tx_weight netif_tx_napi_add

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)

#define sock_is_readable stream_memory_read

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0) */

#ifndef NLA_POLICY_RANGE
#define NLA_POLICY_RANGE(x, y, z)      { .type = NLA_UNSPEC }
#endif

#ifndef NLA_POLICY_EXACT_LEN
#define NLA_POLICY_EXACT_LEN(_len)     { .type = NLA_UNSPEC }
#endif

#ifndef NLA_POLICY_NESTED
#define NLA_POLICY_NESTED(x)           { .type = NLA_NESTED }
#endif

#ifndef NLA_POLICY_MIN_LEN
#define NLA_POLICY_MIN_LEN(x)          { .type = NLA_UNSPEC }
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0) && !defined(EL8)

#define dev_get_tstats64 ip_tunnel_get_stats64

#include <linux/netdevice.h>

static inline void dev_sw_netstats_tx_add(struct net_device *dev,
					  unsigned int packets,
					  unsigned int len)
{
	struct pcpu_sw_netstats *tstats = this_cpu_ptr(dev->tstats);

	u64_stats_update_begin(&tstats->syncp);
	tstats->tx_bytes += len;
	tstats->tx_packets += packets;
	u64_stats_update_end(&tstats->syncp);
}

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0) && !defined(EL8) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) && !defined(EL8)

#define genl_small_ops genl_ops
#define small_ops ops
#define n_small_ops n_ops

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) && !defined(EL8) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) && !defined(EL8)

#include <linux/netdevice.h>

static inline void dev_sw_netstats_rx_add(struct net_device *dev, unsigned int len)
{
	struct pcpu_sw_netstats *tstats = this_cpu_ptr(dev->tstats);

	u64_stats_update_begin(&tstats->syncp);
	tstats->rx_bytes += len;
	tstats->rx_packets++;
	u64_stats_update_end(&tstats->syncp);
}

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) && !defined(EL8) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)

/* Iterate through singly-linked GSO fragments of an skb. */
#define skb_list_walk_safe(first, skb, next_skb)				\
	for ((skb) = (first), (next_skb) = (skb) ? (skb)->next : NULL; (skb);	\
	     (skb) = (next_skb), (next_skb) = (skb) ? (skb)->next : NULL)

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
/**
 * rcu_replace_pointer() - replace an RCU pointer, returning its old value
 * @rcu_ptr: RCU pointer, whose old value is returned
 * @ptr: regular pointer
 * @c: the lockdep conditions under which the dereference will take place
 *
 * Perform a replacement, where @rcu_ptr is an RCU-annotated
 * pointer and @c is the lockdep argument that is passed to the
 * rcu_dereference_protected() call used to read that pointer.  The old
 * value of @rcu_ptr is returned, and @rcu_ptr is set to @ptr.
 */
#undef rcu_replace_pointer
#define rcu_replace_pointer(rcu_ptr, ptr, c)				\
({									\
	typeof(ptr) __tmp = rcu_dereference_protected((rcu_ptr), (c));	\
	rcu_assign_pointer((rcu_ptr), (ptr));				\
	__tmp;								\
})

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0)

/* commit 895b5c9f206e renamed nf_reset to nf_reset_ct */
#undef nf_reset_ct
#define nf_reset_ct nf_reset

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)

/* commit 1550c171935d introduced rt_gw4 and rt_gw6 for IPv6 gateways */
#define rt_gw4 rt_gateway

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
#define skb_probe_transport_header_(skb) skb_probe_transport_header(skb, 0)
#else
#define skb_probe_transport_header_ skb_probe_transport_header
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
static inline void skb_mark_not_on_list(struct sk_buff *skb)
{
	skb->next = NULL;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
static inline void *skb_put_data(struct sk_buff *skb, const void *data,
				 unsigned int len)
{
	void *tmp = skb_put(skb, len);

	memcpy(tmp, data, len);

	return tmp;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
#define timer_setup(timer, func, flags) \
	setup_timer(timer, (void (*)(unsigned long))func, \
		    (unsigned long)timer)
#define from_timer(var, timer, field) \
	container_of(timer, typeof(*var), field)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
static inline int __nlmsg_parse(const struct nlmsghdr *nlh, int hdrlen,
				struct nlattr *tb[], int maxtype,
				const struct nla_policy *policy)
{
	if (nlh->nlmsg_len < nlmsg_msg_size(hdrlen)) {
		pr_err_ratelimited("Invalid header length");
		return -EINVAL;
	}

	return nla_parse(tb, maxtype, nlmsg_attrdata(nlh, hdrlen),
			   nlmsg_attrlen(nlh, hdrlen), policy);
}

static inline int nlmsg_parse_deprecated(const struct nlmsghdr *nlh, int hdrlen,
					 struct nlattr *tb[], int maxtype,
					 const struct nla_policy *policy,
					 const void *ptr)
{
	return __nlmsg_parse(nlh, hdrlen, tb, maxtype, policy);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
#define atomic64_fetch_add_unless atomic64_add_unless
#endif

#endif /* _NET_OVPN_DCO_LINUX_COMPAT_H_ */
