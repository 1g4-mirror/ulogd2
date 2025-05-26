/* ulogd_filter_IP2HBIN.c, Version $Revision: 1.0 $
 *
 * ulogd interpreter plugin for internal IP storage format
 * to binary conversion in host order
 *
 * (C) 2012 by Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * Based on ulogd_filter_IP2BIN.c Eric Leblond <eric@inl.fr>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <ulogd/ulogd.h>
#include <netinet/if_ether.h>

enum input_keys {
	KEY_OOB_FAMILY,
	KEY_OOB_PROTOCOL,
	KEY_IP_SADDR,
	START_KEY = KEY_IP_SADDR,
	KEY_IP_DADDR,
	KEY_ORIG_IP_SADDR,
	KEY_ORIG_IP_DADDR,
	KEY_REPLY_IP_SADDR,
	KEY_REPLY_IP_DADDR,
	MAX_KEY = KEY_REPLY_IP_DADDR,
};

static struct ulogd_key ip2hbin_inp[] = {
	[KEY_OOB_FAMILY] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.family",
	},
	[KEY_OOB_PROTOCOL] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.protocol",
	},
	[KEY_IP_SADDR] = {
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name = "ip.saddr",
	},
	[KEY_IP_DADDR] = {
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name = "ip.daddr",
	},
	[KEY_ORIG_IP_SADDR] = {
		.type 	= ULOGD_RET_IPADDR,
		.flags 	= ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name	= "orig.ip.saddr",
	},
	[KEY_ORIG_IP_DADDR] = {
		.type	= ULOGD_RET_IPADDR,
		.flags	= ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name	= "orig.ip.daddr",
	},
	[KEY_REPLY_IP_SADDR] = {
		.type 	= ULOGD_RET_IPADDR,
		.flags 	= ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name	= "reply.ip.saddr",
	},
	[KEY_REPLY_IP_DADDR] = {
		.type	= ULOGD_RET_IPADDR,
		.flags	= ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name	= "reply.ip.daddr",
	},
};

static struct ulogd_key ip2hbin_keys[] = {
	{
		.type = ULOGD_RET_IPADDR,
		.name = "ip.hsaddr",
	},
	{
		.type = ULOGD_RET_IPADDR,
		.name = "ip.hdaddr",
	},
	{
		.type = ULOGD_RET_IPADDR,
		.name = "orig.ip.hsaddr",
	},
	{
		.type = ULOGD_RET_IPADDR,
		.name = "orig.ip.hdaddr",
	},
	{
		.type = ULOGD_RET_IPADDR,
		.name = "reply.ip.hsaddr",
	},
	{
		.type = ULOGD_RET_IPADDR,
		.name = "reply.ip.hdaddr",
	},
};

static void ip2hbin(struct ulogd_key *inp, int i, struct ulogd_key *outp, int o,
		   uint8_t addr_family)
{
	switch (addr_family) {
	case AF_INET6:
		okey_set_u128(&outp[o], ikey_get_u128(&inp[i]));
		break;
	case AF_INET:
		okey_set_u32(&outp[o], ntohl(ikey_get_u32(&inp[i])));
		break;
	}
}

static int interp_ip2hbin(struct ulogd_pluginstance *pi)
{
	struct ulogd_key *outp = pi->output.keys;
	struct ulogd_key *inp = pi->input.keys;
	uint8_t proto_family, addr_family;
	int i, o;

	proto_family = ikey_get_u8(&inp[KEY_OOB_FAMILY]);

	switch (proto_family) {
	case NFPROTO_IPV6:
		addr_family = AF_INET6;
		break;
	case NFPROTO_IPV4:
		addr_family = AF_INET;
		break;
	case NFPROTO_BRIDGE:
		if (!pp_is_valid(inp, KEY_OOB_PROTOCOL)) {
			ulogd_log(ULOGD_NOTICE,
				  "No protocol inside NFPROTO_BRIDGE packet\n");
			return ULOGD_IRET_ERR;
		}
		switch (ikey_get_u16(&inp[KEY_OOB_PROTOCOL])) {
		case ETH_P_IPV6:
			addr_family = AF_INET6;
			break;
		case ETH_P_IP:
		case ETH_P_ARP:
			addr_family = AF_INET;
			break;
		default:
			ulogd_log(ULOGD_NOTICE,
				  "Unexpected protocol inside NFPROTO_BRIDGE packet\n");
			return ULOGD_IRET_ERR;
		}
		break;
	default:
		/* TODO handle error */
		ulogd_log(ULOGD_NOTICE, "Unexpected protocol family\n");
		return ULOGD_IRET_ERR;
	}

	/* Iter on all addr fields */
	for (i = START_KEY, o = 0; i <= MAX_KEY; i++, o++) {
		if (pp_is_valid(inp, i)) {
			ip2hbin(inp, i, outp, o, addr_family);
		}
	}

	return ULOGD_IRET_OK;
}

static struct ulogd_plugin ip2hbin_plugin = {
	.name = "IP2HBIN",
	.input = {
		.keys = ip2hbin_inp,
		.num_keys = ARRAY_SIZE(ip2hbin_inp),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
		},
	.output = {
		.keys = ip2hbin_keys,
		.num_keys = ARRAY_SIZE(ip2hbin_keys),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
		},
	.interp = &interp_ip2hbin,
	.version = VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&ip2hbin_plugin);
}
