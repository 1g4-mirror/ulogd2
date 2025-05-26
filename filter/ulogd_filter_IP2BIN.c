/* ulogd_filter_IP2BIN.c, Version $Revision: 1500 $
 *
 * ulogd interpreter plugin for internal IP storage format to binary conversion
 *
 * (C) 2008 by Eric Leblond <eric@inl.fr>
 *
 * Based on ulogd_filter_IFINDEX.c Harald Welte <laforge@gnumonks.org>
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

static struct ulogd_key ip2bin_inp[] = {
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

static struct ulogd_key ip2bin_keys[] = {
	{
		.type = ULOGD_RET_RAWSTR,
		.name = "ip.saddr.bin",
	},
	{
		.type = ULOGD_RET_RAWSTR,
		.name = "ip.daddr.bin",
	},
	{
		.type = ULOGD_RET_RAWSTR,
		.name = "orig.ip.saddr.bin",
	},
	{
		.type = ULOGD_RET_RAWSTR,
		.name = "orig.ip.daddr.bin",
	},
	{
		.type = ULOGD_RET_RAWSTR,
		.name = "reply.ip.saddr.bin",
	},
	{
		.type = ULOGD_RET_RAWSTR,
		.name = "reply.ip.daddr.bin",
	},

};

static char ipbin_array[MAX_KEY - START_KEY + 1][FORMAT_IPV6_BUFSZ];

static int ip2bin(struct ulogd_key *inp, int index, int oindex)
{
	char family = ikey_get_u8(&inp[KEY_OOB_FAMILY]);
	char convfamily = family;
	struct in6_addr *addr;
	struct in6_addr ip4_addr;

	if (family == AF_BRIDGE) {
		if (!pp_is_valid(inp, KEY_OOB_PROTOCOL)) {
			ulogd_log(ULOGD_NOTICE,
				  "No protocol inside AF_BRIDGE packet\n");
			return ULOGD_IRET_ERR;
		}
		switch (ikey_get_u16(&inp[KEY_OOB_PROTOCOL])) {
		case ETH_P_IPV6:
			convfamily = AF_INET6;
			break;
		case ETH_P_IP:
			convfamily = AF_INET;
			break;
		case ETH_P_ARP:
			convfamily = AF_INET;
			break;
		default:
			ulogd_log(ULOGD_NOTICE,
				  "Unknown protocol inside AF_BRIDGE packet\n");
			return ULOGD_IRET_ERR;
		}
	}

	switch (convfamily) {
		case AF_INET6:
			addr = (struct in6_addr *)ikey_get_u128(&inp[index]);
			break;
		case AF_INET:
			/* Convert IPv4 to IPv4 in IPv6 */
			addr = &ip4_addr;
			uint32_to_ipv6(ikey_get_u32(&inp[index]), addr);
			break;
		default:
			/* TODO handle error */
			ulogd_log(ULOGD_NOTICE, "Unknown protocol family\n");
			return ULOGD_IRET_ERR;
	}

	format_ipv6(ipbin_array[oindex], sizeof(ipbin_array[oindex]), addr);

	return ULOGD_IRET_OK;
}

static int interp_ip2bin(struct ulogd_pluginstance *pi)
{
	struct ulogd_key *ret = pi->output.keys;
	struct ulogd_key *inp = pi->input.keys;
	int i;
	int fret;

	/* Iter on all addr fields */
	for(i = START_KEY; i <= MAX_KEY; i++) {
		if (pp_is_valid(inp, i)) {
			fret = ip2bin(inp, i, i - START_KEY);
			if (fret != ULOGD_IRET_OK)
				return fret;
			okey_set_ptr(&ret[i - START_KEY],
				     ipbin_array[i - START_KEY]);
		}
	}

	return ULOGD_IRET_OK;
}

static struct ulogd_plugin ip2bin_plugin = {
	.name = "IP2BIN",
	.input = {
		.keys = ip2bin_inp,
		.num_keys = ARRAY_SIZE(ip2bin_inp),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
		},
	.output = {
		.keys = ip2bin_keys,
		.num_keys = ARRAY_SIZE(ip2bin_keys),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
		},
	.interp = &interp_ip2bin,
	.version = VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&ip2bin_plugin);
}
