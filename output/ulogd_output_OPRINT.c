/* ulogd_OPRINT.C
 *
 * ulogd output target for logging to a file 
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
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
#include <errno.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>

#ifndef ULOGD_OPRINT_DEFAULT
#define ULOGD_OPRINT_DEFAULT	"/var/log/ulogd_oprint.log"
#endif

struct oprint_priv {
	FILE *of;
};

static int oprint_interp(struct ulogd_pluginstance *upi)
{
	struct oprint_priv *opi = (struct oprint_priv *) &upi->private;
	unsigned int i;
	
	fprintf(opi->of, "===>PACKET BOUNDARY\n");
	for (i = 0; i < upi->input.num_keys; i++) {
		struct ulogd_key *ret = upi->input.keys[i].u.source;

		if (!ret)
			ulogd_log(ULOGD_NOTICE, "no result for %s ?!?\n",
				  upi->input.keys[i].name);

		if (!IS_VALID(*ret))
			continue;

		fprintf(opi->of,"%s=", ret->name);
		switch (ret->type) {
		case ULOGD_RET_STRING:
			fprintf(opi->of, "%s\n", (char *) ret->u.value.ptr);
			break;
		case ULOGD_RET_BOOL:
		case ULOGD_RET_INT8:
		case ULOGD_RET_INT16:
		case ULOGD_RET_INT32:
			fprintf(opi->of, "%d\n", ret->u.value.i32);
			break;
		case ULOGD_RET_INT64:
			fprintf(opi->of, "%" PRId64 "\n", ret->u.value.i64);
			break;
		case ULOGD_RET_UINT8:
		case ULOGD_RET_UINT16:
		case ULOGD_RET_UINT32:
			fprintf(opi->of, "%u\n", ret->u.value.ui32);
			break;
		case ULOGD_RET_UINT64:
			fprintf(opi->of, "%" PRIu64 "\n", ret->u.value.ui64);
			break;
		case ULOGD_RET_IPADDR: {
			char addrbuf[INET6_ADDRSTRLEN + 1] = "";
			struct in6_addr ipv6addr;
			struct in_addr ipv4addr;
			int family;
			void *addr;

			if (ret->len == sizeof(ipv6addr)) {
				memcpy(ipv6addr.s6_addr, ret->u.value.ui128,
				       sizeof(ipv6addr.s6_addr));
				addr = &ipv6addr;
				family = AF_INET6;
			} else {
				ipv4addr.s_addr = ret->u.value.ui32;
				addr = &ipv4addr;
				family = AF_INET;
			}
			if (!inet_ntop(family, addr, addrbuf, sizeof(addrbuf)))
				break;

			fprintf(opi->of, "%s\n", addrbuf);
			break;
		}
		case ULOGD_RET_NONE:
			fprintf(opi->of, "<none>\n");
			break;
		default:
			fprintf(opi->of, "default\n");
			break;
		}
	}
	if (upi->config_kset->ces[1].u.value != 0)
		fflush(opi->of);

	return ULOGD_IRET_OK;
}

static struct config_keyset oprint_kset = {
	.num_ces = 2,
	.ces = {
		{
			.key = "file", 
			.type = CONFIG_TYPE_STRING, 
			.options = CONFIG_OPT_NONE,
			.u = {.string = ULOGD_OPRINT_DEFAULT },
		},
		{
			.key = "sync",
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u = { .value = 0 },
		},
	},
};

static void sighup_handler_print(struct ulogd_pluginstance *upi, int signal)
{
	struct oprint_priv *oi = (struct oprint_priv *) &upi->private;
	FILE *old = oi->of;

	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "OPRINT: reopening logfile\n");
		oi->of = fopen(upi->config_kset->ces[0].u.string, "a");
		if (!oi->of) {
			ulogd_log(ULOGD_ERROR, "can't open PKTLOG: %s\n",
				strerror(errno));
			oi->of = old;
		} else {
			fclose(old);
		}
		break;
	default:
		break;
	}
}

static int oprint_configure(struct ulogd_pluginstance *upi,
			    struct ulogd_pluginstance_stack *stack)
{
	int ret;

	ret = ulogd_wildcard_inputkeys(upi);
	if (ret < 0)
		return ret;

	ret = ulogd_parse_configfile(upi->id, upi->config_kset);
	if (ret < 0)
		return ret;

	return 0;
}

static int oprint_init(struct ulogd_pluginstance *upi)
{
	struct oprint_priv *op = (struct oprint_priv *) &upi->private;

	op->of = fopen(upi->config_kset->ces[0].u.string, "a");
	if (!op->of) {
		ulogd_log(ULOGD_FATAL, "can't open PKTLOG: %s\n", 
			strerror(errno));
		return -1;
	}		
	return 0;
}

static int oprint_fini(struct ulogd_pluginstance *pi)
{
	struct oprint_priv *op = (struct oprint_priv *) &pi->private;

	if (op->of != stdout)
		fclose(op->of);

	return 0;
}

static struct ulogd_plugin oprint_plugin = {
	.name = "OPRINT", 
	.input = {
			.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
		},
	.output = {
			.type = ULOGD_DTYPE_SINK,
		},
	.configure = &oprint_configure,
	.interp	= &oprint_interp,
	.start 	= &oprint_init,
	.stop	= &oprint_fini,
	.signal = &sighup_handler_print,
	.config_kset = &oprint_kset,
	.version = VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&oprint_plugin);
}
