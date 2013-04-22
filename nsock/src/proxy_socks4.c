/***************************************************************************
 * proxy_socks4.c -- SOCKS4 proxying.                                      *
 *                                                                         *
 ***********************IMPORTANT NSOCK LICENSE TERMS***********************
 *                                                                         *
 * The nsock parallel socket event library is (C) 1999-2012 Insecure.Com   *
 * LLC This library is free software; you may redistribute and/or          *
 * modify it under the terms of the GNU General Public License as          *
 * published by the Free Software Foundation; Version 2.  This guarantees  *
 * your right to use, modify, and redistribute this software under certain *
 * conditions.  If this license is unacceptable to you, Insecure.Com LLC   *
 * may be willing to sell alternative licenses (contact                    *
 * sales@insecure.com ).                                                   *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two. You must obey the GNU GPL in all *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
 *                                                                         *
 * If you received these files with a written license agreement stating    *
 * terms other than the (GPL) terms above, then that alternative license   *
 * agreement takes precedence over this comment.                           *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to nmap-dev@insecure.org for possible incorporation into the main       *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because the *
 * inability to relicense code has caused devastating problems for other   *
 * Free Software projects (such as KDE and NASM).  We also occasionally    *
 * relicense the code to third parties as discussed above.  If you wish to *
 * specify special license conditions of your contributions, just say so   *
 * when you send them.                                                     *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details                            *
 * (http://www.gnu.org/licenses/gpl-2.0.html).                             *
 *                                                                         *
 ***************************************************************************/

/* $Id $ */

#include "nsock.h"
#include "nsock_internal.h"
#include <netdb.h>
#include <string.h>

#define DEFAULT_PROXY_PORT_SOCKS4 1080


struct socks4_data {
    char version;
    char type;
    unsigned short port;
    unsigned long address;
    char null;
} __attribute__((packed));


/* ---- PROTOTYPES ---- */
static int proxy_socks4_node_new(struct proxy_node **node, const struct uri *uri);
static void proxy_socks4_node_delete(struct proxy_node *node);
static void proxy_socks4_handler(nsock_pool nspool, nsock_event nsevent, void *udata);


/* ---- PROXY DEFINITION ---- */
const struct proxy_op proxy_socks4_ops = {
  .prefix      = "socks4://",
  .type        = PROXY_TYPE_SOCKS4,
  .node_new    = proxy_socks4_node_new,
  .node_delete = proxy_socks4_node_delete,
  .handler     = proxy_socks4_handler,
};


int proxy_socks4_node_new(struct proxy_node **node, const struct uri *uri) {
  int rc;
  struct proxy_node *proxy;

  proxy = (struct proxy_node *)safe_zalloc(sizeof(struct proxy_node));
  proxy->ops = &proxy_socks4_ops;

  rc = proxy_resolve(uri->host, (struct sockaddr *)&proxy->ss, &proxy->sslen);
  if (rc < 0)
    goto err_out;

  if (proxy->ss.ss_family != AF_INET) {
    rc = -1;
    goto err_out;
  }

  if (uri->port == -1)
    proxy->port = DEFAULT_PROXY_PORT_SOCKS4;
  else
    proxy->port = (unsigned short)uri->port;

  rc = 1;

err_out:
  if (rc < 0) {
    free(proxy);
    proxy = NULL;
  }
  *node = proxy;
  return rc;
}

void proxy_socks4_node_delete(struct proxy_node *node) {
  if (node)
    free(node);
}

static inline void socks4_init(struct socks4_data *socks4,
                               struct sockaddr_storage *ss, size_t sslen,
                               unsigned short port) {
    struct sockaddr_in *sin = (struct sockaddr_in *)ss;

    memset(socks4, 0x00, sizeof(struct socks4_data));
    socks4->version = 4;
    socks4->type = 1;
    socks4->port = htons(port);
    assert(ss->ss_family == AF_INET);
    socks4->address = sin->sin_addr.s_addr;
}

void proxy_socks4_handler(nsock_pool nspool, nsock_event nsevent, void *udata) {
  mspool *nsp = (mspool *)nspool;
  msevent *nse = (msevent *)nsevent;
  struct sockaddr_storage *ss;
  size_t sslen;
  unsigned short port;
  struct proxy_node *next;

  switch (nse->iod->px_ctx->px_state) {
    struct socks4_data socks4;

    case PROXY_STATE_INITIAL:
      nse->iod->px_ctx->px_state = PROXY_STATE_SOCKS4_TCP_CONNECTED;

      next = proxy_ctx_node_next(nse->iod->px_ctx);
      if (next) {
        ss = &next->ss;
        sslen = next->sslen;
        port = next->port;
      } else {
        ss = &nse->iod->px_ctx->target_ss;
        sslen = nse->iod->px_ctx->target_sslen;
        port = nse->iod->px_ctx->target_port;
      }

      socks4_init(&socks4, ss, sslen, port);

      nsock_write(nspool, (nsock_iod)nse->iod, nsock_proxy_ev_dispatch,
                  4000, udata, (char *)&socks4, 9);
      nsock_readbytes(nspool, (nsock_iod)nse->iod, nsock_proxy_ev_dispatch,
                      4000, udata, 8);
      break;

    case PROXY_STATE_SOCKS4_TCP_CONNECTED:
      if (nse->type == NSE_TYPE_READ) {
        char *res;
        int reslen;

        res = nse_readbuf(nse, &reslen);

	if (!(reslen == 8 && res[1] == 90)) {
	  assert(0);
	}
        nse->iod->px_ctx->px_state = PROXY_STATE_SOCKS4_TUNNEL_ESTABLISHED;

        if (nse->iod->px_ctx->px_current->next == NULL) {
          forward_event(nsp, nse, udata);
        } else {
          nse->iod->px_ctx->px_current = nse->iod->px_ctx->px_current->next;
          nse->iod->px_ctx->px_state = PROXY_STATE_INITIAL;
          nsock_proxy_ev_dispatch(nsp, nse, udata);
        }
      }
      break;

    case PROXY_STATE_SOCKS4_TUNNEL_ESTABLISHED:
      forward_event(nsp, nse, udata);
      break;

    default:
      fatal("Invalid proxy state!");
  }
}

