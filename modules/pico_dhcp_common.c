/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

.

Authors: Frederik Van Slycken
*********************************************************************/

#include "pico_config.h"
#include "pico_stack.h"
#include "pico_dhcp_common.h"

#if defined (PICO_SUPPORT_DHCPC) || defined (PICO_SUPPORT_DHCPD)
uint8_t dhcp_get_next_option(uint8_t *begin, uint8_t *data, int *len, uint8_t **nextopt)
{
	uint8_t *p;
	uint8_t type;
	uint8_t opt_len;

	if (!begin)
		p = *nextopt;
	else
		p = begin;

	type = *p;
	*nextopt = ++p;
	if ((type == PICO_DHCP_OPT_END) || (type == PICO_DHCP_OPT_PAD)) {
		memset(data, 0, *len);
		len = 0;
		return type;
	}
	opt_len = *p;
	p++;
	if (*len > opt_len)
		*len = opt_len;
	memcpy(data, p, *len);
	*nextopt = p + opt_len;
	return type;
}

/* pico_dhcp_are_options_valid needs to be called first to prevent illegal memory access */
/* The argument pointer is moved forward to the next option */
struct pico_dhcp_opt *pico_dhcp_next_option(struct pico_dhcp_opt **ptr)
{
  uint8_t **p = (uint8_t **)ptr;
  struct pico_dhcp_opt *opt = *ptr;

	if (opt->code == PICO_DHCP_OPT_END)
    return NULL;
  if (opt->code == PICO_DHCP_OPT_PAD) {
    *p += 1; 
		return *ptr;
  }

  *p += (opt->len + 2); /* (len + 2) to account for code and len octet */
  return *ptr;
}

int pico_dhcp_are_options_valid(void *ptr, int len)
{
	uint8_t optlen = 0, *p = ptr;

	while (len > 0) {
    switch (*p)
    {
      case PICO_DHCP_OPT_END:
        return 1;

      case PICO_DHCP_OPT_PAD:
        p++;
        len--;
        break;

      default:
        p++; /* move pointer from code octet to len octet */
        if ((--len <= 0) || (len - (*p + 1) < 0)) /* (*p + 1) to account for len octet */
          return 0;
        optlen = *p;
        p += optlen + 1;
        len -= optlen;
        break;
    }
	}
	return 0;
}
#endif
