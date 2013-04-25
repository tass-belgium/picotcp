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
//this function should only be used after you checked if the options are valid! otherwise it could read from bad memory!
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
	if ((type == PICO_DHCPOPT_END) || (type == PICO_DHCPOPT_PAD)) {
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

int is_options_valid(uint8_t *opt_buffer, int len)
{
	uint8_t *p = opt_buffer;
	while (len > 0) {
		if (*p == PICO_DHCPOPT_END)
			return 1;
		else if (*p == PICO_DHCPOPT_PAD) {
			p++;
			len--;
		} else {
			uint8_t opt_len;
			p++;
			len--;
			if(len > 0) {
				opt_len = *p;
				p += opt_len + 1;
				len -= opt_len;
			}else
				return 0;
		}
	}
	return 0;
}

#endif
