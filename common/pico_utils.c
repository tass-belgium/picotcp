/**
 * Calculate checksum of a given string
 */
uint16_t net_checksum(void *inbuf, int len)
{
	uint8_t *buf = (uint8_t *) inbuf;
	uint32_t sum = 0, carry=0;
	int i=0;
	for(i=0; i<len; i++){
		if (i%2){
			sum+=buf[i];
		}else{
			sum+=( buf[i] << 8);
		}
	}
	carry = (sum&0xFFFF0000) >>16;
	sum = (sum&0x0000FFFF);
	return (uint16_t) ~(sum + carry)  ;
}
