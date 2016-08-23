#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

using namespace std;

struct FTD_hdr {
//header struct
	u_char  header_type;		/* source port */
	u_char	header_ext_length;		/* destination port */
    u_short	header_msg_length;		/* datagram length */
//ext msg
};
typedef u_char byte;

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

const char *timestamp_string(struct timeval ts)
	{
	static char timestamp_string_buf[256];

	sprintf(timestamp_string_buf, "%d.%06d",
		(int) ts.tv_sec, (int) ts.tv_usec);

	return timestamp_string_buf;
	}


byte* lzw_decode(byte *in)
{
	byte *out = _new(byte, 4);
	int out_len = 0;
 
	inline void write_out(byte c)
	{
		while (out_len >= _len(out)) _extend(out);
		out[out_len++] = c;
	}
 
	lzw_dec_t *d = _new(lzw_dec_t, 512);
	int len, j, next_shift = 512, bits = 9, n_bits = 0;
	ushort code, c, t, next_code = M_NEW;
 
	uint32_t tmp = 0;
	inline void get_code() {
		while(n_bits < bits) {
			if (len > 0) {
				len --;
				tmp = (tmp << 8) | *(in++);
				n_bits += 8;
			} else {
				tmp = tmp << (bits - n_bits);
				n_bits = bits;
			}
		}
		n_bits -= bits;
		code = tmp >> n_bits;
		tmp &= (1 << n_bits) - 1;
	}
 
	inline void clear_table() {
		_clear(d);
		for (j = 0; j < 256; j++) d[j].c = j;
		next_code = M_NEW;
		next_shift = 512;
		bits = 9;
	};
 
	clear_table(); /* in case encoded bits didn't start with M_CLR */
	for (len = _len(in); len;) {
		get_code();
		if (code == M_EOD) break;
		if (code == M_CLR) {
			clear_table();
			continue;
		}
 
		if (code >= next_code) {
			fprintf(stderr, "Bad sequence\n");
			_del(out);
			goto bail;
		}
 
		d[next_code].prev = c = code;
		while (c > 255) {
			t = d[c].prev; d[t].back = c; c = t;
		}
 
		d[next_code - 1].c = c;
 
		while (d[c].back) {
			write_out(d[c].c);
			t = d[c].back; d[c].back = 0; c = t;
		}
		write_out(d[c].c);
 
		if (++next_code >= next_shift) {
			if (++bits > 16) {
				/* if input was correct, we'd have hit M_CLR before this */
				fprintf(stderr, "Too many bits\n");
				_del(out);
				goto bail;
			}
			_setsize(d, next_shift *= 2);
		}
	}
 
	/* might be ok, so just whine, don't be drastic */
	if (code != M_EOD) fputs("Bits did not end in EOD\n", stderr);
 
	_setsize(out, out_len);
bail:	_del(d);
	return out;
}
int main() {
  pcap_t *descr;
  char errbuf[PCAP_ERRBUF_SIZE];

  // open capture file for offline processing
  descr = pcap_open_offline("alltraffic.pcap", errbuf);
  if (descr == NULL) {
      cout << "pcap_open_live() failed: " << errbuf << endl;
      return 1;
  }

  // start packet processing loop, just like live capture
  if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
      cout << "pcap_loop() failed: " << pcap_geterr(descr);
      return 1;
  }

  cout << "capture finished" << endl;

  return 0;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  const struct ether_header* ethernetHeader;
  const struct ip* ipHeader;
  const struct tcphdr* tcpHeader;
  char sourceIp[INET_ADDRSTRLEN];
  char destIp[INET_ADDRSTRLEN];
  u_int sourcePort, destPort;
  u_char *data;
  int dataLength = 0;
  string dataStr = "";
struct FTD_hdr *ftd;
//printf("timestamp:%s \n",timestamp_string(pkthdr->ts));

  ethernetHeader = (struct ether_header*)packet;
  if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
      ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
      inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
      inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

      if (ipHeader->ip_p == IPPROTO_TCP) {
          tcpHeader = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
          sourcePort = ntohs(tcpHeader->source);
          destPort = ntohs(tcpHeader->dest);
          data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
          dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

          // convert non-printable characters, other than carriage return, line feed,
          // or tab into periods when displayed.
ftd = (struct FTD_hdr*) data;

if(ftd->header_type!=0x00)
{
switch(ftd->header_type)
{
case 0x01:
cout<<"normal msg, ";
break;
case 0x02:
cout<<"compress msg, ";
break;
}
if(ftd->header_ext_length>0x00)
cout<<" has extend msg ";

cout<<"msg:lens:"<<ntohs(ftd->header_msg_length)<<endl;
          for (int i = 0; i < dataLength; i++) {
#if 0
              if ((data[i] >= 32 && data[i] <= 126) || data[i] == 10 || data[i] == 11 || data[i] == 13) {
                  dataStr += (char)data[i];
              } else {
                  dataStr += ".";
              }
#endif
char temp[8];
sprintf(temp,"0x%x",data[i]);
dataStr += temp;
          }

          // print the results
          cout << sourceIp << ":" << sourcePort << " -> " << destIp << ":" << destPort << endl;
          //if (dataLength > 0) {
          //    cout << dataStr << endl;
          //}
}
      }
  }
}
