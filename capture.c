#include <capture.h>

/* this is the callback function used by pcap. which means, whenever pcap receives a packet it calls this function. 
 * let me explain the parameters of pcap_callback now
 * 0) first one is a parameter we just wanted to pass to our function (basically any variable(s) we want to use in 
 *    here from main())
 * 1) second one is the header of the packet we captured, this includes ethernet header, followed by ip header etc.
 * 2) third one is the full packet, i.e. raw packet right out of the wire with its payload
 *
 * so, what i'm doing here is simply adding the packet and packet header to a linked-list, but you can do anything
 * you want this packet. see what i'm doing with the packets i store in the linked-list in the main, you can almost
 * copy-paste that stuff here and it would work just fine.
 */
void pcap_callback (u_char * arg, const struct pcap_pkthdr *pkthdr, const u_char * packet){

  /* just append the packet header and raw packet to the linked-list
   * nothing fancy here, look at main() to learn how to work with the 
   * packet header etc. 
   */
  append_item ((buffer *) arg, pkthdr, packet);

}
