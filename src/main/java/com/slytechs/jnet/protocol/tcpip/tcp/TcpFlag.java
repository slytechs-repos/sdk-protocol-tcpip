package com.slytechs.jnet.protocol.tcpip.tcp;

import com.slytechs.jnet.protocol.api.flag.Flag;
import com.slytechs.jnet.protocol.api.flag.FlagDef;

/**
 * TCP header flags as defined in RFC 793 and subsequent RFCs.
 * Handles the 9-bit control flags field in the TCP header.
 */
public enum TcpFlag implements Flag {
    // Standard TCP flags (bits 0-8 of the TCP flags field)
    FIN(0),  // Finish - No more data from sender
    SYN(1),  // Synchronize - Synchronize sequence numbers
    RST(2),  // Reset - Reset the connection
    PSH(3),  // Push - Push data to application immediately
    ACK(4),  // Acknowledgment - Acknowledgment field is significant
    URG(5),  // Urgent - Urgent pointer field is significant
    ECE(6),  // ECN Echo - RFC 3168
    CWR(7),  // Congestion Window Reduced - RFC 3168
    NS(8);   // Nonce Sum - RFC 3540 (experimental)
    
    private final FlagDef impl;
    
    TcpFlag(int position) {
        this.impl = new FlagDef(name(), position, 1);
    }
    
    @Override public long mask() { return impl.mask(); }
    @Override public int position() { return impl.position(); }
    @Override public String toString() { return impl.toString(); }
}