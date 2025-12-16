/*
 * Sly Technologies Free License
 * 
 * Copyright 2025 Sly Technologies Inc.
 *
 * Licensed under the Sly Technologies Free License (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.slytechs.com/free-license-text
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.slytechs.jnet.protocol.tcpip;

import com.slytechs.jnet.core.api.memory.ByteBuf;
import com.slytechs.jnet.protocol.api.ProtoId;
import com.slytechs.jnet.protocol.api.builtin.L2FrameType;
import com.slytechs.jnet.protocol.api.builtin.L3FrameType;
import com.slytechs.jnet.protocol.api.builtin.L4FrameType;

/**
 * Stateless packet dissector that stores dissection results in a long array.
 * 
 * <p>
 * This dissector analyzes packet data and records protocol information in a
 * compact array format. The first element (long[0]) contains a bitmask of
 * detected protocols, while subsequent elements contain protocol records with
 * offset and length information.
 * 
 * <h2>Array Format</h2>
 * <ul>
 * <li><b>long[0]:</b> Bitmask - 1 bit per protocol ordinal (within pack)</li>
 * <li><b>long[1..n]:</b> Protocol records encoded as:
 *   <pre>
 *   bits 0-7:   ordinal (protocol index within pack)
 *   bits 8-15:  pack ID
 *   bits 16-31: classification mask (reserved)
 *   bits 32-47: header size in bytes
 *   bits 48-63: offset in packet
 *   </pre>
 * </li>
 * </ul>
 * 
 * <h2>Performance Characteristics</h2>
 * <ul>
 * <li>Zero allocation during dissection</li>
 * <li>Cache-friendly sequential array access</li>
 * <li>Fast bitwise operations for encoding/decoding</li>
 * <li>Stateless design allows reuse and thread safety</li>
 * </ul>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class TcpipPacketDissector {
    
    // Protocol record bit positions and masks
    private static final int ORDINAL_SHIFT = 0;
    private static final int PACK_SHIFT = 8;
    private static final int CLASS_SHIFT = 16;
    private static final int SIZE_SHIFT = 32;
    private static final int OFFSET_SHIFT = 48;
    
    private static final long ORDINAL_MASK = 0xFFL;
    private static final long PACK_MASK = 0xFFL;
    private static final long CLASS_MASK = 0xFFFFL;
    private static final long SIZE_MASK = 0xFFFFL;
    private static final long OFFSET_MASK = 0xFFFFL;
    
    // Common Ethernet types (big-endian values)
    private static final short ETHERTYPE_IPV4 = 0x0800;
    private static final short ETHERTYPE_IPV6 = (short)0x86DD;
    private static final short ETHERTYPE_VLAN = (short)0x8100;
    private static final short ETHERTYPE_QINQ = (short)0x88A8;
    private static final short ETHERTYPE_MPLS = (short)0x8847;
    private static final short ETHERTYPE_MPLS_MULTICAST = (short)0x8848;
    
    // IP protocol numbers
    private static final byte IPPROTO_TCP = 6;
    private static final byte IPPROTO_UDP = 17;
    private static final byte IPPROTO_ICMP = 1;
    private static final byte IPPROTO_ICMPV6 = 58;
    private static final int IPPROTO_SCTP = 132;
    private static final byte IPPROTO_GRE = 47;
    private static final byte IPPROTO_ESP = 50;
    private static final byte IPPROTO_AH = 51;
    
    /**
     * Dissects a packet and stores protocol information in the provided array.
     * 
     * @param protocolArray array to store dissection results (must have capacity for all protocols)
     * @param arrayOffset starting offset in the array (typically 0)
     * @param packet the packet data buffer positioned at packet start
     * @param l2Type the data link type (from pcap or known context)
     * @return number of protocol records written (excluding the bitmask at index 0)
     */
    public int dissect(long[] protocolArray, int arrayOffset, ByteBuf packet, L2FrameType l2Type) {
        // Initialize
        int recordIndex = arrayOffset + 1; // Skip bitmask at index 0
        long bitmask = 0;
        
        // Save packet bounds
        long packetStart = packet.position();
        long packetEnd = packet.limit();
        long packetLength = packetEnd - packetStart;
        
        // Start dissection based on L2 type
        int currentOffset = 0;
        
        // Dissect L2
        L2Result l2Result = dissectL2(packet, currentOffset, l2Type);
        if (l2Result.found) {
            bitmask |= createBitmask(l2Result.protocolId);
            protocolArray[recordIndex++] = encodeRecord(
                l2Result.protocolId,
                currentOffset,
                l2Result.length,
                0 // classification
            );
            currentOffset += l2Result.length;
        }
        
        // Dissect L3 if we have an ethertype
        if (l2Result.nextProtocol > 0 && currentOffset < packetLength) {
            L3Result l3Result = dissectL3(packet, currentOffset, l2Result.nextProtocol);
            if (l3Result.found) {
                bitmask |= createBitmask(l3Result.protocolId);
                protocolArray[recordIndex++] = encodeRecord(
                    l3Result.protocolId,
                    currentOffset,
                    l3Result.length,
                    0 // classification
                );
                currentOffset += l3Result.length;
                
                // Dissect L4 if we have a protocol number
                if (l3Result.nextProtocol > 0 && currentOffset < packetLength) {
                    L4Result l4Result = dissectL4(packet, currentOffset, l3Result.nextProtocol);
                    if (l4Result.found) {
                        bitmask |= createBitmask(l4Result.protocolId);
                        protocolArray[recordIndex++] = encodeRecord(
                            l4Result.protocolId,
                            currentOffset,
                            l4Result.length,
                            0 // classification
                        );
                        currentOffset += l4Result.length;
                    }
                }
            }
        }
        
        // Store bitmask in first element
        protocolArray[arrayOffset] = bitmask;
        
        // Return number of records (not including bitmask)
        return recordIndex - arrayOffset - 1;
    }
    
    /**
     * Dissects Layer 2 header.
     */
    private L2Result dissectL2(ByteBuf packet, int offset, L2FrameType l2Type) {
        L2Result result = new L2Result();
        
        switch (l2Type) {
            case L2_FRAME_TYPE_ETHER -> {
                result.found = true;
                result.protocolId = ProtoId.Constants.PROTO_ID_ETHERNET;
                result.length = 14; // Basic Ethernet header
                
                // Check for VLAN tags
                if (packet.remaining() >= offset + 14) {
                    short etherType = packet.getShortBE(offset + 12);
                    
                    if (etherType == ETHERTYPE_VLAN || etherType == ETHERTYPE_QINQ) {
                        // Include VLAN tag in Ethernet header length
                        result.length = 18;
                        result.protocolId = Tcpip.Constants.VLAN_ID; // Update to VLAN
                        
                        // Check for double tagging
                        if (packet.remaining() >= offset + 18) {
                            short innerType = packet.getShortBE(offset + 16);
                            if (innerType == ETHERTYPE_VLAN) {
                                result.length = 22; // Double VLAN
                                etherType = packet.getShortBE(offset + 20);
                            } else {
                                etherType = innerType;
                            }
                        }
                    }
                    
                    // Set next protocol based on EtherType
                    result.nextProtocol = etherType & 0xFFFF;
                }
            }
            case L2_FRAME_TYPE_PPP -> {
                result.found = true;
                result.protocolId = ProtoId.Constants.PROTO_ID_PPP;
                result.length = 4;
                
                // PPP protocol field
                if (packet.remaining() >= offset + 4) {
                    short protocol = packet.getShortBE(offset + 2);
                    // Map PPP protocols to EtherTypes
                    if (protocol == 0x0021) result.nextProtocol = ETHERTYPE_IPV4;
                    else if (protocol == 0x0057) result.nextProtocol = ETHERTYPE_IPV6;
                }
            }
            default -> {
                result.found = false;
            }
        }
        
        return result;
    }
    
    /**
     * Dissects Layer 3 header.
     */
    private L3Result dissectL3(ByteBuf packet, int offset, int etherType) {
        L3Result result = new L3Result();
        
        switch (etherType) {
            case ETHERTYPE_IPV4 -> {
                if (packet.remaining() < offset + 20) {
                    result.found = false;
                    return result;
                }
                
                result.found = true;
                result.protocolId = L3FrameType.Constants.L3_PROTOCOL_IPv4_ID;
                
                byte versionIhl = packet.get(offset);
                int version = (versionIhl >> 4) & 0x0F;
                if (version != 4) {
                    result.found = false;
                    return result;
                }
                
                int ihl = (versionIhl & 0x0F) * 4;
                result.length = Math.max(20, ihl);
                
                // Get protocol field
                if (packet.remaining() >= offset + 10) {
                    result.nextProtocol = packet.get(offset + 9) & 0xFF;
                }
            }
            case ETHERTYPE_IPV6 -> {
                if (packet.remaining() < offset + 40) {
                    result.found = false;
                    return result;
                }
                
                result.found = true;
                result.protocolId = L3FrameType.Constants.L3_PROTOCOL_IPv6_ID;
                result.length = 40; // Fixed IPv6 header
                
                // Get next header field
                byte nextHeader = packet.get(offset + 6);
                
                // Process extension headers
                int extOffset = offset + 40;
                while (isIPv6ExtensionHeader(nextHeader) && extOffset < packet.remaining()) {
                    int extLen = processIPv6ExtensionLength(packet, nextHeader, extOffset);
                    if (extLen == 0) break;
                    
                    result.length += extLen;
                    extOffset += extLen;
                    
                    if (extOffset < packet.remaining()) {
                        nextHeader = packet.get(extOffset);
                    }
                }
                
                result.nextProtocol = nextHeader & 0xFF;
            }
            default -> {
                result.found = false;
            }
        }
        
        return result;
    }
    
    /**
     * Dissects Layer 4 header.
     */
    private L4Result dissectL4(ByteBuf packet, int offset, int protocol) {
        L4Result result = new L4Result();
        
        switch (protocol) {
            case IPPROTO_TCP -> {
                if (packet.remaining() < offset + 20) {
                    result.found = false;
                    return result;
                }
                
                result.found = true;
                result.protocolId = L4FrameType.Constants.L4_PROTOCOL_TCP_ID;
                
                // Get data offset (upper 4 bits of byte 12)
                byte dataOffset = packet.get(offset + 12);
                int headerLength = ((dataOffset & 0xF0) >> 4) * 4;
                result.length = Math.max(20, headerLength);
            }
            case IPPROTO_UDP -> {
                if (packet.remaining() < offset + 8) {
                    result.found = false;
                    return result;
                }
                
                result.found = true;
                result.protocolId = L4FrameType.Constants.L4_PROTOCOL_UDP_ID;
                result.length = 8; // Fixed UDP header
            }
            case IPPROTO_ICMP, IPPROTO_ICMPV6 -> {
                if (packet.remaining() < offset + 8) {
                    result.found = false;
                    return result;
                }
                
                result.found = true;
                result.protocolId = Tcpip.Constants.ICMP_ID;
                result.length = 8; // Basic ICMP header
            }
            case IPPROTO_SCTP -> {
                if (packet.remaining() < offset + 12) {
                    result.found = false;
                    return result;
                }
                
                result.found = true;
                result.protocolId = L4FrameType.Constants.L4_FRAME_TYPE_OTHER; // SCTP
                result.length = 12; // Common SCTP header
            }
            default -> {
                result.found = false;
            }
        }
        
        return result;
    }
    
    /**
     * Checks if a next header value is an IPv6 extension header.
     */
    private boolean isIPv6ExtensionHeader(byte nextHeader) {
        return nextHeader == 0   // Hop-by-hop
            || nextHeader == 43   // Routing
            || nextHeader == 44   // Fragment
            || nextHeader == 60   // Destination options
            || nextHeader == 51   // Authentication
            || nextHeader == 50;  // Encapsulating Security Payload
    }
    
    /**
     * Calculates the length of an IPv6 extension header.
     */
    private int processIPv6ExtensionLength(ByteBuf packet, byte headerType, int offset) {
        if (offset + 8 > packet.remaining()) return 0;
        
        // Most extension headers have length at offset+1 in 8-byte units
        if (headerType == 44) { // Fragment header is fixed 8 bytes
            return 8;
        }
        
        byte hdrExtLen = packet.get(offset + 1);
        return (hdrExtLen + 1) * 8;
    }
    
    /**
     * Creates a bitmask for a protocol ID.
     * Uses only the ordinal (lower 8 bits) as bit position.
     */
    private long createBitmask(int protocolId) {
        int ordinal = protocolId & 0xFF;
        if (ordinal >= 64) return 0; // Can't fit in long bitmask
        return 1L << ordinal;
    }
    
    /**
     * Encodes a protocol record into a long value.
     * 
     * Format:
     * bits 0-7:   ordinal (protocol index within pack)
     * bits 8-15:  pack ID
     * bits 16-31: classification mask
     * bits 32-47: header size in bytes
     * bits 48-63: offset in packet
     */
    private long encodeRecord(int protocolId, int offset, int size, int classification) {
        int ordinal = protocolId & 0xFF;
        int pack = (protocolId >> 8) & 0xFF;
        
        return ((offset & OFFSET_MASK) << OFFSET_SHIFT) |
               ((size & SIZE_MASK) << SIZE_SHIFT) |
               ((classification & CLASS_MASK) << CLASS_SHIFT) |
               ((pack & PACK_MASK) << PACK_SHIFT) |
               ((ordinal & ORDINAL_MASK) << ORDINAL_SHIFT);
    }
    
    /**
     * Decodes the ordinal from a protocol record.
     */
    public static int decodeOrdinal(long record) {
        return (int)((record >> ORDINAL_SHIFT) & ORDINAL_MASK);
    }
    
    /**
     * Decodes the pack ID from a protocol record.
     */
    public static int decodePack(long record) {
        return (int)((record >> PACK_SHIFT) & PACK_MASK);
    }
    
    /**
     * Decodes the classification mask from a protocol record.
     */
    public static int decodeClassification(long record) {
        return (int)((record >> CLASS_SHIFT) & CLASS_MASK);
    }
    
    /**
     * Decodes the size from a protocol record.
     */
    public static int decodeSize(long record) {
        return (int)((record >> SIZE_SHIFT) & SIZE_MASK);
    }
    
    /**
     * Decodes the offset from a protocol record.
     */
    public static int decodeOffset(long record) {
        return (int)((record >> OFFSET_SHIFT) & OFFSET_MASK);
    }
    
    /**
     * Reconstructs the full protocol ID from a record.
     */
    public static int decodeProtocolId(long record) {
        int ordinal = decodeOrdinal(record);
        int pack = decodePack(record);
        return (pack << 8) | ordinal;
    }
    
    // Internal result classes for dissection stages
    private static class L2Result {
        boolean found;
        int protocolId;
        int length;
        int nextProtocol; // EtherType for next layer
    }
    
    private static class L3Result {
        boolean found;
        int protocolId;
        int length;
        int nextProtocol; // IP protocol number
    }
    
    private static class L4Result {
        boolean found;
        int protocolId;
        int length;
    }
}