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
package com.slytechs.jnet.protocol.tcpip.ip;

import com.slytechs.jnet.protocol.api.address.IpAddress;

/**
 * Common interface for IP protocol headers (IPv4 and IPv6).
 * 
 * <p>
 * Provides version-independent access to common IP header fields and
 * classification methods. Use this interface when code needs to work with
 * either IPv4 or IPv6 packets without version-specific handling.
 * </p>
 *
 * {@snippet :
 * Ip ip = packet.getHeader(ip4);
 * if (ip == null)
 * 	ip = packet.getHeader(ip6);
 * 
 * if (ip != null && !ip.isMulticast()) {
 * 	System.out.println(ip.src() + " -> " + ip.dst());
 * }
 * }
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see Ip4
 * @see Ip6
 */
public interface Ip {

	/**
	 * Returns the IP version.
	 *
	 * @return 4 for IPv4, 6 for IPv6
	 */
	int version();

	/**
	 * Returns the source address.
	 *
	 * @return the source IP address
	 */
	IpAddress src();

	/**
	 * Returns the destination address.
	 *
	 * @return the destination IP address
	 */
	IpAddress dst();

	/**
	 * Returns the upper-layer protocol identifier.
	 * 
	 * <p>
	 * For IPv4 this is the Protocol field. For IPv6 this is the Next Header field
	 * (or the final Next Header after extension headers).
	 * </p>
	 *
	 * @return the protocol number (e.g., 6 for TCP, 17 for UDP)
	 * @see IpProtocolResolver
	 */
	int protocol();

	/**
	 * Returns the hop limit (TTL).
	 * 
	 * <p>
	 * For IPv4 this is the Time To Live field. For IPv6 this is the Hop Limit
	 * field. Both serve the same purpose - limiting packet lifetime.
	 * </p>
	 *
	 * @return the hop limit (0-255)
	 */
	int ttl();

	/**
	 * Returns the Differentiated Services Code Point (6 bits).
	 * 
	 * <p>
	 * Used for QoS classification. Extracted from the TOS field (IPv4) or Traffic
	 * Class field (IPv6).
	 * </p>
	 *
	 * @return the DSCP value (0-63)
	 */
	int dscp();

	/**
	 * Returns the Explicit Congestion Notification field (2 bits).
	 * 
	 * <p>
	 * Extracted from the TOS field (IPv4) or Traffic Class field (IPv6).
	 * </p>
	 *
	 * @return the ECN value (0-3)
	 */
	int ecn();

	/**
	 * Returns the IP header length in bytes.
	 * 
	 * <p>
	 * For IPv4 this is variable (20-60 bytes). For IPv6 this is always 40 bytes
	 * (extension headers are not counted).
	 * </p>
	 *
	 * @return header length in bytes
	 */
	long headerLength();

	/**
	 * Returns the payload length in bytes.
	 * 
	 * <p>
	 * For IPv4 this is Total Length minus header length. For IPv6 this is the
	 * Payload Length field (which includes extension headers).
	 * </p>
	 *
	 * @return payload length in bytes
	 */
	int payloadLength();

	/**
	 * Checks if the packet is fragmented.
	 * 
	 * <p>
	 * For IPv4, checks the MF flag or non-zero fragment offset. For IPv6, checks
	 * for presence of Fragment extension header with MF or non-zero offset.
	 * </p>
	 *
	 * @return true if this packet is a fragment
	 */
	boolean isFragmented();

	/**
	 * Checks if the destination is a multicast address.
	 * 
	 * <p>
	 * IPv4: 224.0.0.0/4 (first octet 224-239). IPv6: ff00::/8.
	 * </p>
	 *
	 * @return true if destination is multicast
	 */
	boolean isMulticast();

	/**
	 * Checks if the destination is a loopback address.
	 * 
	 * <p>
	 * IPv4: 127.0.0.0/8. IPv6: ::1.
	 * </p>
	 *
	 * @return true if destination is loopback
	 */
	boolean isLoopback();

	/**
	 * Checks if the source or destination is a link-local address.
	 * 
	 * <p>
	 * IPv4: 169.254.0.0/16. IPv6: fe80::/10.
	 * </p>
	 *
	 * @return true if either address is link-local
	 */
	boolean isLinkLocal();
}