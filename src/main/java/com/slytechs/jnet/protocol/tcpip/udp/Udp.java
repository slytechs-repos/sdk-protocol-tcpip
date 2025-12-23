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
package com.slytechs.jnet.protocol.tcpip.udp;

import static com.slytechs.jnet.core.api.detail.DetailBuilder.*;

import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;

import com.slytechs.jnet.core.api.detail.DetailBuilder;
import com.slytechs.jnet.core.api.detail.Detailable;
import com.slytechs.jnet.core.api.memory.MemoryHandle.ShortHandle;
import com.slytechs.jnet.protocol.api.FixedHeader;
import com.slytechs.jnet.protocol.api.ProtocolId;
import com.slytechs.jnet.protocol.api.checksum.Checksums;

import static java.lang.foreign.MemoryLayout.*;

/**
 * User Datagram Protocol (UDP) header as defined in RFC 768.
 * 
 * <p>
 * UDP provides a simple, connectionless, unreliable datagram service. It adds
 * minimal overhead to IP, providing only multiplexing (via ports) and optional
 * error checking (via checksum). UDP is commonly used for applications that
 * prefer speed over reliability, such as DNS, DHCP, streaming media, and online
 * gaming.
 * </p>
 * 
 * <h2>Header Format</h2>
 * 
 * <pre>
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Source Port          |       Destination Port        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            Length             |           Checksum            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * 
 * <h2>Characteristics</h2>
 * <ul>
 * <li>Connectionless - no handshake required</li>
 * <li>Unreliable - no delivery guarantee, ordering, or retransmission</li>
 * <li>Lightweight - only 8 bytes of header overhead</li>
 * <li>Supports broadcast and multicast</li>
 * </ul>
 * 
 * {@snippet :
 * Udp udp = packet.getHeader(new Udp());
 * 
 * System.out.println("Source port: " + udp.srcPort());
 * System.out.println("Destination port: " + udp.dstPort());
 * System.out.println("Payload length: " + udp.payloadLength());
 * }
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see <a href="https://tools.ietf.org/html/rfc768">RFC 768 - User Datagram
 *      Protocol</a>
 */
public class Udp extends FixedHeader implements Detailable {

	/** Protocol HEADER_ID for UDP. */
	public static final int HEADER_ID = ProtocolId.UDP;

	/** UDP header length in bytes (fixed size). */
	public static final int HEADER_LENGTH = 8;

	/** UDP header memory layout. */
	public static final MemoryLayout LAYOUT = structLayout(
			U16_BE.withName("hdr_src_port"),
			U16_BE.withName("hdr_dst_port"),
			U16_BE.withName("hdr_length"),
			U16_BE.withName("hdr_checksum"));

	private static final ShortHandle SRC_PORT = new ShortHandle(LAYOUT, "hdr_src_port");
	private static final ShortHandle DST_PORT = new ShortHandle(LAYOUT, "hdr_dst_port");
	private static final ShortHandle LENGTH = new ShortHandle(LAYOUT, "hdr_length");
	private static final ShortHandle CHECKSUM = new ShortHandle(LAYOUT, "hdr_checksum");

	/**
	 * Constructs a new UDP header.
	 */
	public Udp() {
		super(HEADER_ID, LAYOUT);
	}

	/**
	 * Returns the source port field (16 bits).
	 * 
	 * <p>
	 * The source port is optional. A value of zero indicates no reply is expected.
	 * </p>
	 *
	 * @return the source port number (0-65535)
	 */
	public int srcPort() {
		return SRC_PORT.getShort(view()) & 0xFFFF;
	}

	/**
	 * Sets the source port field.
	 *
	 * @param port the source port (0-65535)
	 */
	public void setSrcPort(int port) {
		SRC_PORT.setShort(view(), 0, (short) port);
	}

	/**
	 * Returns the destination port field (16 bits).
	 *
	 * @return the destination port number (0-65535)
	 */
	public int dstPort() {
		return DST_PORT.getShort(view()) & 0xFFFF;
	}

	/**
	 * Sets the destination port field.
	 *
	 * @param port the destination port (0-65535)
	 */
	public void setDstPort(int port) {
		DST_PORT.setShort(view(), 0, (short) port);
	}

	/**
	 * Returns the length field (16 bits).
	 * 
	 * <p>
	 * The length includes the 8-byte UDP header plus the payload. Minimum value is
	 * 8 (header only, no payload).
	 * </p>
	 *
	 * @return the total UDP datagram length in bytes
	 */
	public int length() {
		return LENGTH.getShort(view()) & 0xFFFF;
	}

	/**
	 * Sets the length field.
	 *
	 * @param length the total UDP datagram length in bytes
	 */
	public void setLength(int length) {
		LENGTH.setShort(view(), 0, (short) length);
	}

	/**
	 * Returns the payload length in bytes.
	 * 
	 * <p>
	 * Calculated as the total length minus the 8-byte header.
	 * </p>
	 *
	 * @return the payload length in bytes
	 */
	public int payloadLength() {
		return length() - HEADER_LENGTH;
	}

	/**
	 * Returns the checksum field (16 bits).
	 * 
	 * <p>
	 * The checksum covers the UDP header, payload, and a pseudo-header derived from
	 * the IP layer. For IPv4, the checksum is optional (zero means not computed).
	 * For IPv6, the checksum is mandatory.
	 * </p>
	 *
	 * @return the checksum value
	 */
	public int checksum() {
		return CHECKSUM.getShort(view()) & 0xFFFF;
	}

	/**
	 * Returns the checksum as a hexadecimal string.
	 *
	 * @return checksum in "0x0000" format
	 */
	public String checksumAsHex() {
		return "0x%04x".formatted(checksum());
	}

	/**
	 * Computes the UDP checksum including IP pseudo-header.
	 * 
	 * <p>
	 * The UDP checksum covers the pseudo-header (derived from the IP header), the
	 * UDP header, and the UDP payload. The checksum field is treated as zero during
	 * computation.
	 * </p>
	 * 
	 * <p>
	 * For IPv4, a checksum of zero indicates no checksum was computed (optional).
	 * For IPv6, the checksum is mandatory.
	 * </p>
	 *
	 * {@snippet :
	 * int checksum = udp.computeChecksum(ip4.headerOffset(), udp.length(), false);
	 * udp.setChecksum(checksum);
	 * }
	 *
	 * @param ipOffset offset to IP header within the packet
	 * @param udpLen   total UDP datagram length (header + payload) in bytes
	 * @param isIp6    true for IPv6 pseudo-header, false for IPv4
	 * @return computed 16-bit checksum
	 */
	public int computeChecksum(long ipOffset, int udpLen, boolean isIp6) {
		MemorySegment segment = getPacket().view().segment();

		return Checksums.computeUdpChecksum(
				segment, ipOffset,
				segment, headerOffset(),
				udpLen, isIp6);
	}

	/**
	 * Sets the checksum field.
	 *
	 * @param checksum the checksum value
	 */
	public void setChecksum(int checksum) {
		CHECKSUM.setShort(view(), 0, (short) checksum);
	}

	/**
	 * Checks if the checksum is present.
	 * 
	 * <p>
	 * For IPv4, a checksum of zero indicates the checksum was not computed. For
	 * IPv6, the checksum is mandatory and zero is a valid computed value.
	 * </p>
	 *
	 * @return true if checksum is non-zero
	 */
	public boolean hasChecksum() {
		return checksum() != 0;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void buildDetail(DetailBuilder b) {
		int off = (int) headerOffset();

		b.header("User Datagram Protocol", "UDP", HEADER_ID, off, HEADER_LENGTH, h -> {
			h.summaryf("%d → %d Len=%d",
					srcPort(), dstPort(), length());

			h.field("Source Port", srcPort(), shortAt(off));
			h.field("Destination Port", dstPort(), shortAt(off + 2));
			h.field("Length", length(), shortAt(off + 4));
			h.fieldHex("Checksum", checksum(), 4, shortAt(off + 6));
		});
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		return toDetailString();
	}
}