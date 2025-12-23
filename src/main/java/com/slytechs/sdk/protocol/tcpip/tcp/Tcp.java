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
package com.slytechs.sdk.protocol.tcpip.tcp;

import static com.slytechs.sdk.common.detail.DetailBuilder.*;

import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;

import com.slytechs.sdk.common.detail.DetailBuilder;
import com.slytechs.sdk.common.detail.Detailable;
import com.slytechs.sdk.common.memory.MemoryHandle.IntHandle;
import com.slytechs.sdk.common.memory.MemoryHandle.ShortHandle;
import com.slytechs.sdk.protocol.core.ProtocolId;
import com.slytechs.sdk.protocol.core.VariableHeader;
import com.slytechs.sdk.protocol.core.checksum.Checksums;

import static java.lang.foreign.MemoryLayout.*;

/**
 * Transmission Control Protocol (TCP) header as defined in RFC 793.
 * 
 * <p>
 * TCP provides reliable, ordered, and error-checked delivery of a stream of
 * octets between applications running on hosts communicating via an IP network.
 * The TCP header is a minimum of 20 bytes and can extend up to 60 bytes when
 * options are present.
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
 * |                        Sequence Number                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Acknowledgment Number                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Data |       |N|C|E|U|A|P|R|S|F|                             |
 * | Offset| Rsrvd |S|W|C|R|C|S|S|Y|I|           Window            |
 * |       |       | |R|E|G|K|H|T|N|N|                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Checksum            |         Urgent Pointer        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * 
 * <h2>Flag Operations</h2>
 * <p>
 * TCP flags can be checked using the {@code is*()} methods and manipulated
 * using {@link #flags()}, {@link #setFlags(int)}, and {@link #clearFlags(int)}
 * with the {@code FLAG_*} constants.
 * </p>
 * 
 * <pre>{@code
 * // Check flags
 * if (tcp.isSyn() && !tcp.isAck()) { ... }
 * 
 * // Set flags
 * tcp.setFlags(tcp.flags() | Tcp.FLAG_ACK | Tcp.FLAG_PSH);
 * 
 * // Clear flags
 * tcp.clearFlags(Tcp.FLAG_PSH | Tcp.FLAG_URG);
 * }</pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see TcpOptions
 */
public class Tcp extends VariableHeader<TcpOptions> implements Detailable {

	/** Protocol HEADER_ID for TCP. */
	public static final int HEADER_ID = ProtocolId.TCP;

	/** Minimum TCP header length in bytes (without options). */
	public static final int MIN_HEADER_LENGTH = 20;

	/** Maximum TCP header length in bytes (with options). */
	public static final int MAX_HEADER_LENGTH = 60;

	/** TCP header memory layout. */
	public static final MemoryLayout LAYOUT = structLayout(
			U16_BE_A1.withName("hdr_src_port"),
			U16_BE_A1.withName("hdr_dst_port"),
			U32_BE_A1.withName("hdr_seq_number"),
			U32_BE_A1.withName("hdr_ack_number"),
			U16_BE_A1.withName("hdr_hlen_flags"),
			U16_BE_A1.withName("hdr_window"),
			U16_BE_A1.withName("hdr_checksum"),
			U16_BE_A1.withName("hdr_urgent_pointer"));

	private static final ShortHandle SRC_PORT = new ShortHandle(LAYOUT, "hdr_src_port");
	private static final ShortHandle DST_PORT = new ShortHandle(LAYOUT, "hdr_dst_port");
	private static final IntHandle SEQ_NUMBER = new IntHandle(LAYOUT, "hdr_seq_number");
	private static final IntHandle ACK_NUMBER = new IntHandle(LAYOUT, "hdr_ack_number");
	private static final ShortHandle HLEN_FLAGS = new ShortHandle(LAYOUT, "hdr_hlen_flags");
	private static final ShortHandle WINDOW = new ShortHandle(LAYOUT, "hdr_window");
	private static final ShortHandle CHECKSUM = new ShortHandle(LAYOUT, "hdr_checksum");
	private static final ShortHandle URGENT_POINTER = new ShortHandle(LAYOUT, "hdr_urgent_pointer");

	/** FIN flag - No more data from sender. */
	public static final int FLAG_FIN = 0x0001;

	/** SYN flag - Synchronize sequence numbers. */
	public static final int FLAG_SYN = 0x0002;

	/** RST flag - Reset the connection. */
	public static final int FLAG_RST = 0x0004;

	/** PSH flag - Push function. */
	public static final int FLAG_PSH = 0x0008;

	/** ACK flag - Acknowledgment field is significant. */
	public static final int FLAG_ACK = 0x0010;

	/** URG flag - Urgent pointer field is significant. */
	public static final int FLAG_URG = 0x0020;

	/** ECE flag - ECN-Echo (RFC 3168). */
	public static final int FLAG_ECE = 0x0040;

	/** CWR flag - Congestion Window Reduced (RFC 3168). */
	public static final int FLAG_CWR = 0x0080;

	/** NS flag - ECN-nonce concealment protection (RFC 3540). */
	public static final int FLAG_NS = 0x0100;

	/** All flags, use for clearing all flags */
	public static final int FLAG_ALL = FLAG_FIN
			| FLAG_SYN | FLAG_RST | FLAG_PSH | FLAG_ACK
			| FLAG_URG | FLAG_ECE | FLAG_CWR | FLAG_NS;

	private final TcpOptions options = new TcpOptions();

	/**
	 * Constructs a new TCP header.
	 */
	public Tcp() {
		super(HEADER_ID, LAYOUT);
	}

	/**
	 * Returns the acknowledgment number field (32 bits).
	 * 
	 * <p>
	 * If the ACK control bit is set, this field contains the value of the next
	 * sequence number the sender of the segment is expecting to receive.
	 * </p>
	 *
	 * @return the acknowledgment number as an unsigned 32-bit value
	 */
	public long ack() {
		return ACK_NUMBER.getInt(view()) & 0xFFFFFFFFL;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void buildDetail(DetailBuilder b) {
		int off = (int) headerOffset();

		b.header("Transmission Control Protocol", "TCP", HEADER_ID, off, (int) headerLength(), h -> {
			h.summaryf("%d → %d [%s] Seq=%d Ack=%d Win=%d",
					srcPort(), dstPort(), flagsToString(),
					seq(), ack(), window());

			h.field("Source Port", srcPort(), shortAt(off));
			h.field("Destination Port", dstPort(), shortAt(off + 2));
			h.field("Sequence Number", seq(), intAt(off + 4));
			h.field("Acknowledgment Number", ack(), intAt(off + 8));

			h.expandField("Data Offset/Flags", hlenFlags(),
					String.format("Offset=%d, Flags=%s", hlenBytes(), flagsToString()),
					shortAt(off + 12), f -> {
						f.field("Data Offset", hlen(), hlenBytes() + " bytes", bitsAt(off * 8L + 96, 4));
						f.field("Reserved", reserved(), bitsAt(off * 8L + 100, 3));
						f.field("NS", isNs() ? 1 : 0, bitsAt(off * 8L + 103, 1));
						f.field("CWR", isCwr() ? 1 : 0, bitsAt(off * 8L + 104, 1));
						f.field("ECE", isEce() ? 1 : 0, bitsAt(off * 8L + 105, 1));
						f.field("URG", isUrg() ? 1 : 0, bitsAt(off * 8L + 106, 1));
						f.field("ACK", isAck() ? 1 : 0, bitsAt(off * 8L + 107, 1));
						f.field("PSH", isPsh() ? 1 : 0, bitsAt(off * 8L + 108, 1));
						f.field("RST", isRst() ? 1 : 0, bitsAt(off * 8L + 109, 1));
						f.field("SYN", isSyn() ? 1 : 0, bitsAt(off * 8L + 110, 1));
						f.field("FIN", isFin() ? 1 : 0, bitsAt(off * 8L + 111, 1));
					});

			int computedChecksum = computeChecksum(off-20, hlenBytes(), false);
			h.field("Window", window(), shortAt(off + 14));
			h.fieldHex("Checksum", checksum(), 4, shortAt(off + 16));
			h.fieldHex("Computed checksum", computedChecksum, 4, shortAt(off + 16));
			h.field("Urgent Pointer", urgent(), shortAt(off + 18));

			// Options as nested sections
			if (hasOptions()) {
			    for (TcpOptions.TcpOption opt : options()) {
		            h.section(opt.optionName(), opt.optionAbbr(), s -> opt.buildDetail(s));
			    }
			}
		});
	}

	/**
	 * Returns the checksum field (16 bits).
	 * 
	 * <p>
	 * The checksum covers the TCP header, payload, and a pseudo-header derived from
	 * the IP layer.
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
		return Checksums.checksumAsHex(checksum());
	}

	/**
	 * Computes the TCP checksum including IP pseudo-header.
	 * 
	 * <p>
	 * The TCP checksum covers the pseudo-header (derived from the IP header), the
	 * TCP header, and the TCP payload. The checksum field is treated as zero during
	 * computation.
	 * </p>
	 *
	 * {@snippet :
	 * // With IPv4
	 * int checksum = tcp.computeChecksum(ip4.headerOffset(), tcp.hlenBytes() + payloadLen, false);
	 * tcp.setChecksum(checksum);
	 * 
	 * // With IPv6
	 * int checksum = tcp.computeChecksum(ip6.headerOffset(), tcp.hlenBytes() + payloadLen, true);
	 * tcp.setChecksum(checksum);
	 * }
	 *
	 * @param ipOffset offset to IP header within the packet
	 * @param tcpLen   total TCP segment length (header + payload) in bytes
	 * @param isIp6    true for IPv6 pseudo-header, false for IPv4
	 * @return computed 16-bit checksum
	 */
	public int computeChecksum(long ipOffset, int tcpLen, boolean isIp6) {
		MemorySegment segment = getPacket().view().segment();

		return Checksums.computeTcpChecksum(
				segment, ipOffset,
				segment, headerOffset(),
				tcpLen, isIp6);
	}

	/**
	 * Clears the specified flags.
	 *
	 * {@snippet :
	 * tcp.clearFlags(Tcp.FLAG_PSH | Tcp.FLAG_URG);
	 * }
	 *
	 * @param flags the flags to clear (use FLAG_* constants)
	 */

	public void clearFlags(int flags) {
		setFlags(flags() & ~flags);
	}

	/**
	 * Computes and sets the TCP checksum.
	 * 
	 * @throws UnsupportedOperationException TCP checksum requires IP pseudo-header
	 */
	public void computeChecksum() {
		throw new UnsupportedOperationException("TCP checksum computation requires IP pseudo-header");
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
	 * Returns the flags field (9 bits).
	 * 
	 * <p>
	 * Use with FLAG_* constants for bitwise operations.
	 * </p>
	 *
	 * @return the raw flags value
	 * @see #setFlags(int)
	 * @see #clearFlags(int)
	 */
	public int flags() {
		return hlenFlags() & 0x01FF;
	}

	/**
	 * Returns a human-readable string of active TCP flags.
	 *
	 * @return space-separated flag names, or "none" if no flags set
	 */
	public String flagsToString() {
		StringBuilder sb = new StringBuilder();
		if (isNs())
			sb.append("NS ");
		if (isCwr())
			sb.append("CWR ");
		if (isEce())
			sb.append("ECE ");
		if (isUrg())
			sb.append("URG ");
		if (isAck())
			sb.append("ACK ");
		if (isPsh())
			sb.append("PSH ");
		if (isRst())
			sb.append("RST ");
		if (isSyn())
			sb.append("SYN ");
		if (isFin())
			sb.append("FIN ");

		return sb.length() > 0 ? sb.toString().trim() : "none";
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean hasOptions() {
		return hlen() > 5;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public long headerLength() {
		return hlenBytes();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public long headerMinLength() {
		return MIN_HEADER_LENGTH;
	}

	/**
	 * Returns the data offset (header length) in 32-bit words.
	 *
	 * @return header length in 32-bit words (5-15)
	 */
	public int hlen() {
		return (hlenFlags() >>> 12) & 0xF;
	}

	/**
	 * Returns the header length in bytes.
	 *
	 * @return header length in bytes (20-60)
	 */
	public int hlenBytes() {
		return hlen() * 4;
	}

	/**
	 * Returns the combined data offset, reserved, and flags field (16 bits).
	 *
	 * @return the raw 16-bit field value
	 */
	public int hlenFlags() {
		return HLEN_FLAGS.getShort(view()) & 0xFFFF;
	}

	/**
	 * Checks if the ACK flag is set.
	 *
	 * @return true if acknowledgment field is significant
	 */
	public boolean isAck() {
		return (flags() & FLAG_ACK) != 0;
	}

	/**
	 * Checks if the CWR flag is set.
	 *
	 * @return true if congestion window reduced
	 */
	public boolean isCwr() {
		return (flags() & FLAG_CWR) != 0;
	}

	/**
	 * Checks if the ECE flag is set.
	 *
	 * @return true if ECN-Echo is set
	 */
	public boolean isEce() {
		return (flags() & FLAG_ECE) != 0;
	}

	/**
	 * Checks if the FIN flag is set.
	 *
	 * @return true if no more data from sender
	 */
	public boolean isFin() {
		return (flags() & FLAG_FIN) != 0;
	}

	/**
	 * Checks if the NS flag is set.
	 *
	 * @return true if ECN-nonce concealment protection is set
	 */
	public boolean isNs() {
		return (flags() & FLAG_NS) != 0;
	}

	/**
	 * Checks if the PSH flag is set.
	 *
	 * @return true if push function is requested
	 */
	public boolean isPsh() {
		return (flags() & FLAG_PSH) != 0;
	}

	/**
	 * Checks if the RST flag is set.
	 *
	 * @return true if connection reset
	 */
	public boolean isRst() {
		return (flags() & FLAG_RST) != 0;
	}

	/**
	 * Checks if the SYN flag is set.
	 *
	 * @return true if synchronize sequence numbers
	 */
	public boolean isSyn() {
		return (flags() & FLAG_SYN) != 0;
	}

	/**
	 * Checks if this is a SYN-ACK segment.
	 *
	 * @return true if both SYN and ACK flags are set
	 */
	public boolean isSynAck() {
		return isSyn() && isAck();
	}

	/**
	 * Checks if this is a pure SYN segment (connection initiation).
	 *
	 * @return true if SYN is set and ACK is not set
	 */
	public boolean isSynOnly() {
		return isSyn() && !isAck();
	}

	/**
	 * Checks if the URG flag is set.
	 *
	 * @return true if urgent pointer field is significant
	 */
	public boolean isUrg() {
		return (flags() & FLAG_URG) != 0;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void onBindPacket() {
		options.bind(getPacket(), optionsOffset(), optionsLength());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void onUnbindPacket() {
		options.unbind();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public TcpOptions options() {
		if (!options.isBound())
			options.bind(this, optionsOffset(), optionsLength());
		return options;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public long optionsLength() {
		return hlenBytes() - MIN_HEADER_LENGTH;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public long optionsOffset() {
		return headerOffset() + MIN_HEADER_LENGTH;
	}

	/**
	 * Returns the reserved bits (3 bits).
	 * 
	 * <p>
	 * These bits are reserved for future use and should be zero.
	 * </p>
	 *
	 * @return the reserved bits value
	 */
	public int reserved() {
		return (hlenFlags() >>> 9) & 0x7;
	}

	/**
	 * Returns the sequence number field (32 bits).
	 * 
	 * <p>
	 * If the SYN flag is set, this is the initial sequence number. Otherwise, it is
	 * the sequence number of the first data octet in this segment.
	 * </p>
	 *
	 * @return the sequence number as an unsigned 32-bit value
	 */
	public long seq() {
		return SEQ_NUMBER.getInt(view()) & 0xFFFFFFFFL;
	}

	/**
	 * Sets the acknowledgment number field.
	 *
	 * @param ackNum the acknowledgment number
	 */
	public void setAck(long ackNum) {
		ACK_NUMBER.setInt(view(), 0, (int) ackNum);
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
	 * Sets the destination port field.
	 *
	 * @param port the destination port (0-65535)
	 */
	public void setDstPort(int port) {
		DST_PORT.setShort(view(), 0, (short) port);
	}

	/**
	 * Sets the flags field.
	 * 
	 * {@snippet :
	 * tcp.setFlags(tcp.flags() | Tcp.FLAG_ACK | Tcp.FLAG_PSH);
	 * }
	 * 
	 * @param flags the flags value (use FLAG_* constants)
	 * @see #clearFlags(int)
	 * 
	 */
	public void setFlags(int flags) {
		int hlen = hlen();
		setHlenFlags((hlen << 12) | (flags & 0x01FF));
	}

	/**
	 * Sets the data offset (header length) in 32-bit words.
	 *
	 * @param hlen header length in 32-bit words (5-15)
	 */
	public void setHlen(int hlen) {
		int flags = hlenFlags() & 0x0FFF;
		setHlenFlags(((hlen & 0xF) << 12) | flags);
	}

	/**
	 * Sets the combined data offset, reserved, and flags field.
	 *
	 * @param value the 16-bit field value
	 */
	public void setHlenFlags(int value) {
		HLEN_FLAGS.setShort(view(), 0, (short) value);
	}

	/**
	 * Sets the sequence number field.
	 *
	 * @param seqNum the sequence number
	 */
	public void setSeq(long seqNum) {
		SEQ_NUMBER.setInt(view(), 0, (int) seqNum);
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
	 * Sets the urgent pointer field.
	 *
	 * @param urgentPointer the urgent pointer value
	 */
	public void setUrgent(int urgentPointer) {
		URGENT_POINTER.setShort(view(), 0, (short) urgentPointer);
	}

	/**
	 * Sets the window size field.
	 *
	 * @param window the window size (0-65535)
	 */
	public void setWindow(int window) {
		WINDOW.setShort(view(), 0, (short) window);
	}

	/**
	 * Returns the source port field (16 bits).
	 *
	 * @return the source port number (0-65535)
	 */
	public int srcPort() {
		return SRC_PORT.getShort(view()) & 0xFFFF;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		return toDetailString();
	}

	/**
	 * Returns the urgent pointer field (16 bits).
	 * 
	 * <p>
	 * This field is only significant when the URG flag is set. It indicates the
	 * offset from the sequence number indicating the last urgent data byte.
	 * </p>
	 *
	 * @return the urgent pointer value
	 */
	public int urgent() {
		return URGENT_POINTER.getShort(view()) & 0xFFFF;
	}

	/**
	 * Returns the window size field (16 bits).
	 * 
	 * <p>
	 * The number of data octets beginning with the one indicated in the
	 * acknowledgment field which the sender of this segment is willing to accept.
	 * </p>
	 *
	 * @return the window size (0-65535)
	 */
	public int window() {
		return WINDOW.getShort(view()) & 0xFFFF;
	}
}