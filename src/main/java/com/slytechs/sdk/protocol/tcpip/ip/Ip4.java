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
package com.slytechs.sdk.protocol.tcpip.ip;

import java.lang.foreign.MemoryLayout;
import java.util.Map;

import com.slytechs.sdk.common.memory.MemoryHandle;
import com.slytechs.sdk.common.memory.MemoryHandle.ByteHandle;
import com.slytechs.sdk.common.memory.MemoryHandle.ShortHandle;
import com.slytechs.sdk.common.text.DataEmitter;
import com.slytechs.sdk.common.text.Textual;
import com.slytechs.sdk.common.text.format.Macro;
import com.slytechs.sdk.protocol.core.address.Ip4Address;
import com.slytechs.sdk.protocol.core.address.Ip4AddressMemory;
import com.slytechs.sdk.protocol.core.checksum.Checksums;
import com.slytechs.sdk.protocol.core.header.VariableHeader;
import com.slytechs.sdk.protocol.core.id.ProtocolIds;

import static java.lang.foreign.MemoryLayout.*;

/**
 * Internet Protocol version 4 (IPv4) header as defined in RFC 791.
 * 
 * <p>
 * IPv4 is the fourth version of the Internet Protocol and is a core protocol of
 * standards-based internetworking methods in the Internet and other
 * packet-switched networks. The IPv4 header is a minimum of 20 bytes and can
 * extend up to 60 bytes when options are present.
 * </p>
 * 
 * <h2>Header Format</h2>
 * 
 * <pre>
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version|  IHL  |Type of Service|          Total Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Identification        |Flags|      Fragment Offset    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Time to Live |    Protocol   |         Header Checksum       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Source Address                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Destination Address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * 
 * <h2>Flag Operations</h2>
 * <p>
 * IPv4 flags can be checked using the {@code is*()} methods and manipulated
 * using {@link #flags()}, {@link #setFlags(int)}, and {@link #clearFlags(int)}
 * with the {@code FLAG_*} constants.
 * </p>
 * 
 * {@snippet :
 * // Check flags
 * if (ip4.isDf()) { ... }
 * 
 * // Set Don't Fragment
 * ip4.setFlags(ip4.flags() | Ip4.FLAG_DF);
 * 
 * // Clear all flags
 * ip4.clearFlags(Ip4.FLAG_ALL);
 * }
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see Ip4Options
 * @see Ip
 */
public class Ip4 extends VariableHeader<Ip4Options> implements Ip {

	/** Protocol HEADER_ID for IPv4. */
	public static final int HEADER_ID = ProtocolIds.IPv4;

	/** Minimum IPv4 header length in bytes (without options). */
	public static final int MIN_HEADER_LENGTH = 20;

	/** Maximum IPv4 header length in bytes (with options). */
	public static final int MAX_HEADER_LENGTH = 60;

	// @formatter:off
	private static final String SUMMARY = "Internet Protocol Version 4, Src: {ip.src}, Dst: {ip.dst}";
	private static final DataEmitter<Ip4> IP4_EMITTER;
	static {
		IP4_EMITTER = new DataEmitter<>();

		IP4_EMITTER.macro("ip.dsfield.dscp.name", Macro.enumLookup(Map.of(
				0, "CS0", 8, "CS1", 16, "CS2", 24, "CS3", 32, "CS4", 40, "CS5", 48, "CS6", 56, "CS7", 46, "EF")));
		IP4_EMITTER.macro("ip.dsfield.ecn.name", Macro.enumLookup(Map.of(
				0, "Not-ECT", 1, "ECT(1)", 2, "ECT(0)", 3, "CE")));
		IP4_EMITTER.macro("ip.flags.str", Macro.flagList(
				new long[] { 0x8000, 0x4000, 0x2000 },
				new String[] { "RSV", "DF", "MF" },
				"none"));

		IP4_EMITTER.section(SUMMARY, sec -> sec
				.bitfield("{/1111 ..../} = Version: {>>}",
						"ip.version", 0, 4, Ip4::versionIhl)
				.bitfield("{/.... 1111/} = Header Length: {>> * 4} bytes ({>>})",
						"ip.hdr_len", 4, 4, Ip4::versionIhl)
				.field("Differentiated Services Field: {ip.dsfield:0x%02X}", Ip4::tos, "ip.dsfield", ds -> ds
						.bitfield("{/1111 11../} = Differentiated Services Codepoint: {@ip.dsfield.dscp.name} ({>>})",
								"ip.dsfield.dscp", 0, 6, Ip4::dscp)
						.bitfield("{/.... ..11/} = Explicit Congestion Notification: {@ip.dsfield.ecn.name} ({>>})",
								"ip.dsfield.ecn", 6, 2, Ip4::ecn))
				.field("Total Length", Ip4::totalLength, "ip.len")
				.field("Identification", "{ip.id:0x%04X} ({ip.id})", Ip4::id, "ip.id")
				.field("Flags: {ip.flags:0x%04X} ({ip.flags:@ip.flags.str})", Ip4::flagsOffset, "ip.flags", fl -> fl
						.bitfield("{/1... .... .... ..../} = Reserved: {@set}",
								"ip.flags.rsv", 15, 1, Ip4::flagsOffset)
						.bitfield("{/.1.. .... .... ..../} = Don't Fragment: {@set}",
								"ip.flags.df", 14, 1, Ip4::flagsOffset)
						.bitfield("{/..1. .... .... ..../} = More Fragments: {@set}",
								"ip.flags.mf", 13, 1, Ip4::flagsOffset)
						.bitfield("{/...1 1111 1111 1111/} = Fragment Offset: {>>}",
								"ip.frag_offset", 0, 13, Ip4::flagsOffset))
				.field("Time to Live", Ip4::ttl, "ip.ttl")
				.field("Protocol", Ip4::protocolName, "ip.proto")
				.field("Header Checksum", "{ip.checksum:0x%04X}", Ip4::checksum, "ip.checksum")
				.meta("Header checksum status", Ip4::checksumStatus, "ip.checksum.status")
				.field("Source Address", Ip4::src, "ip.src")
				.field("Destination Address", Ip4::dst, "ip.dst")
				.delegate((e, ip4, c) -> {
				    if (!ip4.hasOptions())
				        return e;
				    for (Ip4Options.Ip4Option opt : ip4.options()) {
				        if (opt instanceof Textual t)
				            t.emitText(e, c);
				        else {
				            e.summary("IPv4 Option - %s".formatted(opt.optionName()));
				            e.push();
				            e.field("Type", opt.optionName());
				            e.field("Length", String.valueOf(opt.optionLength()));
				            e.pop();
				        }
				    }
				    return e;
				}));
	}
	// @formatter:on

	/** IPv4 header memory layout. */
	public static final MemoryLayout LAYOUT = structLayout(
			U8_BE_A1.withName("hdr_version_ihl"),
			U8_BE_A1.withName("hdr_type_of_service"),
			U16_BE_A1.withName("hdr_total_length"),
			U16_BE_A1.withName("hdr_identification"),
			U16_BE_A1.withName("hdr_flags_frag_offset"),
			U8_BE_A1.withName("hdr_time_to_live"),
			U8_BE_A1.withName("hdr_protocol"),
			U16_BE_A1.withName("hdr_checksum"),
			Ip4AddressMemory.LAYOUT.withName("hdr_src_addr").withByteAlignment(1),
			Ip4AddressMemory.LAYOUT.withName("hdr_dst_addr").withByteAlignment(1)).withByteAlignment(1);

	private static final ByteHandle VERSION_IHL = new ByteHandle(LAYOUT, "hdr_version_ihl");
	private static final ByteHandle TOS = new ByteHandle(LAYOUT, "hdr_type_of_service");
	private static final ShortHandle TOTAL_LENGTH = new ShortHandle(LAYOUT, "hdr_total_length");
	private static final ShortHandle IDENTIFICATION = new ShortHandle(LAYOUT, "hdr_identification");
	private static final ShortHandle FLAGS_FRAG_OFFSET = new ShortHandle(LAYOUT, "hdr_flags_frag_offset");
	private static final ByteHandle TTL = new ByteHandle(LAYOUT, "hdr_time_to_live");
	private static final ByteHandle PROTOCOL = new ByteHandle(LAYOUT, "hdr_protocol");
	private static final ShortHandle CHECKSUM = new ShortHandle(LAYOUT, "hdr_checksum");

	private static final long SRC_ADDR_OFF = MemoryHandle.byteOffset(LAYOUT, "hdr_src_addr");
	private static final long DST_ADDR_OFF = MemoryHandle.byteOffset(LAYOUT, "hdr_dst_addr");

	/** Reserved flag (bit 15) - must be zero. */
	public static final int FLAG_RESERVED = 0x8000;

	/** Don't Fragment flag (bit 14). */
	public static final int FLAG_DF = 0x4000;

	/** More Fragments flag (bit 13). */
	public static final int FLAG_MF = 0x2000;

	/** All flags combined - use for clearing all flags. */
	public static final int FLAG_ALL = FLAG_RESERVED | FLAG_DF | FLAG_MF;

	/** Mask for fragment offset field (bits 0-12). */
	private static final int FRAG_OFFSET_MASK = 0x1FFF;

	private final Ip4AddressMemory srcAddress = new Ip4AddressMemory();
	private final Ip4AddressMemory dstAddress = new Ip4AddressMemory();
	private final Ip4Options options = new Ip4Options();

	/**
	 * Constructs a new IPv4 header.
	 */
	public Ip4() {
		super(HEADER_ID, LAYOUT);
	}

	/**
	 * Returns the Header Checksum field (16 bits).
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
	 * Clears the specified flags.
	 *
	 * {@snippet :
	 * // Clear Don't Fragment
	 * ip4.clearFlags(Ip4.FLAG_DF);
	 * 
	 * // Clear all flags
	 * ip4.clearFlags(Ip4.FLAG_ALL);
	 * }
	 *
	 * @param flags the flags to clear (use FLAG_* constants)
	 */
	public void clearFlags(int flags) {
		setFlags(flags() & ~flags);
	}

	/**
	 * Computes and sets the IPv4 header checksum.
	 * 
	 * <p>
	 * The checksum is calculated over the entire header with the checksum field
	 * treated as zero during computation.
	 * </p>
	 *
	 * {@snippet :
	 * ip4.computeChecksum();
	 * System.out.println("Checksum: " + ip4.checksumAsHex());
	 * }
	 */
	public int computeChecksum() {
		int computed = Checksums.computeIp4HeaderChecksum(view().segment(), view().start());

		return computed;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int dscp() {
		return (tos() >>> 2) & 0x3F;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Ip4Address dst() {
		return dstAddress;
	}

	/**
	 * Returns the destination address as an integer.
	 *
	 * @return destination address as 32-bit integer
	 */
	public int dstAsInt() {
		return dstAddress.asInt();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int ecn() {
		return tos() & 0x03;
	}

	/**
	 * Returns the flags field (3 bits).
	 * 
	 * <p>
	 * Use with FLAG_* constants for bitwise operations.
	 * </p>
	 *
	 * @return the raw flags value (bits 13-15 of flags/offset field)
	 * @see #setFlags(int)
	 * @see #clearFlags(int)
	 */
	public int flags() {
		return flagsOffset() & (FLAG_ALL);
	}

	/**
	 * Returns the combined flags and fragment offset field (16 bits).
	 *
	 * @return the raw 16-bit field value
	 */
	public int flagsOffset() {
		return FLAGS_FRAG_OFFSET.getShort(view()) & 0xFFFF;
	}

	/**
	 * Returns a human-readable string of active flags.
	 *
	 * @return space-separated flag names, or "none" if no flags set
	 */
	public String flagsToString() {
		StringBuilder sb = new StringBuilder();
		if (isReserved())
			sb.append("RESERVED ");
		if (isDf())
			sb.append("DF ");
		if (isMf())
			sb.append("MF ");
		return sb.length() > 0 ? sb.toString().trim() : "none";
	}

	/**
	 * Returns the fragment offset field (13 bits) in 8-byte units.
	 *
	 * @return fragment offset in 8-byte units
	 */
	public int fragOffset() {
		return flagsOffset() & FRAG_OFFSET_MASK;
	}

	/**
	 * Returns the fragment offset in bytes.
	 *
	 * @return fragment offset in bytes
	 */
	public int fragOffsetBytes() {
		return fragOffset() * 8;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean hasOptions() {
		return ihl() > 5;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public long headerLength() {
		return ihlBytes();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public long headerMinLength() {
		return MIN_HEADER_LENGTH;
	}

	/**
	 * Returns the Identification field (16 bits).
	 * 
	 * <p>
	 * Used for uniquely identifying fragments of an original IP datagram.
	 * </p>
	 *
	 * @return the identification value
	 */
	public int id() {
		return IDENTIFICATION.getShort(view()) & 0xFFFF;
	}

	/**
	 * Returns the Internet Header Length in 32-bit words (4 bits).
	 *
	 * @return header length in 32-bit words (5-15)
	 */
	public int ihl() {
		return versionIhl() & 0xF;
	}

	/**
	 * Returns the Internet Header Length in bytes.
	 *
	 * @return header length in bytes (20-60)
	 */
	public int ihlBytes() {
		return ihl() * 4;
	}

	/**
	 * Checks if the Don't Fragment (DF) flag is set.
	 *
	 * @return true if packet should not be fragmented
	 */
	public boolean isDf() {
		return (flagsOffset() & FLAG_DF) != 0;
	}

	/**
	 * Checks if this is the first fragment of a fragmented packet.
	 *
	 * @return true if MF is set and fragment offset is zero
	 */
	public boolean isFirstFragment() {
		return isMf() && fragOffset() == 0;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isFragmented() {
		return isMf() || fragOffset() != 0;
	}

	/**
	 * Checks if this is the last fragment of a fragmented packet.
	 *
	 * @return true if MF is not set and fragment offset is non-zero
	 */
	public boolean isLastFragment() {
		return !isMf() && fragOffset() != 0;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * IPv4 multicast addresses are in the range {@code 224.0.0.0/4}.
	 * </p>
	 */
	@Override
	public boolean isMulticast() {
		return dstAddress.isMulticast();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * IPv4 loopback addresses are in the range {@code 127.0.0.0/8}.
	 * </p>
	 */
	@Override
	public boolean isLoopback() {
		return dstAddress.isLoopback();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * IPv4 link-local addresses are in the range {@code 169.254.0.0/16}.
	 * </p>
	 */
	@Override
	public boolean isLinkLocal() {
		return dstAddress.isLinkLocal();
	}

	/**
	 * Checks if the destination is a broadcast address.
	 *
	 * @return true if destination is {@code 255.255.255.255}
	 */
	public boolean isBroadcast() {
		return dstAddress.isBroadcast();
	}

	/**
	 * Checks if the destination is a private address.
	 * 
	 * <p>
	 * Private ranges: {@code 10.0.0.0/8}, {@code 172.16.0.0/12},
	 * {@code 192.168.0.0/16}
	 * </p>
	 *
	 * @return true if destination is a private address
	 */
	public boolean isPrivate() {
		return dstAddress.isPrivate();
	}

	/**
	 * Checks if the More Fragments (MF) flag is set.
	 *
	 * @return true if more fragments follow
	 */
	public boolean isMf() {
		return (flagsOffset() & FLAG_MF) != 0;
	}

	/**
	 * Checks if this is a middle fragment of a fragmented packet.
	 *
	 * @return true if MF is set and fragment offset is non-zero
	 */
	public boolean isMiddleFragment() {
		return isMf() && fragOffset() != 0;
	}

	/**
	 * Checks if the reserved flag is set.
	 * 
	 * <p>
	 * This flag must be zero according to RFC 791.
	 * </p>
	 *
	 * @return true if reserved flag is set (should always be false)
	 */
	public boolean isReserved() {
		return (flagsOffset() & FLAG_RESERVED) != 0;
	}

	/**
	 * Checks if the destination is a unicast address.
	 *
	 * @return true if not broadcast or multicast
	 */
	public boolean isUnicast() {
		return !isBroadcast() && !isMulticast();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void onBindPacket() {
		srcAddress.bind(this, SRC_ADDR_OFF, 4);
		dstAddress.bind(this, DST_ADDR_OFF, 4);
		options.bind(getPacket(), optionsOffset(), optionsLength());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void onUnbindPacket() {
		srcAddress.unbind();
		dstAddress.unbind();
		options.unbind();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Ip4Options options() {
		if (!options.isBound())
			options.bind(getPacket(), optionsOffset(), optionsLength());
		return options;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public long optionsLength() {
		return ihlBytes() - MIN_HEADER_LENGTH;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public long optionsOffset() {
		return headerOffset() + MIN_HEADER_LENGTH;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int payloadLength() {
		return totalLength() - ihlBytes();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int protocol() {
		return PROTOCOL.getByte(view()) & 0xFF;
	}

	/**
	 * Sets the Header Checksum field.
	 *
	 * @param checksum the checksum value
	 */
	public void setChecksum(int checksum) {
		CHECKSUM.setShort(view(), 0, (short) checksum);
	}

	/**
	 * Sets DSCP and ECN fields within the TOS byte.
	 *
	 * @param dscp the DSCP value (0-63)
	 * @param ecn  the ECN value (0-3)
	 */
	public void setDscpEcn(int dscp, int ecn) {
		int tos = ((dscp & 0x3F) << 2) | (ecn & 0x03);
		setTos(tos);
	}

	/**
	 * Sets the destination address from an integer.
	 *
	 * @param addr the address as 32-bit integer
	 */
	public void setDst(int addr) {
		dstAddress.setInt(addr);
	}

	/**
	 * Sets the destination address from a byte array.
	 *
	 * @param bytes 4-byte address
	 * @throws IllegalArgumentException if bytes is not 4 bytes
	 */
	public void setDstFromBytes(byte[] bytes) {
		dstAddress.setBytes(bytes);
	}

	/**
	 * Sets the destination address from a string.
	 *
	 * @param ipStr dotted-decimal format (e.g., "192.168.1.1")
	 */
	public void setDstFromString(String ipStr) {
		setDst(Ip4Address.parseIpv4Address(ipStr));
	}

	/**
	 * Sets the flags field.
	 *
	 * {@snippet :
	 * ip4.setFlags(ip4.flags() | Ip4.FLAG_DF);
	 * }
	 *
	 * @param flags the flags value (use FLAG_* constants)
	 * @see #clearFlags(int)
	 */
	public void setFlags(int flags) {
		int offset = fragOffset();
		int newValue = (flags & FLAG_ALL) | (offset & FRAG_OFFSET_MASK);
		FLAGS_FRAG_OFFSET.setShort(view(), 0, (short) newValue);
	}

	/**
	 * Sets the fragment offset field.
	 *
	 * @param offset fragment offset in 8-byte units
	 */
	public void setFragOffset(int offset) {
		int flags = flags();
		int newValue = flags | (offset & FRAG_OFFSET_MASK);
		FLAGS_FRAG_OFFSET.setShort(view(), 0, (short) newValue);
	}

	/**
	 * Sets the Identification field.
	 *
	 * @param id the identification value
	 */
	public void setHeaderId(int id) {
		IDENTIFICATION.setShort(view(), 0, (short) id);
	}

	/**
	 * Sets the Internet Header Length in 32-bit words.
	 *
	 * @param ihl header length in 32-bit words (5-15)
	 */
	public void setIhl(int ihl) {
		int version = version();
		setVersionIhl(version, ihl);
	}

	/**
	 * Sets the Protocol field.
	 *
	 * @param protocol the protocol number
	 * @see IpProtocolResolver
	 */
	public void setProtocol(int protocol) {
		PROTOCOL.setByte(view(), 0, (byte) protocol);
	}

	/**
	 * Sets the source address from an integer.
	 *
	 * @param addr the address as 32-bit integer
	 */
	public void setSrc(int addr) {
		srcAddress.setInt(addr);
	}

	/**
	 * Sets the source address from a byte array.
	 *
	 * @param bytes 4-byte address
	 * @throws IllegalArgumentException if bytes is not 4 bytes
	 */
	public void setSrcFromBytes(byte[] bytes) {
		srcAddress.setBytes(bytes);
	}

	/**
	 * Sets the source address from a string.
	 *
	 * @param ipStr dotted-decimal format (e.g., "192.168.1.1")
	 */
	public void setSrcFromString(String ipStr) {
		setSrc(Ip4Address.parseIpv4Address(ipStr));
	}

	/**
	 * Sets the Type of Service field.
	 *
	 * @param tos the TOS value
	 */
	public void setTos(int tos) {
		TOS.setByte(view(), 0, (byte) tos);
	}

	/**
	 * Sets the Total Length field.
	 *
	 * @param length total packet length in bytes
	 */
	public void setTotalLength(int length) {
		TOTAL_LENGTH.setShort(view(), 0, (short) length);
	}

	/**
	 * Sets the Time To Live field.
	 *
	 * @param ttl the TTL value (0-255)
	 */
	public void setTtl(int ttl) {
		TTL.setByte(view(), 0, (byte) ttl);
	}

	/**
	 * Sets the combined Version and IHL field.
	 *
	 * @param version the IP version (4 bits)
	 * @param ihl     the header length in 32-bit words (4 bits)
	 */
	public void setVersionIhl(int version, int ihl) {
		int value = ((version & 0xF) << 4) | (ihl & 0xF);
		VERSION_IHL.setByte(view(), 0, (byte) value);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Ip4Address src() {
		return srcAddress;
	}

	/**
	 * Returns the source address as an integer.
	 *
	 * @return source address as 32-bit integer
	 */
	public int srcAsInt() {
		return srcAddress.asInt();
	}

	/**
	 * Returns the Type of Service field (8 bits).
	 *
	 * @return the TOS value
	 */
	public int tos() {
		return TOS.getByte(view()) & 0xFF;
	}

	/**
	 * Returns the Total Length field (16 bits).
	 * 
	 * <p>
	 * This is the entire packet size in bytes, including header and data.
	 * </p>
	 *
	 * @return total packet length in bytes
	 */
	public int totalLength() {
		return TOTAL_LENGTH.getShort(view()) & 0xFFFF;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int ttl() {
		return TTL.getByte(view()) & 0xFF;
	}

	/**
	 * Returns the IP version field (4 bits).
	 *
	 * @return 4 for IPv4
	 */
	@Override
	public int version() {
		return (versionIhl() >>> 4) & 0xF;
	}

	/**
	 * Returns the combined Version and IHL field (8 bits).
	 *
	 * @return the raw byte value
	 */
	public int versionIhl() {
		return VERSION_IHL.getByte(view()) & 0xFF;
	}

	public String protocolName() {
		return IpProtocolResolver.resolve(protocol());
	}

	private String checksumStatus() {
		return "Unverified";
	}

	/**
	 * @see com.slytechs.sdk.common.text.Textual#dataEmitter()
	 */
	@Override
	public DataEmitter<?> dataEmitter() {
		return IP4_EMITTER;
	}

}