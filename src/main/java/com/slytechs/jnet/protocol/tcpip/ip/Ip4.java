/*
 * Sly Technologies Free License
 * 
 * Copyright 2024 Sly Technologies Inc.
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

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

import com.slytechs.jnet.core.api.format.StructFormat;
import com.slytechs.jnet.core.api.format.StructFormattable;
import com.slytechs.jnet.protocol.api.address.Ip4Address;
import com.slytechs.jnet.protocol.api.address.Ip4AddressMemory;
import com.slytechs.jnet.protocol.api.address.Ip4AddressRecord;
import com.slytechs.jnet.protocol.api.checksum.Checksums;
import com.slytechs.jnet.protocol.tcpip.Tcpip;

import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;
import static java.lang.foreign.ValueLayout.*;

/**
 * Java binding for IPv4 header with correct 20-byte layout. IPv4 header format
 * as defined in RFC 791.
 */
public class Ip4 extends Ip implements StructFormattable {
	public static final int ID = Tcpip.IPv4_ID;
	public static final int LENGTH = 20;

	public static final MemoryLayout LAYOUT$BIG$SIZE_20 = structLayout(
			JAVA_BYTE.withName("hdr_version_ihl"), // Version (4) + IHL (4) = 8 bits
			JAVA_BYTE.withName("hdr_type_of_service"), // Type of Service = 8 bits
			JAVA_SHORT.withName("hdr_total_length").withOrder(ByteOrder.BIG_ENDIAN), // Total Length = 16 bits
			JAVA_SHORT.withName("hdr_packet_id").withOrder(ByteOrder.BIG_ENDIAN), // Identification = 16 bits
			JAVA_SHORT.withName("hdr_frag_offset").withOrder(ByteOrder.BIG_ENDIAN), // Flags (3) + Fragment Offset (13)
																					// = 16 bits
			JAVA_BYTE.withName("hdr_time_to_live"), // Time to Live = 8 bits
			JAVA_BYTE.withName("hdr_protocol"), // Protocol = 8 bits
			JAVA_SHORT.withName("hdr_checksum").withOrder(ByteOrder.BIG_ENDIAN), // Header Checksum = 16 bits
			Ip4AddressMemory.LAYOUT.withName("hdr_src_addr"), // Source Address = 32 bits
			Ip4AddressMemory.LAYOUT.withName("hdr_dst_addr") // Destination Address = 32 bits
	);

	public static final MemoryLayout LAYOUT = LAYOUT$BIG$SIZE_20;

	private static final VarHandle VERSION_IHL = LAYOUT.varHandle(groupElement("hdr_version_ihl"));
	private static final VarHandle TOS = LAYOUT.varHandle(groupElement("hdr_type_of_service"));
	private static final VarHandle TOTAL_LENGTH = LAYOUT.varHandle(groupElement("hdr_total_length"));
	private static final VarHandle PACKET_ID = LAYOUT.varHandle(groupElement("hdr_packet_id"));
	private static final VarHandle FRAG_OFFSET = LAYOUT.varHandle(groupElement("hdr_frag_offset"));
	private static final VarHandle TTL = LAYOUT.varHandle(groupElement("hdr_time_to_live"));
	private static final VarHandle PROTOCOL = LAYOUT.varHandle(groupElement("hdr_protocol"));
	private static final VarHandle CHECKSUM = LAYOUT.varHandle(groupElement("hdr_checksum"));
	private static final long SRC_ADDR_OFF = LAYOUT.byteOffset(groupElement("hdr_src_addr"));
	private static final long DST_ADDR_OFF = LAYOUT.byteOffset(groupElement("hdr_dst_addr"));

	private final Ip4AddressMemory srcAddress = new Ip4AddressMemory();
	private final Ip4AddressMemory dstAddress = new Ip4AddressMemory();

	public Ip4() {
		super(ID, LAYOUT);
	}

	public Ip4(Arena arena) {
		super(ID, LAYOUT, arena);

		onBindPacket();
	}

	public Ip4(MemorySegment pointer) {
		super(ID, LAYOUT, pointer);

		onBindPacket();
	}

	public Ip4(MemorySegment seg, long offset) {
		super(ID, LAYOUT, seg, offset);

		onBindPacket();
	}

	@Override
	public int headerLength() {
		return ihl() * 4;
	}

	/**
	 * Returns the Header Checksum field (16 bits).
	 */
	public int checksum() {
		return (short) CHECKSUM.get(asMemorySegment(), segmentOffset()) & 0xFFFF;
	}

	/**
	 * Returns true if the Don't Fragment flag is set.
	 */
	public boolean dontFragment() {
		return (fragOffset() & 0x4000) != 0;
	}

	/**
	 * Returns the DSCP portion of the TOS field (6 bits).
	 */
	public int dscp() {
		return (tos() >>> 2) & 0x3F;
	}

	/**
	 * Returns the destination address as an Ip4Address object.
	 */
	@Override
	public Ip4Address dst() {
		return dstAddress;
	}

	/**
	 * Returns the destination address as an integer.
	 */
	public int dstAsInt() {
		return dstAddress.asInt();
	}

	/**
	 * Returns the ECN portion of the TOS field (2 bits).
	 */
	public int ecn() {
		return tos() & 0x03;
	}

	/**
	 * Returns the flags field as a flag set.
	 */
	public Ip4Flags flags() {
		return new Ip4Flags((fragOffset() >>> 13) & 0x07);
	}

	@Override
	public StructFormat format(StructFormat p) {
		return p.openln("Ip4")
				.println("version", version())
				.println("ihl", ihl() + " (" + ihlBytes() + " bytes)")
				.println("tos", tos() + " (dscp=" + dscp() + ", ecn=" + ecn() + ")")
				.println("length", length())
				.println("id", id())
				.println("flags", flags().toString())
				.println("fragOffset", fragOffsetValue() + " (" + fragOffsetBytes() + " bytes)")
				.println("ttl", ttl())
				.println("protocol", protocol())
				.println("checksum", "0x" + Integer.toHexString(checksum()))
				.println("src", src())
				.println("dst", dst())
				.close();
	}

	/**
	 * Returns the combined Flags + Fragment Offset field (16 bits).
	 */
	public int fragOffset() {
		return (short) FRAG_OFFSET.get(asMemorySegment(), segmentOffset()) & 0xFFFF;
	}

	/**
	 * Returns the fragment offset in bytes.
	 */
	public int fragOffsetBytes() {
		return fragOffsetValue() * 8;
	}

	/**
	 * Returns the fragment offset value (13 bits, in 8-byte units).
	 */
	public int fragOffsetValue() {
		return fragOffset() & 0x1FFF;
	}

	/**
	 * Returns the Identification field (16 bits).
	 */
	public int id() {
		return (short) PACKET_ID.get(asMemorySegment(), segmentOffset()) & 0xFFFF;
	}

	/**
	 * Returns the Internet Header Length in 32-bit words.
	 */
	public int ihl() {
		return versionIhl() & 0xF;
	}

	/**
	 * Returns the Internet Header Length in bytes.
	 */
	public int ihlBytes() {
		return ihl() * 4;
	}

	/**
	 * Returns true if this is a broadcast packet.
	 */
	public boolean isBroadcast() {
		return dstAsInt() == 0xFFFFFFFF; // 255.255.255.255
	}

	/**
	 * Returns true if this packet is fragmented.
	 */
	public boolean isFragmented() {
		return moreFragments() || fragOffsetValue() != 0;
	}

	/**
	 * Returns true if this is the last fragment.
	 */
	public boolean isLastFragment() {
		return !moreFragments() && fragOffsetValue() != 0;
	}

	/**
	 * Returns true if this is a multicast packet.
	 */
	public boolean isMulticast() {
		int firstOctet = (dstAsInt() >>> 24) & 0xFF;
		return firstOctet >= 224 && firstOctet <= 239; // 224.0.0.0/4
	}

	/**
	 * Returns true if this is a unicast packet.
	 */
	public boolean isUnicast() {
		return !isBroadcast() && !isMulticast();
	}

	/**
	 * Returns the Total Length field (16 bits).
	 */
	public int length() {
		return (short) TOTAL_LENGTH.get(asMemorySegment(), segmentOffset()) & 0xFFFF;
	}

	/**
	 * Returns true if the More Fragments flag is set.
	 */
	public boolean moreFragments() {
		return (fragOffset() & 0x2000) != 0;
	}

	/**
	 * Helper method to parse IPv4 address string to bytes.
	 */
	private byte[] parseIpv4Address(String ipStr) {
		String[] parts = ipStr.split("\\.");
		if (parts.length != 4) {
			throw new IllegalArgumentException("Invalid IPv4 address format: " + ipStr);
		}

		byte[] bytes = new byte[4];
		try {
			for (int i = 0; i < 4; i++) {
				int octet = Integer.parseInt(parts[i]);
				if (octet < 0 || octet > 255) {
					throw new IllegalArgumentException("Invalid octet value: " + octet);
				}
				bytes[i] = (byte) octet;
			}
		} catch (NumberFormatException e) {
			throw new IllegalArgumentException("Invalid IPv4 address format: " + ipStr, e);
		}

		return bytes;
	}

	/**
	 * Returns the Protocol field (8 bits).
	 */
	@Override
	public int protocol() {
		return (byte) PROTOCOL.get(asMemorySegment(), segmentOffset()) & 0xFF;
	}

	/**
	 * Sets the Header Checksum field.
	 */
	public void setChecksum(int value) {
		CHECKSUM.set(asMemorySegment(), segmentOffset(), (short) value);
	}

	/**
	 * @see com.slytechs.jnet.protocol.tcpip.ip.Ip#computeChecksum()
	 */
	@Override
	public void computeChecksum() {
		setChecksum(Checksums.computeIpv4HeaderChecksum(asMemorySegment(), activeBytesStart()));
	}

	/**
	 * Sets both DSCP and ECN fields within TOS.
	 */
	public void setDscpEcn(int dscp, int ecn) {
		int tos = ((dscp & 0x3F) << 2) | (ecn & 0x03);
		setTos(tos);
	}

	/**
	 * Sets the destination address from an integer.
	 */
	public void setDst(int value) {
		dstAddress.setInt(value);
	}

	/**
	 * Sets the destination address from an Ip4Address object.
	 */
	public void setDstFromAddress(Ip4Address address) {
		setDst(address.asInt());
	}

	/**
	 * Sets the destination address from a byte array.
	 */
	public void setDstFromBytes(byte[] bytes) {
		if (bytes.length != 4) {
			throw new IllegalArgumentException("IPv4 address must be 4 bytes");
		}
		int addr = ((bytes[0] & 0xFF) << 24) |
				((bytes[1] & 0xFF) << 16) |
				((bytes[2] & 0xFF) << 8) |
				(bytes[3] & 0xFF);
		setDst(addr);
	}

	/**
	 * Sets the destination address from a string.
	 */
	public void setDstFromString(String ipStr) {
		setDstFromBytes(parseIpv4Address(ipStr));
	}

	/**
	 * Sets the flags field from a flag set.
	 */
	public void setFlags(Ip4Flags flags) {
		int currentOffset = fragOffsetValue();
		int flagBits = (int) (flags.value() << 13);
		setFragOffset(currentOffset | flagBits);
	}

	/**
	 * Sets the combined Flags + Fragment Offset field.
	 */
	public void setFragOffset(int value) {
		FRAG_OFFSET.set(asMemorySegment(), segmentOffset(), (short) value);
	}

	/**
	 * Sets the fragment offset and flags separately.
	 */
	public void setFragOffsetValue(int offsetValue, boolean dontFragment, boolean moreFragments) {
		int packed = offsetValue & 0x1FFF;
		if (dontFragment)
			packed |= 0x4000;
		if (moreFragments)
			packed |= 0x2000;
		setFragOffset(packed);
	}

	/**
	 * Sets the Identification field.
	 */
	public void setId(int value) {
		PACKET_ID.set(asMemorySegment(), segmentOffset(), (short) value);
	}

	/**
	 * Sets the Total Length field.
	 */
	public void setLength(int value) {
		TOTAL_LENGTH.set(asMemorySegment(), segmentOffset(), (short) value);
	}

	/**
	 * Sets the Protocol field.
	 */
	public void setProtocol(int value) {
		PROTOCOL.set(asMemorySegment(), segmentOffset(), (byte) value);
	}

	/**
	 * Sets the source address from an integer.
	 */
	public void setSrc(int value) {
		srcAddress.setInt(value);
	}

	/**
	 * @see com.slytechs.jnet.core.api.memory.MemoryBinding#onBindMemorySegment()
	 */
	@Override
	protected void onBindPacket() {
		srcAddress.bindMemory(asMemory(), activeBytesStart() + SRC_ADDR_OFF);
		dstAddress.bindMemory(asMemory(), activeBytesStart() + DST_ADDR_OFF);
	}

	/**
	 * @see com.slytechs.jnet.core.api.memory.MemoryBinding#onUnbind()
	 */
	@Override
	protected void onUnbindPacket() {
		srcAddress.unbindMemory();
		dstAddress.unbindMemory();

		super.onUnbindMemory();
	}

	/**
	 * Sets the source address from an Ip4Address object.
	 */
	public void setSrcFromAddress(Ip4Address address) {
		setSrc(address.asInt());
	}

	/**
	 * Sets the source address from a byte array.
	 */
	public void setSrcFromBytes(byte[] bytes) {
		srcAddress.setBytes(bytes);
	}

	/**
	 * Sets the source address from a string.
	 */
	public void setSrcFromString(String ipStr) {
		setSrcFromBytes(parseIpv4Address(ipStr));
	}

	/**
	 * Sets the Type of Service field.
	 */
	public void setTos(int value) {
		TOS.set(asMemorySegment(), segmentOffset(), (byte) value);
	}

	/**
	 * Sets the TOS field from a flag set.
	 */
	public void setTosFromFlags(Ip4TosFlags tosFlags) {
		setTos((int) tosFlags.value());
	}

	/**
	 * Sets the Time to Live field.
	 */
	public void setTtl(int value) {
		TTL.set(asMemorySegment(), segmentOffset(), (byte) value);
	}

	/**
	 * Sets the combined Version + IHL field.
	 */
	public void setVersionIhl(int value) {
		VERSION_IHL.set(asMemorySegment(), segmentOffset(), (byte) value);
	}

	/**
	 * Sets version and IHL fields separately.
	 */
	public void setVersionIhl(int version, int ihl) {
		setVersionIhl(((version & 0xF) << 4) | (ihl & 0xF));
	}

	/**
	 * Returns the source address as an Ip4Address object.
	 */
	@Override
	public Ip4AddressRecord src() {
		return new Ip4AddressRecord(srcAsInt());
	}

	/**
	 * Returns the source address as an integer.
	 */
	public int srcAsInt() {
		return srcAddress.asInt();
	}

	/**
	 * Returns the Type of Service field (8 bits).
	 */
	public int tos() {
		return (byte) TOS.get(asMemorySegment(), segmentOffset()) & 0xFF;
	}

	/**
	 * Returns the TOS field as a flag set.
	 */
	public Ip4TosFlags tosAsFlags() {
		return new Ip4TosFlags(tos());
	}

	@Override
	public String toString() {
		return format(new StructFormat()).toString();
	}

	/**
	 * Returns the Time to Live field (8 bits).
	 */
	public int ttl() {
		return (byte) TTL.get(asMemorySegment(), activeBytesStart()) & 0xFF;
	}

	/**
	 * Returns the IP version (should always be 4 for IPv4).
	 */
	@Override
	public int version() {
		return (versionIhl() >>> 4) & 0xF;
	}

	/**
	 * Returns the combined Version + IHL field (8 bits).
	 */
	public int versionIhl() {
		return (byte) VERSION_IHL.get(asMemorySegment(), segmentOffset()) & 0xFF;
	}

	/**
	 * @see com.slytechs.jnet.protocol.tcpip.ip.Ip#setVersion(int)
	 */
	@Override
	public void setVersion(int newVersion) {
		int ihl = ihl();

		setVersionIhl(newVersion, ihl);
	}

}