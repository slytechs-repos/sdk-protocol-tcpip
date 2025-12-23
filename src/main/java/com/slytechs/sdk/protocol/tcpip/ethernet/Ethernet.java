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
package com.slytechs.sdk.protocol.tcpip.ethernet;

import static com.slytechs.sdk.common.detail.DetailBuilder.*;

import java.lang.foreign.MemoryLayout;

import com.slytechs.sdk.common.detail.DetailBuilder;
import com.slytechs.sdk.common.detail.Detailable;
import com.slytechs.sdk.common.memory.MemoryHandle;
import com.slytechs.sdk.common.memory.MemoryHandle.ShortHandle;
import com.slytechs.sdk.protocol.core.ExtensibleHeader;
import com.slytechs.sdk.protocol.core.ProtocolId;
import com.slytechs.sdk.protocol.core.address.MacAddress;
import com.slytechs.sdk.protocol.core.address.MacAddressMemory;
import com.slytechs.sdk.protocol.core.checksum.Checksums;

import static java.lang.foreign.MemoryLayout.*;

/**
 * Ethernet frame header as defined in IEEE 802.3 and Ethernet II (DIX).
 * 
 * <p>
 * Ethernet is the most widely deployed link-layer protocol. This class supports
 * both Ethernet II (DIX) framing and IEEE 802.3 framing, distinguished by the
 * value of the Type/Length field.
 * </p>
 * 
 * <h2>Header Format</h2>
 * <pre>
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Destination MAC Address                    |
 * +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                               |                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 * |                      Source MAC Address                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          EtherType/Length     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * 
 * <h2>Frame Types</h2>
 * <ul>
 * <li><b>Ethernet II (DIX)</b> - Type/Length field >= 1536 (0x0600) indicates
 *     EtherType identifying the payload protocol</li>
 * <li><b>IEEE 802.3</b> - Type/Length field <= 1500 indicates payload length,
 *     followed by LLC/SNAP headers</li>
 * </ul>
 * 
 * <h2>Frame Check Sequence (FCS)</h2>
 * <p>
 * Ethernet frames include a 4-byte FCS (CRC32) at the end. The FCS is typically
 * stripped by the NIC before delivery to software. When present (e.g., in pcap
 * files captured with FCS), use {@link #computeFcs(int)} to verify.
 * </p>
 * 
 * {@snippet :
 * Ethernet eth = packet.getHeader(new Ethernet());
 * 
 * System.out.println("Source: " + eth.src());
 * System.out.println("Destination: " + eth.dst());
 * 
 * if (eth.isEthernetII()) {
 *     System.out.println("EtherType: " + EtherTypeResolver.resolveAbbr(eth.etherType()));
 * } else {
 *     System.out.println("IEEE 802.3 Length: " + eth.etherType());
 * }
 * }
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see Eth8023Extensions
 * @see MacAddress
 * @see EtherTypeResolver
 */
public final class Ethernet extends ExtensibleHeader<Eth8023Extensions> implements Detailable {

	/** Protocol HEADER_ID for Ethernet. */
	public static final int HEADER_ID = ProtocolId.ETHERNET;

	/** Ethernet header length in bytes (without FCS). */
	public static final int HEADER_LENGTH = 14;

	/** Ethernet FCS (Frame Check Sequence) length in bytes. */
	public static final int FCS_LENGTH = 4;

	/** Minimum EtherType value (Ethernet II vs IEEE 802.3 boundary). */
	public static final int MIN_ETHERTYPE = 0x0600;

	/** Maximum IEEE 802.3 length value. */
	public static final int MAX_LENGTH = 1500;

	/** EtherType for IPv4. */
	public static final int ETHERTYPE_IPV4 = 0x0800;

	/** EtherType for IPv6. */
	public static final int ETHERTYPE_IPV6 = 0x86DD;

	/** EtherType for ARP. */
	public static final int ETHERTYPE_ARP = 0x0806;

	/** EtherType for VLAN (802.1Q). */
	public static final int ETHERTYPE_VLAN = 0x8100;

	/** EtherType for QinQ (802.1ad). */
	public static final int ETHERTYPE_QINQ = 0x88A8;

	/** EtherType for MPLS unicast. */
	public static final int ETHERTYPE_MPLS = 0x8847;

	/** EtherType for MPLS multicast. */
	public static final int ETHERTYPE_MPLS_MCAST = 0x8848;

	/** Ethernet header memory layout. */
	public static final MemoryLayout LAYOUT = structLayout(
			MacAddressMemory.LAYOUT.withName("hdr_dst_addr"),
			MacAddressMemory.LAYOUT.withName("hdr_src_addr"),
			U16_BE.withName("hdr_ethertype")
	);

	private static final ShortHandle ETHERTYPE = new ShortHandle(LAYOUT, "hdr_ethertype");
	private static final long DST_ADDR_OFF = MemoryHandle.byteOffset(LAYOUT, "hdr_dst_addr");
	private static final long SRC_ADDR_OFF = MemoryHandle.byteOffset(LAYOUT, "hdr_src_addr");

	private final MacAddressMemory dstAddress = new MacAddressMemory();
	private final MacAddressMemory srcAddress = new MacAddressMemory();
	private final Eth8023Extensions extensions = new Eth8023Extensions();

	/**
	 * Constructs a new Ethernet header.
	 */
	public Ethernet() {
		super(HEADER_ID, LAYOUT);
	}

	/**
	 * Returns the destination MAC address.
	 *
	 * @return the destination MAC address
	 */
	public MacAddress dst() {
		return dstAddress;
	}

	/**
	 * Returns the destination MAC address as a 48-bit value in a long.
	 *
	 * @return the destination MAC address as a long
	 */
	public long dstAsLong() {
		return dstAddress.asLong();
	}

	/**
	 * Returns the destination MAC address as a byte array.
	 *
	 * @return 6-byte array containing the destination MAC address
	 */
	public byte[] dstAsBytes() {
		return dstAddress.bytes();
	}

	/**
	 * Sets the destination MAC address from a long.
	 *
	 * @param mac the MAC address as a 48-bit value
	 */
	public void setDst(long mac) {
		dstAddress.setLong(mac);
	}

	/**
	 * Sets the destination MAC address from a byte array.
	 *
	 * @param bytes 6-byte MAC address
	 * @throws IllegalArgumentException if bytes is not 6 bytes
	 */
	public void setDstFromBytes(byte[] bytes) {
		dstAddress.setBytes(bytes);
	}

	/**
	 * Sets the destination MAC address from a string.
	 *
	 * @param macStr MAC address in "XX:XX:XX:XX:XX:XX" or "XX-XX-XX-XX-XX-XX" format
	 */
	public void setDstFromString(String macStr) {
		setDstFromBytes(MacAddress.parseMacAddress(macStr));
	}

	/**
	 * Returns the source MAC address.
	 *
	 * @return the source MAC address
	 */
	public MacAddress src() {
		return srcAddress;
	}

	/**
	 * Returns the source MAC address as a 48-bit value in a long.
	 *
	 * @return the source MAC address as a long
	 */
	public long srcAsLong() {
		return srcAddress.asLong();
	}

	/**
	 * Returns the source MAC address as a byte array.
	 *
	 * @return 6-byte array containing the source MAC address
	 */
	public byte[] srcAsBytes() {
		return srcAddress.bytes();
	}

	/**
	 * Sets the source MAC address from a long.
	 *
	 * @param mac the MAC address as a 48-bit value
	 */
	public void setSrc(long mac) {
		srcAddress.setLong(mac);
	}

	/**
	 * Sets the source MAC address from a byte array.
	 *
	 * @param bytes 6-byte MAC address
	 * @throws IllegalArgumentException if bytes is not 6 bytes
	 */
	public void setSrcFromBytes(byte[] bytes) {
		srcAddress.setBytes(bytes);
	}

	/**
	 * Sets the source MAC address from a string.
	 *
	 * @param macStr MAC address in "XX:XX:XX:XX:XX:XX" or "XX-XX-XX-XX-XX-XX" format
	 */
	public void setSrcFromString(String macStr) {
		setSrcFromBytes(MacAddress.parseMacAddress(macStr));
	}

	/**
	 * Returns the EtherType/Length field (16 bits).
	 * 
	 * <p>
	 * For Ethernet II frames (value >= 1536), this is the EtherType identifying
	 * the payload protocol. For IEEE 802.3 frames (value <= 1500), this is the
	 * payload length.
	 * </p>
	 *
	 * @return the EtherType or length value
	 * @see #isEthernetII()
	 * @see #isIeee8023()
	 */
	public int etherType() {
		return ETHERTYPE.getShort(view()) & 0xFFFF;
	}

	/**
	 * Sets the EtherType/Length field.
	 *
	 * @param value the EtherType or length value
	 */
	public void setEtherType(int value) {
		ETHERTYPE.setShort(view(), 0, (short) value);
	}

	/**
	 * Checks if this is an Ethernet II (DIX) frame.
	 * 
	 * <p>
	 * Ethernet II frames have a Type/Length field >= 1536 (0x0600), which
	 * indicates an EtherType value identifying the payload protocol.
	 * </p>
	 *
	 * @return true if this is an Ethernet II frame
	 */
	public boolean isEthernetII() {
		return etherType() >= MIN_ETHERTYPE;
	}

	/**
	 * Checks if this is an IEEE 802.3 frame.
	 * 
	 * <p>
	 * IEEE 802.3 frames have a Type/Length field <= 1500, which indicates the
	 * payload length. The payload is typically followed by LLC and optionally
	 * SNAP headers.
	 * </p>
	 *
	 * @return true if this is an IEEE 802.3 frame
	 */
	public boolean isIeee8023() {
		return etherType() <= MAX_LENGTH;
	}

	/**
	 * Checks if the destination is a broadcast address.
	 *
	 * @return true if destination is FF:FF:FF:FF:FF:FF
	 */
	public boolean isBroadcast() {
		return dstAddress.isBroadcast();
	}

	/**
	 * Checks if the destination is a multicast address.
	 * 
	 * <p>
	 * Multicast addresses have the least significant bit of the first octet set.
	 * </p>
	 *
	 * @return true if destination is a multicast address
	 */
	public boolean isMulticast() {
		return dstAddress.isMulticast();
	}

	/**
	 * Checks if the destination is a unicast address.
	 *
	 * @return true if destination is neither broadcast nor multicast
	 */
	public boolean isUnicast() {
		return !isBroadcast() && !isMulticast();
	}

	/**
	 * Computes the Ethernet Frame Check Sequence (FCS).
	 * 
	 * <p>
	 * The FCS is a CRC32 computed over the entire frame from destination MAC
	 * through the end of the payload. This method computes the FCS for the
	 * specified frame length.
	 * </p>
	 * 
	 * <p>
	 * Note: The FCS is typically stripped by the NIC. Use this method when
	 * working with captures that include the FCS (e.g., pcap files captured
	 * with FCS enabled).
	 * </p>
	 *
	 * {@snippet :
	 * // Frame length excluding FCS
	 * int frameLen = packet.captureLength() - Ethernet.FCS_LENGTH;
	 * int computed = eth.computeFcs(frameLen);
	 * int stored = packet.getInt(frameLen);  // FCS at end of frame
	 * boolean valid = (computed == stored);
	 * }
	 *
	 * @param frameLength total frame length in bytes (excluding FCS)
	 * @return computed 32-bit FCS value
	 */
	public int computeFcs(int frameLength) {
		return Checksums.computeEthernetFcs(
				getPacket().view().segment(),
				headerOffset(),
				frameLength);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean hasExtensions() {
		return isIeee8023();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Eth8023Extensions extensions() {
		if (!extensions.isBound())
			extensions.bind(getPacket(), extensionsOffset(), extensionsLength());

		return extensions;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public long extensionsOffset() {
		return headerOffset() + HEADER_LENGTH;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public long extensionsLength() {
		if (isIeee8023()) {
			return etherType(); // Length field indicates payload length
		}
		return 0;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void onBindPacket() {
		dstAddress.bind(this, DST_ADDR_OFF, MacAddress.LENGTH);
		srcAddress.bind(this, SRC_ADDR_OFF, MacAddress.LENGTH);

		if (hasExtensions()) {
			extensions.bind(getPacket(), extensionsOffset(), extensionsLength());
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void onUnbindPacket() {
		dstAddress.unbind();
		srcAddress.unbind();
		extensions.unbind();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void buildDetail(DetailBuilder b) {
		int off = (int) headerOffset();

		b.header("Ethernet", "ETH", HEADER_ID, off, HEADER_LENGTH, h -> {
			h.summaryf("%s → %s %s",
					src(), dst(),
					isEthernetII()
							? EtherTypeResolver.resolveAbbrOrHex(etherType())
							: "IEEE 802.3 Len=" + etherType());

			h.field("Destination", dst().toString(), bits(off, 6));
			h.field("Source", src().toString(), bits(off + 6, 6));

			if (isEthernetII()) {
				h.fieldHex("Type", etherType(), 4,
						EtherTypeResolver.resolveOrHex(etherType()),
						shortAt(off + 12));
			} else {
				h.field("Length", etherType(), shortAt(off + 12));
			}
		});

		if (hasExtensions()) {
			extensions().buildDetail(b);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		return toDetailString();
	}
}