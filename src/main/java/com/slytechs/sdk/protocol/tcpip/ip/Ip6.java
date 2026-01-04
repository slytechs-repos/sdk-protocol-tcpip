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

import static com.slytechs.sdk.common.detail.DetailBuilder.*;

import java.lang.foreign.MemoryLayout;

import com.slytechs.sdk.common.detail.DetailBuilder;
import com.slytechs.sdk.common.detail.Detailable;
import com.slytechs.sdk.common.memory.MemoryHandle;
import com.slytechs.sdk.common.memory.MemoryHandle.ByteHandle;
import com.slytechs.sdk.common.memory.MemoryHandle.IntHandle;
import com.slytechs.sdk.common.memory.MemoryHandle.ShortHandle;
import com.slytechs.sdk.protocol.core.ExtensibleHeader;
import com.slytechs.sdk.protocol.core.ProtocolId;
import com.slytechs.sdk.protocol.core.address.Ip6Address;
import com.slytechs.sdk.protocol.core.address.Ip6AddressMemory;

import static java.lang.foreign.MemoryLayout.*;

/**
 * Internet Protocol version 6 (IPv6) header as defined in RFC 8200.
 * 
 * <p>
 * IPv6 is the most recent version of the Internet Protocol, designed to replace
 * IPv4 due to address exhaustion. IPv6 uses 128-bit addresses and has a fixed
 * 40-byte header with optional extension headers that follow the main header.
 * </p>
 * 
 * <h2>Header Format</h2>
 * 
 * <pre>
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version| Traffic Class |           Flow Label                  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Payload Length        |  Next Header  |   Hop Limit   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +                         Source Address                        +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +                      Destination Address                      +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * 
 * <h2>Extension Headers</h2>
 * <p>
 * Unlike IPv4 options which are part of the header, IPv6 uses separate
 * extension headers that chain after the main header. Use {@link #extensions()}
 * to access extension headers and {@link #finalProtocol()} to get the
 * upper-layer protocol after all extensions.
 * </p>
 * 
 * {@snippet :
 * Ip6 ip6 = packet.getHeader(new Ip6());
 * 
 * // Next Header field (may be extension header)
 * int nextHdr = ip6.nextHeader();
 * 
 * // Upper-layer protocol (after all extensions)
 * int protocol = ip6.protocol();
 * 
 * // Check for fragmentation
 * if (ip6.isFragmented()) {
 * 	Ip6Extensions.Fragment frag = ip6.extensions().fragment();
 * 	System.out.println("Fragment offset: " + frag.fragmentOffset());
 * }
 * }
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see Ip6Extensions
 * @see Ip
 */
public class Ip6 extends ExtensibleHeader<Ip6Extensions> implements Ip, Detailable {

	/** Protocol HEADER_ID for IPv6. */
	public static final int HEADER_ID = ProtocolId.IPv6;

	/** IPv6 header length in bytes (fixed size). */
	public static final int HEADER_LENGTH = 40;

	/** IPv6 header memory layout. */
	public static final MemoryLayout LAYOUT = structLayout(
			U32_BE.withName("hdr_vtc_flow"),
			U16_BE.withName("hdr_payload_len"),
			U8_BE.withName("hdr_next_hdr"),
			U8_BE.withName("hdr_hop_limit"),
			Ip6AddressMemory.LAYOUT.withName("hdr_src_addr"),
			Ip6AddressMemory.LAYOUT.withName("hdr_dst_addr"));

	private static final IntHandle VTC_FLOW = new IntHandle(LAYOUT, "hdr_vtc_flow");
	private static final ShortHandle PAYLOAD_LEN = new ShortHandle(LAYOUT, "hdr_payload_len");
	private static final ByteHandle NEXT_HDR = new ByteHandle(LAYOUT, "hdr_next_hdr");
	private static final ByteHandle HOP_LIMIT = new ByteHandle(LAYOUT, "hdr_hop_limit");

	private static final long SRC_ADDR_OFF = MemoryHandle.byteOffset(LAYOUT, "hdr_src_addr");
	private static final long DST_ADDR_OFF = MemoryHandle.byteOffset(LAYOUT, "hdr_dst_addr");

	private final Ip6AddressMemory srcAddress = new Ip6AddressMemory();
	private final Ip6AddressMemory dstAddress = new Ip6AddressMemory();
	private final Ip6Extensions extensions = new Ip6Extensions();

	/**
	 * Constructs a new IPv6 header.
	 */
	public Ip6() {
		super(HEADER_ID, LAYOUT);
	}

	/**
	 * Returns the IP version field (4 bits).
	 *
	 * @return 6 for IPv6
	 */
	@Override
	public int version() {
		return (vtcFlow() >>> 28) & 0xF;
	}

	/**
	 * Returns the combined Version, Traffic Class, and Flow Label field (32 bits).
	 *
	 * @return the raw 32-bit field value
	 */
	public int vtcFlow() {
		return VTC_FLOW.getInt(view());
	}

	/**
	 * Sets the combined Version, Traffic Class, and Flow Label field.
	 *
	 * @param value the 32-bit field value
	 */
	public void setVtcFlow(int value) {
		VTC_FLOW.setInt(view(), 0, value);
	}

	/**
	 * Returns the Traffic Class field (8 bits).
	 * 
	 * <p>
	 * Equivalent to IPv4's Type of Service field. Contains DSCP and ECN.
	 * </p>
	 *
	 * @return the traffic class value (0-255)
	 */
	public int trafficClass() {
		return (vtcFlow() >>> 20) & 0xFF;
	}

	/**
	 * Sets the Traffic Class field.
	 *
	 * @param trafficClass the traffic class value (0-255)
	 */
	public void setTrafficClass(int trafficClass) {
		int current = vtcFlow();
		int newValue = (current & 0xF00FFFFF) | ((trafficClass & 0xFF) << 20);
		setVtcFlow(newValue);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int dscp() {
		return (trafficClass() >>> 2) & 0x3F;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int ecn() {
		return trafficClass() & 0x03;
	}

	/**
	 * Sets DSCP and ECN fields within the Traffic Class.
	 *
	 * @param dscp the DSCP value (0-63)
	 * @param ecn  the ECN value (0-3)
	 */
	public void setDscpEcn(int dscp, int ecn) {
		int trafficClass = ((dscp & 0x3F) << 2) | (ecn & 0x03);
		setTrafficClass(trafficClass);
	}

	/**
	 * Returns the Flow Label field (20 bits).
	 * 
	 * <p>
	 * Used for labeling sequences of packets for which special handling is
	 * requested, such as non-default quality of service or real-time service.
	 * </p>
	 *
	 * @return the flow label value (0-1048575)
	 */
	public int flowLabel() {
		return vtcFlow() & 0xFFFFF;
	}

	/**
	 * Sets the Flow Label field.
	 *
	 * @param flowLabel the flow label value (0-1048575)
	 */
	public void setFlowLabel(int flowLabel) {
		int current = vtcFlow();
		int newValue = (current & 0xFFF00000) | (flowLabel & 0xFFFFF);
		setVtcFlow(newValue);
	}

	/**
	 * Returns the Payload Length field (16 bits).
	 * 
	 * <p>
	 * Length of the IPv6 payload in bytes, including any extension headers. Does
	 * not include the 40-byte IPv6 header itself.
	 * </p>
	 *
	 * @return payload length in bytes
	 */
	@Override
	public int payloadLength() {
		return PAYLOAD_LEN.getShort(view()) & 0xFFFF;
	}

	/**
	 * Sets the Payload Length field.
	 *
	 * @param length payload length in bytes
	 */
	public void setPayloadLength(int length) {
		PAYLOAD_LEN.setShort(view(), 0, (short) length);
	}

	/**
	 * Returns the Next Header field (8 bits).
	 * 
	 * <p>
	 * Identifies the type of header immediately following the IPv6 header. This may
	 * be an extension header or an upper-layer protocol. Use {@link #protocol()} to
	 * get the final upper-layer protocol after all extension headers.
	 * </p>
	 *
	 * @return the next header value
	 * @see #protocol()
	 * @see #finalProtocol()
	 * @see IpProtocolResolver
	 */
	public int nextHeader() {
		return NEXT_HDR.getByte(view()) & 0xFF;
	}

	/**
	 * Sets the Next Header field.
	 *
	 * @param nextHeader the next header value
	 */
	public void setNextHeader(int nextHeader) {
		NEXT_HDR.setByte(view(), 0, (byte) nextHeader);
	}

	/**
	 * Returns the upper-layer protocol after all extension headers.
	 * 
	 * <p>
	 * Unlike {@link #nextHeader()} which returns the immediate next header (which
	 * may be an extension header), this method traverses all extension headers and
	 * returns the final upper-layer protocol.
	 * </p>
	 *
	 * {@snippet :
	 * // nextHeader() might return 44 (Fragment)
	 * // protocol() returns 6 (TCP) - the actual payload protocol
	 * int nextHdr = ip6.nextHeader();   // e.g., 44 (Fragment extension)
	 * int protocol = ip6.protocol();     // e.g., 6 (TCP)
	 * }
	 *
	 * @return the upper-layer protocol number (e.g., 6 for TCP, 17 for UDP)
	 * @see #nextHeader()
	 * @see IpProtocolResolver
	 */
	@Override
	public int protocol() {
		return finalProtocol();
	}

	/**
	 * Returns the final protocol after all extension headers.
	 * 
	 * <p>
	 * If no extension headers are present, returns {@link #nextHeader()}.
	 * Otherwise, returns the Next Header value from the last extension header.
	 * </p>
	 *
	 * @return the final upper-layer protocol number
	 */
	public int finalProtocol() {
		if (hasExtensions()) {
			return extensions().finalProtocol();
		}
		return nextHeader();
	}

	/**
	 * Returns the Hop Limit field (8 bits).
	 * 
	 * <p>
	 * Decremented by 1 by each node that forwards the packet. The packet is
	 * discarded if Hop Limit is decremented to zero. Equivalent to IPv4's TTL.
	 * </p>
	 *
	 * @return the hop limit value (0-255)
	 */
	public int hopLimit() {
		return HOP_LIMIT.getByte(view()) & 0xFF;
	}

	/**
	 * Sets the Hop Limit field.
	 *
	 * @param hopLimit the hop limit value (0-255)
	 */
	public void setHopLimit(int hopLimit) {
		HOP_LIMIT.setByte(view(), 0, (byte) hopLimit);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * For IPv6, this is an alias for {@link #hopLimit()}.
	 * </p>
	 */
	@Override
	public int ttl() {
		return hopLimit();
	}

	/**
	 * Sets the TTL (Hop Limit) field.
	 * 
	 * <p>
	 * For IPv6, this is an alias for {@link #setHopLimit(int)}.
	 * </p>
	 *
	 * @param ttl the TTL value (0-255)
	 */
	public void setTtl(int ttl) {
		setHopLimit(ttl);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Ip6Address src() {
		return srcAddress;
	}

	/**
	 * Sets the source address from a byte array.
	 *
	 * @param bytes 16-byte address
	 * @throws IllegalArgumentException if bytes is not 16 bytes
	 */
	public void setSrcFromBytes(byte[] bytes) {
		srcAddress.setBytes(bytes);
	}

	/**
	 * Sets the source address from an Ip6Address object.
	 *
	 * @param address the source address
	 */
	public void setSrcFromAddress(Ip6Address address) {
		setSrcFromBytes(address.bytes());
	}

	/**
	 * Sets the source address from a string.
	 *
	 * @param ipStr IPv6 address string (e.g., "2001:db8::1")
	 */
	public void setSrcFromString(String ipStr) {
		setSrcFromBytes(Ip6Address.parseIpv6Address(ipStr));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Ip6Address dst() {
		return dstAddress;
	}

	/**
	 * Sets the destination address from a byte array.
	 *
	 * @param bytes 16-byte address
	 * @throws IllegalArgumentException if bytes is not 16 bytes
	 */
	public void setDstFromBytes(byte[] bytes) {
		dstAddress.setBytes(bytes);
	}

	/**
	 * Sets the destination address from an Ip6Address object.
	 *
	 * @param address the destination address
	 */
	public void setDstFromAddress(Ip6Address address) {
		setDstFromBytes(address.bytes());
	}

	/**
	 * Sets the destination address from a string.
	 *
	 * @param ipStr IPv6 address string (e.g., "2001:db8::1")
	 */
	public void setDstFromString(String ipStr) {
		setDstFromBytes(Ip6Address.parseIpv6Address(ipStr));
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * IPv6 multicast addresses are in the range {@code ff00::/8}.
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
	 * IPv6 loopback address is {@code ::1}.
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
	 * IPv6 link-local addresses are in the range {@code fe80::/10}.
	 * </p>
	 */
	@Override
	public boolean isLinkLocal() {
		return dstAddress.isLinkLocal();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * For IPv6, fragmentation is indicated by the presence of a Fragment extension
	 * header with either the More Fragments flag set or a non-zero fragment offset.
	 * </p>
	 */
	@Override
	public boolean isFragmented() {
		if (!hasExtensions()) {
			return false;
		}
		return extensions().isFragmented();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public long headerLength() {
		return HEADER_LENGTH;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean hasExtensions() {
		return Ip6Extensions.isExtensionHeader(nextHeader());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Ip6Extensions extensions() {
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
		return super.end() - extensionsOffset();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void onBindPacket() {
		super.onBindPacket();
		srcAddress.bind(this, SRC_ADDR_OFF, 16);
		dstAddress.bind(this, DST_ADDR_OFF, 16);

		extensions.setParent(this);
		extensions.bind(getPacket(), extensionsOffset());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void onUnbindPacket() {
		srcAddress.unbind();
		dstAddress.unbind();
		extensions.unbind();

		super.onUnbindPacket();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void buildDetail(DetailBuilder b) {
		int off = (int) headerOffset();

		b.header("Internet Protocol version 6", "IPv6", HEADER_ID, off, HEADER_LENGTH, h -> {

			h.expandField("Version/Traffic Class/Flow Label", vtcFlow(),
					String.format("Version=%d, TC=%d, Flow=%d", version(), trafficClass(), flowLabel()),
					intAt(off), f -> {
						f.field("Version", version(), bitsAt(off * 8L, 4));
						f.field("Traffic Class", trafficClass(), bitsAt(off * 8L + 4, 8));
						f.field("DSCP", dscp(), bitsAt(off * 8L + 4, 6));
						f.field("ECN", ecn(), bitsAt(off * 8L + 10, 2));
						f.field("Flow Label", flowLabel(), bitsAt(off * 8L + 12, 20));
					});

			h.field("Payload Length", payloadLength(), shortAt(off + 4));
			h.field("Next Header", nextHeader(), IpProtocolResolver.resolveAbbrOrNumber(nextHeader()), byteAt(off + 6));
			h.field("Hop Limit", hopLimit(), byteAt(off + 7));
			h.field("Source", src().toString(), bits(off + 8, 16));
			h.field("Destination", dst().toString(), bits(off + 24, 16));
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