package com.slytechs.jnet.protocol.tcpip.ip;

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

import com.slytechs.jnet.core.api.format.StructFormat;
import com.slytechs.jnet.protocol.api.address.Ip6Address;
import com.slytechs.jnet.protocol.api.address.Ip6AddressMemory;
import com.slytechs.jnet.protocol.tcpip.Tcpip;

import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;
import static java.lang.foreign.ValueLayout.*;

/**
 * Java binding for IPv6 header with dynamic mapped access. IPv6 header format
 * as defined in RFC 8200.
 */
public class Ip6 extends Ip {
	public static final int ID = Tcpip.IPv6_ID;

	public static final MemoryLayout LAYOUT$BIG$SIZE_40 = structLayout(
			JAVA_INT.withName("hdr_vtc_flow").withOrder(ByteOrder.BIG_ENDIAN), // Version + Traffic Class + Flow Label
			JAVA_SHORT.withName("hdr_payload_len").withOrder(ByteOrder.BIG_ENDIAN), // Payload Length
			JAVA_BYTE.withName("hdr_next_hdr"), // Next Header
			JAVA_BYTE.withName("hdr_hop_limit"), // Hop Limit
			Ip6AddressMemory.LAYOUT.withName("hdr_src_addr"), // Source Address (128 bits)
			Ip6AddressMemory.LAYOUT.withName("hdr_dst_addr") // Destination Address (128 bits)
	);

	public static final MemoryLayout LAYOUT = LAYOUT$BIG$SIZE_40;

	private static final VarHandle VTC_FLOW = LAYOUT.varHandle(groupElement("hdr_vtc_flow"));
	private static final VarHandle PAYLOAD_LEN = LAYOUT.varHandle(groupElement("hdr_payload_len"));
	private static final VarHandle NEXT_HDR = LAYOUT.varHandle(groupElement("hdr_next_hdr"));
	private static final VarHandle HOP_LIMIT = LAYOUT.varHandle(groupElement("hdr_hop_limit"));
	private static final long SRC_ADDR_OFF = LAYOUT.byteOffset(groupElement("hdr_src_addr"));
	private static final long DST_ADDR_OFF = LAYOUT.byteOffset(groupElement("hdr_dst_addr"));

	private final Ip6AddressMemory srcAddress = new Ip6AddressMemory();
	private final Ip6AddressMemory dstAddress = new Ip6AddressMemory();

	public Ip6() {
		super(ID, LAYOUT);
	}

	public Ip6(MemorySegment pointer) {
		super(ID, LAYOUT, pointer);

		onBindMemory();
	}

	public Ip6(MemorySegment seg, long offset) {
		super(ID, LAYOUT, seg, offset);

		onBindMemory();
	}

	public Ip6(Arena arena) {
		super(ID, LAYOUT, arena);

		onBindMemory();
	}

	/**
	 * Returns the IP version (should always be 6 for IPv6).
	 */
	@Override
	public int version() {
		return (vtcFlow() >>> 28) & 0xF;
	}

	/**
	 * Returns the Traffic Class field (8 bits). Equivalent to IPv4's Type of
	 * Service field.
	 */
	public int trafficClass() {
		return (vtcFlow() >>> 20) & 0xFF;
	}

	/**
	 * Returns the DSCP portion of the Traffic Class field (6 bits).
	 */
	public int dscp() {
		return (trafficClass() >>> 2) & 0x3F;
	}

	/**
	 * Returns the ECN portion of the Traffic Class field (2 bits).
	 */
	public int ecn() {
		return trafficClass() & 0x03;
	}

	/**
	 * Returns the Flow Label field (20 bits).
	 */
	public int flowLabel() {
		return vtcFlow() & 0xFFFFF;
	}

	/**
	 * Returns the combined Version + Traffic Class + Flow Label field (32 bits).
	 */
	public int vtcFlow() {
		return (int) VTC_FLOW.get(asMemorySegment(), segmentOffset());
	}

	/**
	 * Sets the combined Version + Traffic Class + Flow Label field.
	 */
	public void setVtcFlow(int value) {
		VTC_FLOW.set(asMemorySegment(), segmentOffset(), value);
	}

	/**
	 * Sets the Traffic Class field.
	 */
	public void setTrafficClass(int trafficClass) {
		int current = vtcFlow();
		int newValue = (current & 0xF00FFFFF) | ((trafficClass & 0xFF) << 20);
		setVtcFlow(newValue);
	}

	/**
	 * Sets both DSCP and ECN fields within Traffic Class.
	 */
	public void setDscpEcn(int dscp, int ecn) {
		int trafficClass = ((dscp & 0x3F) << 2) | (ecn & 0x03);
		setTrafficClass(trafficClass);
	}

	/**
	 * Sets the Flow Label field.
	 */
	public void setFlowLabel(int flowLabel) {
		int current = vtcFlow();
		int newValue = (current & 0xFFF00000) | (flowLabel & 0xFFFFF);
		setVtcFlow(newValue);
	}

	/**
	 * Returns the Payload Length field (16 bits). Length of the IPv6 payload
	 * (excluding the header itself).
	 */
	public int payloadLength() {
		return (short) PAYLOAD_LEN.get(asMemorySegment(), segmentOffset()) & 0xFFFF;
	}

	/**
	 * Sets the Payload Length field.
	 */
	public void setPayloadLength(int value) {
		PAYLOAD_LEN.set(asMemorySegment(), segmentOffset(), (short) value);
	}

	/**
	 * Returns the Next Header field (8 bits). Identifies the type of header
	 * immediately following the IPv6 header.
	 */
	public int nextHeader() {
		return (byte) NEXT_HDR.get(asMemorySegment(), segmentOffset()) & 0xFF;
	}

	/**
	 * Sets the Next Header field.
	 */
	public void setNextHeader(int value) {
		NEXT_HDR.set(asMemorySegment(), segmentOffset(), (byte) value);
	}

	/**
	 * Returns the Hop Limit field (8 bits). Equivalent to IPv4's TTL field.
	 */
	public int hopLimit() {
		return (byte) HOP_LIMIT.get(asMemorySegment(), 0) & 0xFF;
	}

	/**
	 * Sets the Hop Limit field.
	 */
	public void setHopLimit(int value) {
		HOP_LIMIT.set(asMemorySegment(), segmentOffset(), (byte) value);
	}

	/**
	 * Returns the source address as an Ip6Address object.
	 */
	@Override
	public Ip6Address src() {
		return srcAddress;
	}

	/**
	 * Sets the source address from a byte array.
	 */
	public void setSrcFromBytes(byte[] bytes) {
		srcAddress.setBytes(bytes);
	}

	/**
	 * Sets the source address from a string representation.
	 */
	public void setSrcFromString(String ipStr) {
		setSrcFromBytes(Ip6Address.parseIpv6Address(ipStr));
	}

	/**
	 * Sets the source address from an Ip6Address object.
	 */
	public void setSrcFromAddress(Ip6Address address) {
		setSrcFromBytes(address.bytes());
	}

	/**
	 * Returns the destination address as an Ip6Address object.
	 */
	@Override
	public Ip6Address dst() {
		return dstAddress;
	}

	/**
	 * Sets the destination address from a byte array.
	 */
	public void setDstFromBytes(byte[] bytes) {
		dstAddress.setBytes(bytes);
	}

	/**
	 * Sets the destination address from a string representation.
	 */
	public void setDstFromString(String ipStr) {
		setDstFromBytes(Ip6Address.parseIpv6Address(ipStr));
	}

	/**
	 * Sets the destination address from an Ip6Address object.
	 */
	public void setDstFromAddress(Ip6Address address) {
		setDstFromBytes(address.bytes());
	}

	/**
	 * @see com.slytechs.jnet.core.api.memory.MemoryBinding#onBindMemorySegment()
	 */
	@Override
	protected void onBindPacket() {
		super.onBindPacket();

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

		super.onUnbindPacket();
	}

	@Override
	public String toString() {
		return format(new StructFormat()).toString();
	}

	@Override
	public StructFormat format(StructFormat p) {
		return p.openln("Ip6")
				.println("version", version())
				.println("trafficClass", trafficClass())
				.println("flowLabel", flowLabel())
				.println("payloadLength", payloadLength())
				.println("nextHeader", nextHeader())
				.println("hopLimit", hopLimit())
				.println("src", src())
				.println("dst", dst())
				.close();
	}

	/**
	 * @see com.slytechs.jnet.protocol.tcpip.ip.Ip#protocol()
	 */
	@Override
	public int protocol() {
		return nextHeader();
	}

	/**
	 * @see com.slytechs.jnet.protocol.tcpip.ip.Ip#setVersion(int)
	 */
	@Override
	public void setVersion(int newVersion) {
		int flow = ((int) VTC_FLOW.get(asMemorySegment(), activeBytesStart())) & 0x0FFF_FFFF;
		flow |= (newVersion << 28);

		VTC_FLOW.set(asMemorySegment(), activeBytesStart(), flow);
	}

	/**
	 * @see com.slytechs.jnet.protocol.tcpip.ip.Ip#computeChecksum()
	 */
	@Override
	public void computeChecksum() {
		throw new UnsupportedOperationException("not implemented yet");
	}
}