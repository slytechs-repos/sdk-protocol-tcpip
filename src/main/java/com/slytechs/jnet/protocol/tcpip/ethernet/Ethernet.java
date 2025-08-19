package com.slytechs.jnet.protocol.tcpip.ethernet;

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

import com.slytechs.jnet.core.api.format.StructFormat;
import com.slytechs.jnet.core.api.format.StructFormattable;
import com.slytechs.jnet.protocol.api.Header;
import com.slytechs.jnet.protocol.api.address.MacAddress;
import com.slytechs.jnet.protocol.api.address.MacAddressMemory;
import com.slytechs.jnet.protocol.tcpip.Tcpip;

import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;
import static java.lang.foreign.ValueLayout.*;

/**
 * Java binding for Ethernet frame header with correct 14-byte layout. Ethernet
 * frame format as defined in IEEE 802.3.
 */
public final class Ethernet extends Header implements StructFormattable {

	public static final int ID = Tcpip.ETHERNET_ID;
	public static final int LENGTH = 14;

	public static final MemoryLayout LAYOUT$BIG$SIZE_14 = structLayout(
			MacAddressMemory.LAYOUT.withName("hdr_dst_addr"), // Destination MAC Address = 48 bits
			MacAddressMemory.LAYOUT.withName("hdr_src_addr"), // Source MAC Address = 48 bits
			JAVA_SHORT.withName("hdr_ethertype").withOrder(ByteOrder.BIG_ENDIAN) // EtherType/Length = 16 bits
	);

	public static final MemoryLayout LAYOUT = LAYOUT$BIG$SIZE_14;

	private static final VarHandle ETHERTYPE = LAYOUT.varHandle(groupElement("hdr_ethertype"));
	private static final long DST_ADDR_OFF = LAYOUT.byteOffset(groupElement("hdr_dst_addr"));
	private static final long SRC_ADDR_OFF = LAYOUT.byteOffset(groupElement("hdr_src_addr"));

	private final MacAddressMemory dstAddress = new MacAddressMemory();
	private final MacAddressMemory srcAddress = new MacAddressMemory();

	public Ethernet() {
		super(ID, LAYOUT);
	}

	public Ethernet(Arena arena) {
		super(ID, LAYOUT, arena);
	}

	public Ethernet(MemorySegment pointer) {
		super(ID, LAYOUT, pointer);
	}

	public Ethernet(MemorySegment seg, long offset) {
		super(ID, LAYOUT, seg, offset);
	}

	/**
	 * Returns the destination MAC address as a MacAddress object.
	 */
	public MacAddress dst() {
		return dstAddress;
	}

	/**
	 * Returns the destination MAC address as a long.
	 */
	public long dstAsLong() {
		return dstAddress.asLong();
	}

	/**
	 * Returns the destination MAC address as a byte array.
	 */
	public byte[] dstAsBytes() {
		return dstAddress.bytes();
	}

	/**
	 * Returns the destination MAC address as a string.
	 */
	public String dstAsString() {
		return MacAddress.formatMacAddress(dstAddress.bytes());
	}

	/**
	 * Returns the source MAC address as a MacAddress object.
	 */
	public MacAddress src() {
		return srcAddress;
	}

	/**
	 * Returns the source MAC address as a long.
	 */
	public long srcAsLong() {
		return srcAddress.asLong();
	}

	/**
	 * Returns the source MAC address as a byte array.
	 */
	public byte[] srcAsBytes() {
		return srcAddress.bytes();
	}

	/**
	 * Returns the source MAC address as a string.
	 */
	public String srcAsString() {
		return MacAddress.formatMacAddress(srcAddress.bytes());
	}

	/**
	 * Returns the EtherType/Length field (16 bits).
	 */
	public int etherType() {
		return (short) ETHERTYPE.get(asMemorySegment(), activeBytesStart()) & 0xFFFF;
	}

	/**
	 * Sets the EtherType/Length field.
	 */
	public void setEtherType(int value) {
		ETHERTYPE.set(asMemorySegment(), activeBytesStart(), (short) value);
	}

	/**
	 * Returns true if the EtherType field indicates a length (IEEE 802.3). Values
	 * <= 1500 indicate length, values >= 1536 indicate EtherType.
	 */
	public boolean isLength() {
		return etherType() <= 1500;
	}

	/**
	 * Returns true if the EtherType field indicates an EtherType (Ethernet II).
	 * Values >= 1536 indicate EtherType, values <= 1500 indicate length.
	 */
	public boolean isEtherType() {
		return etherType() >= 1536;
	}

	/**
	 * Returns the length value if this is an IEEE 802.3 frame. Only valid if
	 * isLength() returns true.
	 */
	public int lengthValue() {
		if (!isLength()) {
			throw new IllegalStateException("EtherType field does not contain a length value");
		}
		return etherType();
	}

	/**
	 * Returns the EtherType value if this is an Ethernet II frame. Only valid if
	 * isEtherType() returns true.
	 */
	public int etherTypeValue() {
		if (!isEtherType()) {
			throw new IllegalStateException("EtherType field does not contain an EtherType value");
		}
		return etherType();
	}

	/**
	 * Sets the destination MAC address from a long.
	 */
	public void setDst(long mac) {
		dstAddress.setLong(mac);
	}

	/**
	 * Sets the destination MAC address from a MacAddress object.
	 */
	public void setDstFromAddress(MacAddress address) {
		setDst(address.asLong());
	}

	/**
	 * Sets the destination MAC address from a byte array.
	 */
	public void setDstFromBytes(byte[] bytes) {
		dstAddress.setBytes(bytes);
	}

	/**
	 * Sets the destination MAC address from a string.
	 */
	public void setDstFromString(String macStr) {
		setDstFromBytes(MacAddress.parseMacAddress(macStr));
	}

	/**
	 * Sets the source MAC address from a long.
	 */
	public void setSrc(long mac) {
		srcAddress.setLong(mac);
	}

	/**
	 * Sets the source MAC address from a MacAddress object.
	 */
	public void setSrcFromAddress(MacAddress address) {
		setSrc(address.asLong());
	}

	/**
	 * Sets the source MAC address from a byte array.
	 */
	public void setSrcFromBytes(byte[] bytes) {
		srcAddress.setBytes(bytes);
	}

	/**
	 * Sets the source MAC address from a string.
	 */
	public void setSrcFromString(String macStr) {
		setSrcFromBytes(MacAddress.parseMacAddress(macStr));
	}

	/**
	 * Returns true if this is a broadcast frame (destination is broadcast MAC).
	 */
	public boolean isBroadcast() {
		return dst().isBroadcast();
	}

	/**
	 * Returns true if this is a multicast frame (destination is multicast MAC).
	 */
	public boolean isMulticast() {
		return dst().isMulticast();
	}

	/**
	 * Returns true if this is a unicast frame (destination is unicast MAC).
	 */
	public boolean isUnicast() {
		return !isBroadcast() && !isMulticast();
	}

	/**
	 * Returns the frame type description based on EtherType.
	 */
	public String getFrameTypeDescription() {
		if (isLength()) {
			return "IEEE 802.3 (Length=" + lengthValue() + ")";
		}

		int type = etherTypeValue();
		return switch (type) {
		case 0x0800 -> "IPv4";
		case 0x0806 -> "ARP";
		case 0x86DD -> "IPv6";
		case 0x8100 -> "VLAN Tagged";
		case 0x88CC -> "LLDP";
		case 0x8808 -> "Ethernet Flow Control";
		case 0x8809 -> "Ethernet Slow Protocols";
		case 0x8847 -> "MPLS Unicast";
		case 0x8848 -> "MPLS Multicast";
		case 0x88E5 -> "802.1AE (MACsec)";
		case 0x88F7 -> "PTP (Precision Time Protocol)";
		default -> String.format("Unknown (0x%04X)", type);
		};

	}

	@Override
	protected void onBindPacket() {
		dstAddress.bindMemory(asMemory(), activeBytesStart() + DST_ADDR_OFF);
		srcAddress.bindMemory(asMemory(), activeBytesStart() + SRC_ADDR_OFF);
	}

	@Override
	protected void onUnbindPacket() {
		dstAddress.unbindMemory();
		srcAddress.unbindMemory();
	}

	@Override
	public StructFormat format(StructFormat p) {
		return p.openln("Ethernet")
				.println("dst", dstAsString())
				.println("src", srcAsString())
				.println("etherType", String.format("0x%04X (%s)", etherType(), getFrameTypeDescription()))
				.close();
	}

	@Override
	public String toString() {
		return format(new StructFormat()).toString();
	}
}