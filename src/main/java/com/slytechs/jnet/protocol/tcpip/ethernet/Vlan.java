package com.slytechs.jnet.protocol.tcpip.ethernet;

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

import com.slytechs.jnet.core.api.format.StructFormat;
import com.slytechs.jnet.core.api.format.StructFormattable;
import com.slytechs.jnet.protocol.api.Header;
import com.slytechs.jnet.protocol.api.address.VlanId;
import com.slytechs.jnet.protocol.api.address.VlanIdMemory;
import com.slytechs.jnet.protocol.tcpip.Tcpip;

import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;
import static java.lang.foreign.ValueLayout.*;

/**
 * Java binding for IEEE 802.1Q VLAN tag header with correct 4-byte layout. VLAN
 * tag format as defined in IEEE 802.1Q.
 */
public class Vlan extends Header implements StructFormattable {
	public static final int ID = Tcpip.VLAN_ID;
	public static final int LENGTH = 2;

	public static final MemoryLayout LAYOUT$BIG$SIZE_4 = structLayout(
			JAVA_SHORT.withName("hdr_tpid").withOrder(ByteOrder.BIG_ENDIAN), // Tag Protocol Identifier = 16 bits
			VlanIdMemory.LAYOUT.withName("hdr_tci") // Tag Control Information = 16 bits
	);

	public static final MemoryLayout LAYOUT = LAYOUT$BIG$SIZE_4;

	private static final VarHandle TPID = LAYOUT.varHandle(groupElement("hdr_tpid"));
	private static final long TCI_OFF = LAYOUT.byteOffset(groupElement("hdr_tci"));


	private final VlanIdMemory tci = new VlanIdMemory();

	public Vlan() {
		super(ID, LAYOUT);
	}

	public Vlan(Arena arena) {
		super(ID, LAYOUT, arena);
		onBindPacket();
	}

	public Vlan(MemorySegment pointer) {
		super(ID, LAYOUT, pointer);
		onBindPacket();
	}

	public Vlan(MemorySegment seg, long offset) {
		super(ID, LAYOUT, seg, offset);
		onBindPacket();
	}

	/**
	 * Returns the Tag Protocol Identifier (TPID) field (16 bits). Typically 0x8100
	 * for standard VLAN tags.
	 */
	public int tpid() {
		return (short) TPID.get(asMemorySegment(), segmentOffset()) & 0xFFFF;
	}

	/**
	 * Sets the Tag Protocol Identifier (TPID) field.
	 */
	public void setTpid(int value) {
		TPID.set(asMemorySegment(), segmentOffset(), (short) value);
	}

	/**
	 * Returns the Tag Control Information as a VlanId object. This provides access
	 * to PCP, DEI, and VID fields.
	 */
	public VlanId tci() {
		return tci;
	}

	/**
	 * Returns the Priority Code Point (PCP) field (3 bits). Values 0-7 indicating
	 * frame priority.
	 */
	public int pcp() {
		return tci.pcp();
	}

	/**
	 * Returns the Drop Eligible Indicator (DEI) flag (1 bit). Indicates if the
	 * frame is eligible to be dropped during congestion.
	 */
	public boolean dei() {
		return tci.dei();
	}

	/**
	 * Returns the VLAN Identifier (VID) field (12 bits). The actual VLAN ID
	 * (1-4094, with 0 and 4095 reserved).
	 */
	public int vid() {
		return tci.vid();
	}

	/**
	 * Sets the Priority Code Point (PCP) field.
	 */
	public void setPcp(int pcp) {
		tci.setPcp(pcp);
	}

	/**
	 * Sets the Drop Eligible Indicator (DEI) flag.
	 */
	public void setDei(boolean dei) {
		tci.setDei(dei);
	}

	/**
	 * Sets the VLAN Identifier (VID) field.
	 */
	public void setVid(int vid) {
		tci.setVid(vid);
	}

	/**
	 * Sets all TCI fields at once.
	 */
	public void setTci(int pcp, boolean dei, int vid) {
		tci.setTci(pcp, dei, vid);
	}

	/**
	 * Returns true if this is the standard VLAN EtherType (0x8100).
	 */
	public boolean isStandardVlan() {
		return tpid() == EtherTypes.VLAN;
	}

	/**
	 * Returns true if this is a QinQ (double-tagged) outer tag (0x88A8).
	 */
	public boolean isQinQOuter() {
		return tpid() == EtherTypes.QINQ_OUTER;
	}

	/**
	 * Returns true if this is a QinQ (double-tagged) inner tag (0x8100).
	 */
	public boolean isQinQInner() {
		return tpid() == EtherTypes.VLAN;
	}

	/**
	 * Returns true if this VLAN ID is reserved (0 or 4095).
	 */
	public boolean isReservedVid() {
		int vlanId = vid();
		return vlanId == 0 || vlanId == 4095;
	}

	/**
	 * Returns true if this is a valid user VLAN ID (1-4094).
	 */
	public boolean isValidVid() {
		int vlanId = vid();
		return vlanId >= 1 && vlanId <= 4094;
	}

	/**
	 * Returns true if this VLAN has high priority (PCP >= 4).
	 */
	public boolean isHighPriority() {
		return pcp() >= 4;
	}

	/**
	 * Returns the traffic class description based on PCP value.
	 */
	public String getTrafficClass() {
		return switch (pcp()) {
		case 0 -> "Best Effort";
		case 1 -> "Background";
		case 2 -> "Excellent Effort";
		case 3 -> "Critical Applications";
		case 4 -> "Video";
		case 5 -> "Voice";
		case 6 -> "Internetwork Control";
		case 7 -> "Network Control";
		default -> "Unknown";
		};
	}

	/**
	 * Returns the VLAN type description based on TPID.
	 */
	public String getVlanTypeDescription() {
		return switch (tpid()) {
		case EtherTypes.VLAN -> "IEEE 802.1Q VLAN or QinQ Inner Tag";
		case EtherTypes.QINQ_OUTER -> "QinQ Outer Tag (802.1ad)";
		default -> String.format("Unknown VLAN Type (0x%04X)", tpid());
		};
	}

	@Override
	protected void onBindPacket() {
		super.onBindPacket();

		tci.bindMemory(asMemory(), activeBytesStart() + TCI_OFF);
	}

	@Override
	protected void onUnbindPacket() {
		tci.unbindMemory();

		super.onUnbindPacket();
	}

	@Override
	public StructFormat format(StructFormat p) {
		return p.openln("Vlan")
				.println("tpid", String.format("0x%04X (%s)", tpid(), getVlanTypeDescription()))
				.println("pcp", pcp() + " (" + getTrafficClass() + ")")
				.println("dei", dei() ? "drop-eligible" : "keep")
				.println("vid", vid())
				.close();
	}

	@Override
	public String toString() {
		return format(new StructFormat()).toString();
	}
}