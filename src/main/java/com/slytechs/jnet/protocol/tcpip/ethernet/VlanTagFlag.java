package com.slytechs.jnet.protocol.tcpip.ethernet;

import com.slytechs.jnet.protocol.api.flag.Flag;
import com.slytechs.jnet.protocol.api.flag.FlagDef;

/**
 * VLAN tag flags as defined in IEEE 802.1Q. Handles the 4-byte VLAN tag
 * structure.
 */
public enum VlanTagFlag implements Flag {
	// VLAN Tag Control Information (TCI) - 16 bits
	PCP(13, 3), // Priority Code Point (3 bits)
	DEI(12), // Drop Eligible Indicator (1 bit)
	VID(0, 12); // VLAN Identifier (12 bits)

	private final FlagDef impl;

	VlanTagFlag(int position) {
		this.impl = new FlagDef(name(), position, 1);
	}

	VlanTagFlag(int position, int width) {
		this.impl = new FlagDef(name(), position, width);
	}

	@Override
	public long mask() {
		return impl.mask();
	}

	@Override
	public int position() {
		return impl.position();
	}

	@Override
	public String toString() {
		return impl.toString();
	}
}