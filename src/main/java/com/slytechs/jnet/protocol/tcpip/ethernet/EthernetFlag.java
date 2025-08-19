package com.slytechs.jnet.protocol.tcpip.ethernet;

import com.slytechs.jnet.protocol.api.flag.Flag;
import com.slytechs.jnet.protocol.api.flag.FlagDef;

/**
 * Ethernet frame flags and VLAN tag flags. Demonstrates flags for Layer 2
 * protocols.
 */
public enum EthernetFlag implements Flag {
	// MAC address flags (from first byte of MAC address)
	MULTICAST(0), // Bit 0: Multicast/Unicast
	LOCALLY_ADMINISTERED(1), // Bit 1: Locally/Universally Administered

	// Frame type flags (logical flags, not actual bits)
	HAS_VLAN_TAG(8),
	HAS_DOUBLE_TAG(9),
	IS_JUMBO_FRAME(10),
	HAS_FCS(11);

	private final FlagDef impl;

	EthernetFlag(int position) {
		this.impl = new FlagDef(name(), position, 1);
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
