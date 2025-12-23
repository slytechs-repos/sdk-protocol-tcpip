package com.slytechs.sdk.protocol.tcpip.ip;

import com.slytechs.sdk.protocol.core.flag.Flag;
import com.slytechs.sdk.protocol.core.flag.FlagDef;

/**
 * IPv4 header flags as defined in RFC 791. Handles the flags field in the IPv4
 * header (3 bits total).
 */
public enum Ip4Flag implements Flag {
	// Standard IPv4 flags (3-bit field)
	RESERVED(2), // Bit 0 (MSB) - Reserved, must be zero
	DONT_FRAGMENT(1), // Bit 1 - Don't Fragment (DF)
	MORE_FRAGMENTS(0); // Bit 2 (LSB) - More Fragments (MF)

	private final FlagDef impl;

	Ip4Flag(int position) {
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