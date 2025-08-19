package com.slytechs.jnet.protocol.tcpip.tcp;

import com.slytechs.jnet.protocol.api.flag.Flag;
import com.slytechs.jnet.protocol.api.flag.FlagDef;

/**
 * TCP window scaling and options flags. Demonstrates how to handle more complex
 * flag scenarios.
 */
public enum TcpOptionFlag implements Flag {
	// TCP Options presence flags (not actual bits, but logical flags)
	MSS_PRESENT(0),
	WINDOW_SCALE_PRESENT(1),
	SACK_PERMITTED(2),
	SACK_PRESENT(3),
	TIMESTAMP_PRESENT(4),

	// Window scaling factor (4-bit field)
	WINDOW_SCALE(8, 4);

	private final FlagDef impl;

	TcpOptionFlag(int position) {
		this.impl = new FlagDef(name(), position, 1);
	}

	TcpOptionFlag(int position, int width) {
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