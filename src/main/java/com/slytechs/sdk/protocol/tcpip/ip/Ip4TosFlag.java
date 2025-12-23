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

import com.slytechs.sdk.protocol.core.flag.Flag;
import com.slytechs.sdk.protocol.core.flag.FlagDef;

/**
 * IPv4 Type of Service (TOS) flags and fields. Handles the 8-bit TOS field with
 * both legacy TOS and modern DSCP/ECN interpretation.
 */
public enum Ip4TosFlag implements Flag {
	// Legacy TOS interpretation (RFC 791)
	PRECEDENCE(5, 3), // Bits 7-5: Precedence
	DELAY(4), // Bit 4: Delay
	THROUGHPUT(3), // Bit 3: Throughput
	RELIABILITY(2), // Bit 2: Reliability
	COST(1), // Bit 1: Cost

	// Modern DSCP/ECN interpretation (RFC 2474, RFC 3168)
	DSCP(2, 6), // Bits 7-2: Differentiated Services Code Point
	ECN(0, 2); // Bits 1-0: Explicit Congestion Notification

	private final FlagDef impl;

	Ip4TosFlag(int position) {
		this.impl = new FlagDef(name(), position, 1);
	}

	Ip4TosFlag(int position, int width) {
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