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
package com.slytechs.jnet.protocol.tcpip.ip;

import java.util.Arrays;
import java.util.Collection;

import com.slytechs.jnet.protocol.api.flag.AbstractFlagSet;

/**
 * IPv4 Type of Service flags container.
 */
public class Ip4TosFlags extends AbstractFlagSet<Ip4TosFlag> {
	private static final Collection<Ip4TosFlag> ALL_FLAGS = Arrays.asList(Ip4TosFlag.values());

	public Ip4TosFlags(long value) {
		super(value & 0xFF, ALL_FLAGS); // Only use lower 8 bits
	}

	public Ip4TosFlags() {
		this(0);
	}

	@Override
	public Ip4TosFlags withValue(long value) {
		return new Ip4TosFlags(value);
	}

	// Legacy TOS methods
	public int getPrecedence() {
		return (int) getValue(Ip4TosFlag.PRECEDENCE);
	}

	public boolean isLowDelay() {
		return isSet(Ip4TosFlag.DELAY);
	}

	public boolean isHighThroughput() {
		return isSet(Ip4TosFlag.THROUGHPUT);
	}

	public boolean isHighReliability() {
		return isSet(Ip4TosFlag.RELIABILITY);
	}

	public boolean isLowCost() {
		return isSet(Ip4TosFlag.COST);
	}

	// Modern DSCP/ECN methods
	public int getDscp() {
		return (int) getValue(Ip4TosFlag.DSCP);
	}

	public int getEcn() {
		return (int) getValue(Ip4TosFlag.ECN);
	}

	public Ip4TosFlags withDscp(int dscp) {
		return (Ip4TosFlags) withValue(Ip4TosFlag.DSCP, dscp);
	}

	public Ip4TosFlags withEcn(int ecn) {
		return (Ip4TosFlags) withValue(Ip4TosFlag.ECN, ecn);
	}

	// Well-known DSCP values
	public static Ip4TosFlags defaultDscp() {
		return new Ip4TosFlags().withDscp(0);
	}

	public static Ip4TosFlags expeditedForwarding() {
		return new Ip4TosFlags().withDscp(46); // EF
	}

	public static Ip4TosFlags assuredForwarding11() {
		return new Ip4TosFlags().withDscp(10); // AF11
	}

	public static Ip4TosFlags assuredForwarding21() {
		return new Ip4TosFlags().withDscp(18); // AF21
	}

	public static Ip4TosFlags assuredForwarding31() {
		return new Ip4TosFlags().withDscp(26); // AF31
	}

	public static Ip4TosFlags assuredForwarding41() {
		return new Ip4TosFlags().withDscp(34); // AF41
	}
}