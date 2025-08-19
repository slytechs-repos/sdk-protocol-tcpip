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
package com.slytechs.jnet.protocol.tcpip.ethernet;

import java.util.Arrays;
import java.util.Collection;

import com.slytechs.jnet.protocol.api.flag.AbstractFlagSet;

/**
 * Ethernet frame flags container.
 */
public class EthernetFlags extends AbstractFlagSet<EthernetFlag> {
	private static final Collection<EthernetFlag> ALL_FLAGS = Arrays.asList(EthernetFlag.values());

	public EthernetFlags(long value) {
		super(value, ALL_FLAGS);
	}

	public EthernetFlags() {
		this(0);
	}

	@Override
	public EthernetFlags withValue(long value) {
		return new EthernetFlags(value);
	}

	// MAC address methods
	public boolean isMulticast() {
		return isSet(EthernetFlag.MULTICAST);
	}

	public boolean isUnicast() {
		return !isSet(EthernetFlag.MULTICAST);
	}

	public boolean isLocallyAdministered() {
		return isSet(EthernetFlag.LOCALLY_ADMINISTERED);
	}

	public boolean isUniversallyAdministered() {
		return !isSet(EthernetFlag.LOCALLY_ADMINISTERED);
	}

	// Frame type methods
	public boolean hasVlanTag() {
		return isSet(EthernetFlag.HAS_VLAN_TAG);
	}

	public boolean hasDoubleTag() {
		return isSet(EthernetFlag.HAS_DOUBLE_TAG);
	}

	public boolean isJumboFrame() {
		return isSet(EthernetFlag.IS_JUMBO_FRAME);
	}

	public boolean hasFcs() {
		return isSet(EthernetFlag.HAS_FCS);
	}

	// Convenience methods
	public EthernetFlags asMulticast() {
		return (EthernetFlags) withFlag(EthernetFlag.MULTICAST);
	}

	public EthernetFlags asUnicast() {
		return (EthernetFlags) withoutFlag(EthernetFlag.MULTICAST);
	}

	public EthernetFlags withVlanTag() {
		return (EthernetFlags) withFlag(EthernetFlag.HAS_VLAN_TAG);
	}

	public EthernetFlags withJumboFrame() {
		return (EthernetFlags) withFlag(EthernetFlag.IS_JUMBO_FRAME);
	}

	/**
	 * Creates flags for a standard unicast frame.
	 */
	public static EthernetFlags standardUnicast() {
		return new EthernetFlags().asUnicast();
	}

	/**
	 * Creates flags for a multicast frame.
	 */
	public static EthernetFlags multicastFrame() {
		return new EthernetFlags().asMulticast();
	}

	/**
	 * Creates flags for a VLAN-tagged frame.
	 */
	public static EthernetFlags vlanTaggedFrame() {
		return new EthernetFlags().withVlanTag();
	}
}