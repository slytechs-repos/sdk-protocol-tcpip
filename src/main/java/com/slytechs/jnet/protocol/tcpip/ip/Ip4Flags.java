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
 * IPv4 flags container that manages the 3-bit flags field.
 */
public class Ip4Flags extends AbstractFlagSet<Ip4Flag> {
	private static final Collection<Ip4Flag> ALL_FLAGS = Arrays.asList(Ip4Flag.values());

	public Ip4Flags(long value) {
		super(value & 0x07, ALL_FLAGS); // Only use lower 3 bits
	}

	public Ip4Flags() {
		this(0);
	}

	@Override
	public Ip4Flags withValue(long value) {
		return new Ip4Flags(value);
	}

	// Convenience methods for IPv4-specific operations
	public boolean isDontFragment() {
		return isSet(Ip4Flag.DONT_FRAGMENT);
	}

	public boolean isMoreFragments() {
		return isSet(Ip4Flag.MORE_FRAGMENTS);
	}

	public boolean isLastFragment() {
		return !isSet(Ip4Flag.MORE_FRAGMENTS);
	}

	public boolean isFragmented() {
		return isSet(Ip4Flag.MORE_FRAGMENTS) || isSet(Ip4Flag.DONT_FRAGMENT);
	}

	public Ip4Flags setDontFragment() {
		return (Ip4Flags) withFlag(Ip4Flag.DONT_FRAGMENT);
	}

	public Ip4Flags setMoreFragments() {
		return (Ip4Flags) withFlag(Ip4Flag.MORE_FRAGMENTS);
	}

	public Ip4Flags clearDontFragment() {
		return (Ip4Flags) withoutFlag(Ip4Flag.DONT_FRAGMENT);
	}

	public Ip4Flags clearMoreFragments() {
		return (Ip4Flags) withoutFlag(Ip4Flag.MORE_FRAGMENTS);
	}

	/**
	 * Creates flags for a non-fragmented packet.
	 */
	public static Ip4Flags nonFragmented() {
		return new Ip4Flags().setDontFragment();
	}

	/**
	 * Creates flags for the first fragment of a fragmented packet.
	 */
	public static Ip4Flags firstFragment() {
		return new Ip4Flags().setMoreFragments();
	}

	/**
	 * Creates flags for a middle fragment of a fragmented packet.
	 */
	public static Ip4Flags middleFragment() {
		return new Ip4Flags().setMoreFragments();
	}

	/**
	 * Creates flags for the last fragment of a fragmented packet.
	 */
	public static Ip4Flags lastFragment() {
		return new Ip4Flags(); // No flags set
	}
}