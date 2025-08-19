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
 * VLAN tag flags container.
 */
public class VlanTagFlags extends AbstractFlagSet<VlanTagFlag> {
	private static final Collection<VlanTagFlag> ALL_FLAGS = Arrays.asList(VlanTagFlag.values());

	public VlanTagFlags(long value) {
		super(value & 0xFFFF, ALL_FLAGS); // Only use lower 16 bits (TCI)
	}

	public VlanTagFlags() {
		this(0);
	}

	@Override
	public VlanTagFlags withValue(long value) {
		return new VlanTagFlags(value);
	}

	// Field accessor methods
	public int getPcp() {
		return (int) getValue(VlanTagFlag.PCP);
	}

	public boolean isDei() {
		return isSet(VlanTagFlag.DEI);
	}

	public int getVid() {
		return (int) getValue(VlanTagFlag.VID);
	}

	// Field setter methods
	public VlanTagFlags withPcp(int pcp) {
		return (VlanTagFlags) withValue(VlanTagFlag.PCP, pcp);
	}

	public VlanTagFlags withDei(boolean dei) {
		return dei ? (VlanTagFlags) withFlag(VlanTagFlag.DEI) : (VlanTagFlags) withoutFlag(VlanTagFlag.DEI);
	}

	public VlanTagFlags withVid(int vid) {
		return (VlanTagFlags) withValue(VlanTagFlag.VID, vid);
	}

	// Priority methods
	public boolean isHighPriority() {
		return getPcp() >= 4;
	}

	public boolean isLowPriority() {
		return getPcp() < 4;
	}

	public boolean isNetworkControl() {
		return getPcp() == 7;
	}

	public boolean isVoice() {
		return getPcp() == 6;
	}

	public boolean isVideo() {
		return getPcp() == 5;
	}

	public boolean isCriticalData() {
		return getPcp() == 4;
	}

	public boolean isBestEffort() {
		return getPcp() == 0;
	}

	// VLAN ID methods
	public boolean isDefaultVlan() {
		return getVid() == 1;
	}

	public boolean isReservedVlan() {
		return getVid() == 0 || getVid() == 4095;
	}

	public boolean isValidVlan() {
		return getVid() >= 1 && getVid() <= 4094;
	}

	/**
	 * Returns the traffic class description based on PCP value.
	 */
	public String getTrafficClass() {
		switch (getPcp()) {
		case 0:
			return "Best Effort";
		case 1:
			return "Background";
		case 2:
			return "Excellent Effort";
		case 3:
			return "Critical Applications";
		case 4:
			return "Video";
		case 5:
			return "Voice";
		case 6:
			return "Internetwork Control";
		case 7:
			return "Network Control";
		default:
			return "Unknown";
		}
	}

	// Factory methods for common configurations
	public static VlanTagFlags defaultVlan() {
		return new VlanTagFlags().withVid(1).withPcp(0);
	}

	public static VlanTagFlags voiceVlan(int vid) {
		return new VlanTagFlags().withVid(vid).withPcp(6);
	}

	public static VlanTagFlags videoVlan(int vid) {
		return new VlanTagFlags().withVid(vid).withPcp(5);
	}

	public static VlanTagFlags dataVlan(int vid) {
		return new VlanTagFlags().withVid(vid).withPcp(3);
	}

	public static VlanTagFlags managementVlan(int vid) {
		return new VlanTagFlags().withVid(vid).withPcp(7);
	}

	@Override
	public String toString() {
		return String.format("VLAN[vid=%d, pcp=%d(%s), dei=%s]",
				getVid(), getPcp(), getTrafficClass(), isDei() ? "drop" : "keep");
	}
}