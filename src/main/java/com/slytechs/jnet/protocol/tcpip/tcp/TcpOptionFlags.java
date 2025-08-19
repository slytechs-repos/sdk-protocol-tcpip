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
package com.slytechs.jnet.protocol.tcpip.tcp;

import java.util.Arrays;
import java.util.Collection;

import com.slytechs.jnet.protocol.api.flag.AbstractFlagSet;

/**
 * TCP options flags container.
 */
public class TcpOptionFlags extends AbstractFlagSet<TcpOptionFlag> {
	private static final Collection<TcpOptionFlag> ALL_FLAGS = Arrays.asList(TcpOptionFlag.values());

	public TcpOptionFlags(long value) {
		super(value, ALL_FLAGS);
	}

	public TcpOptionFlags() {
		this(0);
	}

	@Override
	public TcpOptionFlags withValue(long value) {
		return new TcpOptionFlags(value);
	}

	// Option presence methods
	public boolean hasMss() {
		return isSet(TcpOptionFlag.MSS_PRESENT);
	}

	public boolean hasWindowScale() {
		return isSet(TcpOptionFlag.WINDOW_SCALE_PRESENT);
	}

	public boolean hasSackPermitted() {
		return isSet(TcpOptionFlag.SACK_PERMITTED);
	}

	public boolean hasSack() {
		return isSet(TcpOptionFlag.SACK_PRESENT);
	}

	public boolean hasTimestamp() {
		return isSet(TcpOptionFlag.TIMESTAMP_PRESENT);
	}

	// Window scale methods
	public int getWindowScale() {
		return (int) getValue(TcpOptionFlag.WINDOW_SCALE);
	}

	public TcpOptionFlags withWindowScale(int scale) {
		return (TcpOptionFlags) withValue(TcpOptionFlag.WINDOW_SCALE, scale).withFlag(TcpOptionFlag.WINDOW_SCALE_PRESENT);
	}

	// Convenience methods for setting options
	public TcpOptionFlags withMss() {
		return (TcpOptionFlags) withFlag(TcpOptionFlag.MSS_PRESENT);
	}

	public TcpOptionFlags withSackPermitted() {
		return (TcpOptionFlags) withFlag(TcpOptionFlag.SACK_PERMITTED);
	}

	public TcpOptionFlags withTimestamp() {
		return (TcpOptionFlags) withFlag(TcpOptionFlag.TIMESTAMP_PRESENT);
	}

	public TcpOptionFlags withSack() {
		return (TcpOptionFlags) withFlag(TcpOptionFlag.SACK_PRESENT);
	}

	/**
	 * Returns true if this represents a modern TCP connection with advanced
	 * options.
	 */
	public boolean isModernTcp() {
		return hasWindowScale() || hasSackPermitted() || hasTimestamp();
	}

	/**
	 * Returns true if this connection supports SACK (either permitted or active).
	 */
	public boolean supportsSack() {
		return hasSackPermitted() || hasSack();
	}
}