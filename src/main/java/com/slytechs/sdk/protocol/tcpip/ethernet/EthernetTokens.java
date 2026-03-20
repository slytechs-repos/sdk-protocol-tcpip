/*
 * Copyright 2005-2026 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.sdk.protocol.tcpip.ethernet;

import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;

import com.slytechs.sdk.protocol.core.token.TokenFactory;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class EthernetTokens implements TokenFactory {

	/**
	 * 
	 */
	public EthernetTokens() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.TokenFactory#newToken(long,
	 *      java.nio.ByteBuffer, int)
	 */
	@Override
	public EthernetToken newToken(long token, ByteBuffer b, int index) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.TokenFactory#newToken(long,
	 *      java.lang.foreign.MemorySegment, long)
	 */
	@Override
	public EthernetToken newToken(long token, MemorySegment seg, long offset) {
		throw new UnsupportedOperationException("not implemented yet");
	}

}
