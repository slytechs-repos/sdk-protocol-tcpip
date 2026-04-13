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
package com.slytechs.sdk.protocol.tcpip.tcp;

import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;

import com.slytechs.sdk.protocol.core.token.TokenFactory;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class TcpTokens implements TokenFactory {

	public static final int STREAM_SYN = 1;
	public static final int STREAM_FIN = 2;
	public static final int SEGMENT_OUT_OF_ORDER = 3;
	public static final int SEGMENT_TIMEOUT = 4;
	public static final int WINDOW_RESIZE = 5;
	public static final int STREAM_RST = 6;
	public static final int RETRANSMIT = 7;
	public static final int FAST_RETRANSMIT = 8;
	public static final int DUPLICATE_ACK = 9;
	public static final int STREAM_TIMEOUT = 10;

	/**
	 * 
	 */
	public TcpTokens() {}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.TokenFactory#newToken(long,
	 *      java.nio.ByteBuffer, int)
	 */
	@Override
	public TcpToken newToken(long token, ByteBuffer b, int index) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.TokenFactory#newToken(long,
	 *      java.lang.foreign.MemorySegment, long)
	 */
	@Override
	public TcpToken newToken(long token, MemorySegment seg, long offset) {
		throw new UnsupportedOperationException("not implemented yet");
	}

}
