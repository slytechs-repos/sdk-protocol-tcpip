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

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;

import com.slytechs.jnet.core.api.format.StructFormattable;
import com.slytechs.jnet.protocol.api.Header;
import com.slytechs.jnet.protocol.api.address.IpAddress;
import com.slytechs.jnet.protocol.tcpip.Tcpip;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public abstract class Ip extends Header implements StructFormattable {
	public static final int ID = Tcpip.IP_ID;

	public Ip(int id, MemoryLayout layout) {
		super(id, layout);
	}

	public Ip(int id, MemoryLayout layout, Arena arena) {
		super(id, layout, arena);
	}

	public Ip(int id, MemoryLayout layout, MemorySegment pointer) {
		super(id, layout, pointer);
	}

	public Ip(int id, MemoryLayout layout, MemorySegment pointer, Arena arena) {
		super(id, layout, pointer, arena);
	}

	public Ip(int id, MemoryLayout layout, MemorySegment seg, long offset) {
		super(id, layout, seg, offset);
	}

	public abstract void computeChecksum();

	public abstract IpAddress dst();

	public abstract int protocol();

	public abstract void setVersion(int newVersion);

	public abstract IpAddress src();

	public abstract int version();
}
