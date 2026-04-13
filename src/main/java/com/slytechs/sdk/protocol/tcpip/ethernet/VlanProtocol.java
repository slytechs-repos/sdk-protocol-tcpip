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

import com.slytechs.sdk.protocol.core.Protocol;
import com.slytechs.sdk.protocol.core.header.HeaderFactory;
import com.slytechs.sdk.protocol.core.id.ProtocolIds;
import com.slytechs.sdk.protocol.core.pack.ProtocolPack;
import com.slytechs.sdk.protocol.tcpip.TcpipPack;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public final class VlanProtocol implements Protocol {

	private static final VlanProtocol INSTANCE = new VlanProtocol();
	public static final int ID = ProtocolIds.VLAN;
	public static final String NAME = "Vlan";
	public static final ProtocolPack PACK = TcpipPack.of();
	public static final HeaderFactory<Vlan> FACTORY = Vlan::new;

	public static VlanProtocol of() {
		return INSTANCE;
	}

	private VlanProtocol() {}

	/**
	 * @see com.slytechs.sdk.protocol.core.Protocol#id()
	 */
	@Override
	public int id() {
		return ID;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.Protocol#name()
	 */
	@Override
	public String name() {
		return NAME;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.Protocol#protocolPack()
	 */
	@Override
	public ProtocolPack protocolPack() {
		return PACK;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.Protocol#headerFactory()
	 */
	@Override
	public HeaderFactory<?> headerFactory() {
		return FACTORY;
	}

}
