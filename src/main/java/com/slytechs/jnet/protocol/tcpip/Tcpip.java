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
package com.slytechs.jnet.protocol.tcpip;

import java.util.List;

import com.slytechs.jnet.protocol.api.Header;
import com.slytechs.jnet.protocol.api.HeaderExtension;
import com.slytechs.jnet.protocol.api.HeaderFactory;
import com.slytechs.jnet.protocol.api.Protocol;
import com.slytechs.jnet.protocol.api.ProtocolId;
import com.slytechs.jnet.protocol.api.pack.ProtocolPack;
import com.slytechs.jnet.protocol.tcpip.ethernet.Ethernet;
import com.slytechs.jnet.protocol.tcpip.impl.TcpipProtocolPack;
import com.slytechs.jnet.protocol.tcpip.ip.Ip4;
import com.slytechs.jnet.protocol.tcpip.ip.Ip6;
import com.slytechs.jnet.protocol.tcpip.tcp.Tcp;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public enum Tcpip implements Protocol {
	ETHERNET(Ethernet.class, ProtocolId.ETHERNET),
	IPv4(Ip4.class, ProtocolId.IPv4),
	IPv6(Ip6.class, ProtocolId.IPv6),
	Tcp(Tcp.class, ProtocolId.TCP),
	;


	private final int id;
	private final HeaderFactory<?> headerFactory;

	public static Tcpip valueOf(int id) {
		for (var c : values())
			if (c.id == id)
				return c;

		return null;
	}

	<T extends Header> Tcpip(Class<T> headerClass, int id) {
		this.id = id;
		this.headerFactory = new HeaderFactory<>(headerClass);
	}

	/**
	 * @see com.slytechs.jnet.proto.api.Protocol#descriptorId()
	 */
	@Override
	public int id() {
		return id;
	}

	/**
	 * @see com.slytechs.jnet.proto.api.Protocol#pack()
	 */
	@Override
	public ProtocolPack pack() {
		return TcpipProtocolPack.get();
	}

	/**
	 * @see com.slytechs.jnet.proto.api.Protocol#headerFactory()
	 */
	@Override
	public HeaderFactory<?> headerFactory() {
		return headerFactory;
	}

	/**
	 * @see com.slytechs.jnet.proto.api.Protocol#listOptions()
	 */
	@Override
	public List<HeaderExtension> listOptions() {
		throw new UnsupportedOperationException("not implemented yet");
	}

}
