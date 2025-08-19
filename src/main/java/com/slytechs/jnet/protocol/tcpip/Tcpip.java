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

import static com.slytechs.jnet.protocol.api.pack.ProtocolPack.*;

import java.util.List;

import com.slytechs.jnet.protocol.api.Header;
import com.slytechs.jnet.protocol.api.HeaderFactory;
import com.slytechs.jnet.protocol.api.Option;
import com.slytechs.jnet.protocol.api.Protocol;
import com.slytechs.jnet.protocol.tcpip.ethernet.Ethernet;
import com.slytechs.jnet.protocol.tcpip.ethernet.Vlan;
import com.slytechs.jnet.protocol.tcpip.impl.TcpipProtocolPack;
import com.slytechs.jnet.protocol.tcpip.ip.Ip;
import com.slytechs.jnet.protocol.tcpip.ip.Ip4;
import com.slytechs.jnet.protocol.tcpip.ip.Ip6;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public enum Tcpip implements Protocol {
	ETHERNET(Ethernet.class, Tcpip.ETHERNET_ID),
	VLAN(Vlan.class, Tcpip.VLAN_ID),
	IP(Ip.class, Tcpip.IP_ID),
	IPv4(Ip4.class, Tcpip.IPv4_ID),
	IPv6(Ip6.class, Tcpip.IPv6_ID),
	;

	public static final int ETHERNET_ID = TCPIP_ID | 1;
	public static final int VLAN_ID = TCPIP_ID | 2;
	public static final int IP_ID = TCPIP_ID | 10;
	public static final int IPv4_ID = TCPIP_ID | 11;
	public static final int IPv6_ID = TCPIP_ID | 12;
	public static final int ICMP_ID = TCPIP_ID | 13;
	public static final int TCP_ID = TCPIP_ID | 14;
	public static final int UDP_ID = TCPIP_ID | 15;

	private final int id;

	public static Tcpip valueOf(int id) {
		for (var c : values())
			if (c.id == id)
				return c;

		return null;
	}

	<T extends Header> Tcpip(Class<T> headerClass, int id) {
		this.id = id;
	}

	/**
	 * @see com.slytechs.jnet.proto.api.Protocol#id()
	 */
	@Override
	public int id() {
		return id;
	}

	/**
	 * @see com.slytechs.jnet.proto.api.Protocol#pack()
	 */
	@Override
	public TcpipProtocolPack pack() {
		return TcpipProtocolPack.get();
	}

	/**
	 * @see com.slytechs.jnet.proto.api.Protocol#headerFactory()
	 */
	@Override
	public HeaderFactory<?> headerFactory() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.proto.api.Protocol#listOptions()
	 */
	@Override
	public List<Option> listOptions() {
		throw new UnsupportedOperationException("not implemented yet");
	}

}
