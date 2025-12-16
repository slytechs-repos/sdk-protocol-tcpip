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
import com.slytechs.jnet.protocol.api.HeaderExtension;
import com.slytechs.jnet.protocol.api.HeaderFactory;
import com.slytechs.jnet.protocol.api.Protocol;
import com.slytechs.jnet.protocol.tcpip.ethernet.Ethernet;
import com.slytechs.jnet.protocol.tcpip.impl.TcpipProtocolPack;
import com.slytechs.jnet.protocol.tcpip.ip.Ip4;
import com.slytechs.jnet.protocol.tcpip.ip.Ip6;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public enum Tcpip implements Protocol {
	ETHERNET(Ethernet.class, Constants.ETHERNET_ID),
	IPv4(Ip4.class, Constants.IPv4_ID),
	IPv6(Ip6.class, Constants.IPv6_ID),
	;

	public interface Constants {
		int ETHERNET_ID = TCPIP_ID | 1;
		int LLC_ID = TCPIP_ID | 2;
		int SNAP_ID = TCPIP_ID | 3;
		int NOVELL_RAW_ID = TCPIP_ID | 4;
		int ISL_ID = TCPIP_ID | 5;
		int PPP_ID = TCPIP_ID | 6;
		int FDDI_ID = TCPIP_ID | 7;
		int ATM_ID = TCPIP_ID | 8;
		int VLAN_ID = TCPIP_ID | 9;
		int MPLS_ID = TCPIP_ID | 10;
		int IPSEC_AH_ID = TCPIP_ID | 11;
		int IPSEC_ESP_ID = TCPIP_ID | 12;
		int IPSEC_ESP_TRAILER_ID = TCPIP_ID | 13;
		int ARP_ID = TCPIP_ID | 14;        // 0x0E
		int IP_ID = TCPIP_ID | 20;
		int IPv4_ID = TCPIP_ID | 21;
		int IPv6_ID = TCPIP_ID | 22;
		int ICMP_ID = TCPIP_ID | 23;
		int ICMPV6_ID = TCPIP_ID | 24;     // 0x18
		int TCP_ID = TCPIP_ID | 30;
		int UDP_ID = TCPIP_ID | 31;
	}

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
	public List<HeaderExtension> listOptions() {
		throw new UnsupportedOperationException("not implemented yet");
	}

}
