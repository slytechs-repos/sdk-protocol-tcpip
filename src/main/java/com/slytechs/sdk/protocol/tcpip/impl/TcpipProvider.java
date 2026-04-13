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
package com.slytechs.sdk.protocol.tcpip.impl;

import com.slytechs.sdk.protocol.core.Protocol;
import com.slytechs.sdk.protocol.core.pack.ProtocolPack;
import com.slytechs.sdk.protocol.core.spi.PackProvider;
import com.slytechs.sdk.protocol.tcpip.Tcpip;
import com.slytechs.sdk.protocol.tcpip.TcpipPack;
import com.slytechs.sdk.protocol.tcpip.ethernet.EthernetProtocol;
import com.slytechs.sdk.protocol.tcpip.ethernet.VlanProtocol;
import com.slytechs.sdk.protocol.tcpip.ip.Ip4Protocol;
import com.slytechs.sdk.protocol.tcpip.ip.Ip6Protocol;
import com.slytechs.sdk.protocol.tcpip.ipsec.AhProtocol;
import com.slytechs.sdk.protocol.tcpip.ipsec.EspProtocol;
import com.slytechs.sdk.protocol.tcpip.ipsec.EspTrailerProtocol;
import com.slytechs.sdk.protocol.tcpip.mpls.MplsProtocol;
import com.slytechs.sdk.protocol.tcpip.tcp.TcpProtocol;
import com.slytechs.sdk.protocol.tcpip.udp.UdpProtocol;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class TcpipProvider implements PackProvider {

	/**
	 * @see com.slytechs.sdk.protocol.core.spi.PackProvider#protocolPack()
	 */
	@Override
	public ProtocolPack protocolPack() {
		return TcpipPack.of();
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.spi.PackProvider#findProtocol(int)
	 */
	@Override
	public Protocol findProtocol(int protocolId) {
		Tcpip id = Tcpip.valueOf(protocolId);
		if (id == null)
			return null;

		return switch (id) {
		case ETHERNET -> EthernetProtocol.of();
		case VLAN -> VlanProtocol.of();
		case MPLS -> MplsProtocol.of();
		case IPv4 -> Ip4Protocol.of();
		case IPv6 -> Ip6Protocol.of();
		case AH -> AhProtocol.of();
		case ESP -> EspProtocol.of();
		case ESP_TRAILER -> EspTrailerProtocol.of();
		case TCP -> TcpProtocol.of();
		case UDP -> UdpProtocol.of();
		};
	}

}
