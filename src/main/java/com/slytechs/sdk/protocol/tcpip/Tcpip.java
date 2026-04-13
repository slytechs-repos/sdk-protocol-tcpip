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
package com.slytechs.sdk.protocol.tcpip;

import com.slytechs.sdk.protocol.core.id.ProtocolId;
import com.slytechs.sdk.protocol.core.id.ProtocolIds;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public enum Tcpip implements ProtocolId {
	ETHERNET(ProtocolIds.ETHERNET),
	VLAN(ProtocolIds.VLAN),
	MPLS(ProtocolIds.MPLS),
	IPv4(ProtocolIds.IPv4),
	IPv6(ProtocolIds.IPv6),
	AH(ProtocolIds.AH),
	ESP(ProtocolIds.ESP),
	ESP_TRAILER(ProtocolIds.ESP_TRAILER),
	TCP(ProtocolIds.TCP),
	UDP(ProtocolIds.UDP),
	;

	private final int id;

	public static Tcpip valueOf(int id) {
		int descriptorId = ProtocolIds.descriptorId(id);
		for (var c : values())
			if (ProtocolIds.descriptorId(c.id) == descriptorId)
				return c;

		return null;
	}

	Tcpip(int id) {
		this.id = id;
	}

	/**
	 * @see com.slytechs.jnet.proto.api.Protocol#id()
	 */
	@Override
	public int id() {
		return id;
	}

}
