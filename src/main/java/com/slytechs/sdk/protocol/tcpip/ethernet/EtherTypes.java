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
package com.slytechs.sdk.protocol.tcpip.ethernet;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class EtherTypes {
	public static final int VLAN = 0x8100; // IEEE 802.1Q VLAN
	public static final int QINQ_OUTER = 0x88A8; // QinQ outer tag (802.1ad)
	public static final int QINQ_INNER = 0x8100; // QinQ inner tag (same as VLAN)
	public static final int IPV4 = 0x0800;
	public static final int ARP = 0x0806;
	public static final int IPV6 = 0x86DD;
	public static final int LLDP = 0x88CC;
	public static final int MPLS_UNICAST = 0x8847;
	public static final int MPLS_MULTICAST = 0x8848;
	public static final int PTP = 0x88F7;
	public static final int MACSEC = 0x88E5;

	private EtherTypes() {}

}
