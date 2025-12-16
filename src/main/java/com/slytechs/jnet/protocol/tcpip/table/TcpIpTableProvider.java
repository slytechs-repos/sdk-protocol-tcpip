/*
 * Sly Technologies Free License
 * 
 * Copyright 2024 Sly Technologies Inc.
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
package com.slytechs.jnet.protocol.tcpip.table;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

import com.slytechs.jnet.protocol.api.table.TableLookup;
import com.slytechs.jnet.protocol.api.table.TableProvider;

/**
 * Table provider for TCP/IP protocol tables.
 * <p>
 * Provides lookup tables for TCP/IP protocols, including EtherType and OUI
 * tables. EtherType lookups are backed by properties files for multilingual
 * support, while OUI lookups use a Trie-based structure loaded from
 * ieee_oui_manufacturer.dat.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public class TcpIpTableProvider implements TableProvider {

	static final Logger LOGGER = Logger.getLogger(TcpIpTableProvider.class.getName());
	static final String PROTOCOL = "tcpip";
	private static final Set<String> SUPPORTED_TABLES = Set.of(
			"ether_type", "ether_type_abbr",
			"oui",
			"ipv4_proto", "ipv4_proto_abbr",
			"tcp_port", "tcp_port_abbr");

	@Override
	public Set<String> getSupportedProtocols() {
		return Collections.singleton(PROTOCOL);
	}

	@Override
	public Set<String> getSupportedTables(String protocol) {
		return PROTOCOL.equals(protocol) ? new HashSet<>(SUPPORTED_TABLES) : Collections.emptySet();
	}

	@Override
	public TableLookup provideTable(String protocol, String tableName) {
		if (!PROTOCOL.equals(protocol)) {
			return null;
		}
		return switch (tableName) {
		case "ether_type" -> new EtherTypeTable();
		case "ether_type_abbr" -> new EtherTypeAbbrTable();
		case "ipv4_proto" -> new Ipv4ProtoTable();
		case "ipv4_proto_abbr" -> new Ipv4ProtoAbbrTable();
		case "tcp_port" -> new TcpPortTable();
		case "tcp_port_abbr" -> new TcpPortAbbrTable();
		case "oui" -> new OuiTable();
		default -> null;
		};
	}
}