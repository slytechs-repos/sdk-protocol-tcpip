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
package com.slytechs.jnet.protocol.tcpip.table;

import java.util.Locale;
import java.util.ResourceBundle;

import com.slytechs.jnet.protocol.api.table.StringTableValue;
import com.slytechs.jnet.protocol.api.table.TableLookup;

class TcpPortTable implements TableLookup {
	private final ResourceBundle defaultBundle;

	TcpPortTable() {
		this.defaultBundle = ResourceBundle.getBundle("tables.protocol.tcpip.tcp_port");
	}

	@Override
	public String getProtocol() {
		return TcpIpTableProvider.PROTOCOL;
	}

	@Override
	public String getTableName() {
		return "tcp_port";
	}

	@Override
	public StringTableValue lookupString(String key) {
		return lookupString(key, Locale.getDefault());
	}

	@Override
	public StringTableValue lookupString(String key, Locale locale) {
		if (key == null) {
			throw new IllegalArgumentException("Key cannot be null");
		}
		try {
			// Normalize key to tcp_port.0x#### format
			ResourceBundle bundle = ResourceBundle.getBundle("tables.protocol.tcpip.tcp_port", locale);
			return bundle.containsKey(key) ? new StringTableValue(bundle.getString(key)) : null;
		} catch (Exception e) {
			TcpIpTableProvider.LOGGER.warning("Failed to load resource bundle for locale " + locale + ": " + e
					.getMessage());
			return null;
		}
	}
}