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
package com.slytechs.sdk.protocol.tcpip.table;

import java.util.Locale;
import java.util.ResourceBundle;

import com.slytechs.sdk.protocol.core.table.StringTableValue;
import com.slytechs.sdk.protocol.core.table.TableLookup;

class Ipv4ProtoTable implements TableLookup {
	private final ResourceBundle defaultBundle;

	Ipv4ProtoTable() {
		this.defaultBundle = ResourceBundle.getBundle("tables.protocol.tcpip.ipv4_proto");
	}

	@Override
	public String getProtocol() {
		return TcpIpTableProvider.PROTOCOL;
	}

	@Override
	public String getTableName() {
		return "ipv4_proto";
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
			ResourceBundle bundle = ResourceBundle.getBundle("tables.protocol.tcpip.ipv4_proto", locale);
			return bundle.containsKey(key) ? new StringTableValue(bundle.getString(key)) : null;
		} catch (Exception e) {
			TcpIpTableProvider.LOGGER.warning("Failed to load resource bundle for locale " + locale + ": " + e
					.getMessage());
			return null;
		}
	}
}