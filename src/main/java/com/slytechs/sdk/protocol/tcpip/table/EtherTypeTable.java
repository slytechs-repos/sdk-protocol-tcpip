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

class EtherTypeTable implements TableLookup {
    private final ResourceBundle defaultBundle;

    EtherTypeTable() {
        this.defaultBundle = ResourceBundle.getBundle("tables.protocol.tcpip.ether_type");
    }

    @Override
    public String getProtocol() {
        return TcpIpTableProvider.PROTOCOL;
    }

    @Override
    public String getTableName() {
        return "ether_type";
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
            // Normalize key to ether_type.0x#### format
            String normalizedKey = normalizeEtherTypeKey(key);
            ResourceBundle bundle = ResourceBundle.getBundle("tables.protocol.tcpip.ether_type", locale);
            return bundle.containsKey(normalizedKey) ? new StringTableValue(bundle.getString(normalizedKey)) : null;
        } catch (Exception e) {
            TcpIpTableProvider.LOGGER.warning("Failed to load resource bundle for locale " + locale + ": " + e.getMessage());
            return null;
        }
    }

    private String normalizeEtherTypeKey(String key) {
        // Accept formats like "0x0800", "0800", or "2048" (decimal)
        String cleanKey = key.replaceAll("[^0-9A-Fa-f]", "").toLowerCase();
        try {
            int value = Integer.parseInt(cleanKey, 16); // Always parse as hex
            if (value < 0 || value > 0xFFFF) {
                throw new IllegalArgumentException("EtherType value out of range: " + key);
            }
            return String.format("ether_type.0x%04x", value);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid EtherType key format: " + key);
        }
    }
}