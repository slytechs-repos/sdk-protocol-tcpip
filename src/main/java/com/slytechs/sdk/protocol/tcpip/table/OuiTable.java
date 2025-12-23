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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import com.slytechs.sdk.protocol.core.table.StringTableValue;
import com.slytechs.sdk.protocol.core.table.TableLookup;

class OuiTable implements TableLookup {
    private static class TrieNode {
        Map<Character, TrieNode> children = new HashMap<>();
        String vendor;
        WeakReference<TrieNode> weakRef;

        TrieNode() {
            this.weakRef = new WeakReference<>(this);
        }
    }

    private volatile WeakReference<TrieNode> root;

    OuiTable() {
        TrieNode rootNode = new TrieNode();
        this.root = new WeakReference<>(rootNode);
        loadOuiTable(rootNode, 0, 1000); // Load first chunk (1000 entries)
    }

    private void loadOuiTable(TrieNode root, int startLine, int chunkSize) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                getClass().getClassLoader().getResourceAsStream("tables/protocol/tcpip/ieee_oui_manufacturer.dat")))) {
            String line;
            int lineNum = 0;
            while ((line = reader.readLine()) != null && lineNum < startLine + chunkSize) {
                if (lineNum >= startLine && !line.startsWith("#") && !line.trim().isEmpty()) {
                    String[] parts = line.split("=", 2);
                    if (parts.length == 2) {
                        String oui = parts[0].trim();
                        String vendor = parts[1].trim();
                        insertIntoTrie(root, oui, vendor);
                    }
                }
                lineNum++;
            }
        } catch (IOException e) {
            TcpIpTableProvider.LOGGER.warning("Failed to load OUI table: " + e.getMessage());
        }
    }

    private void insertIntoTrie(TrieNode root, String oui, String vendor) {
        String[] parts = oui.split("/");
        String key = parts[0];
        int mask = parts.length > 1 ? Integer.parseInt(parts[1]) : key.length() * 4;

        TrieNode current = root;
        int bitsProcessed = 0;
        for (char c : key.toCharArray()) {
            if (bitsProcessed >= mask) {
                break; // Stop at mask length
            }
            current = current.children.computeIfAbsent(c, k -> new TrieNode());
            bitsProcessed += 4; // Each hex digit is 4 bits
        }
        current.vendor = vendor;
    }

    @Override
    public String getProtocol() {
        return TcpIpTableProvider.PROTOCOL;
    }

    @Override
    public String getTableName() {
        return "oui";
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
        synchronized (this) { // Ensure thread-safe access to root
            TrieNode rootNode = root.get();
            if (rootNode == null) {
                // Reload if GC'd
                rootNode = new TrieNode();
                root = new WeakReference<>(rootNode);
                loadOuiTable(rootNode, 0, 1000);
            }
            String normalizedKey = normalizeOuiKey(key);
            String vendor = lookupInTrie(rootNode, normalizedKey);
            return vendor != null ? new StringTableValue(vendor) : null;
        }
    }

    private String normalizeOuiKey(String key) {
        // Accept formats like "00:00:0C", "00-00-0C", "00000C", or "00000C/24"
        String normalized = key.replaceAll("[:-]", "").toUpperCase();
        if (!normalized.matches("^[0-9A-F]+(/\\d+)?$")) {
            throw new IllegalArgumentException("Invalid OUI key format: " + key);
        }
        return normalized;
    }

    private String lookupInTrie(TrieNode node, String oui) {
        TrieNode current = node;
        String lastVendor = null;
        for (char c : oui.toCharArray()) {
            if (current == null) {
                break;
            }
            if (current.vendor != null) {
                lastVendor = current.vendor; // Store last valid vendor for prefix matching
            }
            current = current.children.get(c);
        }
        return current != null && current.vendor != null ? current.vendor : lastVendor;
    }
}