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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * OUI (Organizationally Unique Identifier) resolver with two-tier lazy loading.
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public final class OuiResolver {

    private static final String SMALL_RESOURCE = "/tables/protocol/tcpip/oui_small.dat";
    private static final String LARGE_RESOURCE = "/tables/protocol/tcpip/oui_large.dat";

    private static volatile Map<Integer, String> smallTable;
    private static volatile Map<Integer, String> largeTable;
    private static volatile boolean largeEnabled;

    private OuiResolver() {}

    public static void enableFullResolution() {
        largeEnabled = true;
    }

    public static void preloadFullResolutionAsync() {
        largeEnabled = true;
        Thread.ofVirtual().start(OuiResolver::getLargeTable);
    }

    public static String resolve(int oui) {
        Map<Integer, String> small = getSmallTable();
        if (small != null) {
            String name = small.get(oui);
            if (name != null) return name;
        }

        if (largeEnabled) {
            Map<Integer, String> large = getLargeTable();
            if (large != null) {
                return large.get(oui);
            }
        }

        return null;
    }

    public static boolean isFullResolutionEnabled() {
        return largeEnabled;
    }

    public static boolean isFullResolutionLoaded() {
        return largeTable != null;
    }

    private static Map<Integer, String> getSmallTable() {
        if (smallTable == null) {
            synchronized (OuiResolver.class) {
                if (smallTable == null) {
                    smallTable = loadResource(SMALL_RESOURCE);
                }
            }
        }
        return smallTable;
    }

    private static Map<Integer, String> getLargeTable() {
        if (largeTable == null) {
            synchronized (OuiResolver.class) {
                if (largeTable == null) {
                    largeTable = loadResource(LARGE_RESOURCE);
                }
            }
        }
        return largeTable;
    }

    private static Map<Integer, String> loadResource(String resourceName) {
        Map<Integer, String> map = new HashMap<>();

        try (InputStream is = OuiResolver.class.getResourceAsStream(resourceName)) {
            if (is == null) return map;

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(is, StandardCharsets.UTF_8))) {

                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) continue;

                    int eq = line.indexOf('=');
                    if (eq < 0) continue;

                    try {
                        int oui = Integer.parseInt(line.substring(0, eq).trim(), 16);
                        String name = line.substring(eq + 1).trim();
                        map.put(oui, name);
                    } catch (NumberFormatException e) {
                        // Skip malformed lines
                    }
                }
            }
        } catch (IOException e) {
            // Return partial map on error
        }

        return map;
    }
}