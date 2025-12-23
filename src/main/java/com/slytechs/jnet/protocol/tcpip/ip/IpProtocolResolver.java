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
package com.slytechs.jnet.protocol.tcpip.ip;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * IP Protocol number resolver with lazy loading from properties files.
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public final class IpProtocolResolver {

    private static final String FULL_RESOURCE = "/tables/protocol/tcpip/ipv4_proto.properties";
    private static final String ABBR_RESOURCE = "/tables/protocol/tcpip/ipv4_proto_abbr.properties";
    private static final String KEY_PREFIX = "ip_protocol.";

    private static volatile Map<Integer, String> fullNames;
    private static volatile Map<Integer, String> abbrNames;

    private IpProtocolResolver() {}

    public static String resolve(int protocol) {
        Map<Integer, String> map = getFullNames();
        return map != null ? map.get(protocol) : null;
    }

    public static String resolveAbbr(int protocol) {
        Map<Integer, String> map = getAbbrNames();
        return map != null ? map.get(protocol) : null;
    }

    public static String resolveOrNumber(int protocol) {
        String name = resolve(protocol);
        return name != null ? name : String.valueOf(protocol);
    }

    public static String resolveAbbrOrNumber(int protocol) {
        String name = resolveAbbr(protocol);
        return name != null ? name : String.valueOf(protocol);
    }

    private static Map<Integer, String> getFullNames() {
        if (fullNames == null) {
            synchronized (IpProtocolResolver.class) {
                if (fullNames == null) {
                    fullNames = loadResource(FULL_RESOURCE);
                }
            }
        }
        return fullNames;
    }

    private static Map<Integer, String> getAbbrNames() {
        if (abbrNames == null) {
            synchronized (IpProtocolResolver.class) {
                if (abbrNames == null) {
                    abbrNames = loadResource(ABBR_RESOURCE);
                }
            }
        }
        return abbrNames;
    }

    private static Map<Integer, String> loadResource(String resourceName) {
        Map<Integer, String> map = new HashMap<>();

        try (InputStream is = IpProtocolResolver.class.getResourceAsStream(resourceName)) {
            if (is == null) return map;

            Properties props = new Properties();
            props.load(is);

            for (String key : props.stringPropertyNames()) {
                if (!key.startsWith(KEY_PREFIX)) continue;

                String numStr = key.substring(KEY_PREFIX.length());
                try {
                    int protocol = Integer.parseInt(numStr);
                    map.put(protocol, props.getProperty(key));
                } catch (NumberFormatException e) {
                    // Skip malformed keys
                }
            }
        } catch (IOException e) {
            // Return partial map on error
        }

        return map;
    }
}