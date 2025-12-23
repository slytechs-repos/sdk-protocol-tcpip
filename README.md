# SDK Protocol TCP/IP

[![Java](https://img.shields.io/badge/Java-22%2B-orange.svg)](https://openjdk.java.net/projects/jdk/22/) [![Maven Central](https://img.shields.io/badge/Maven-Central-blue.svg)](https://search.maven.org/artifact/com.slytechs.sdk/sdk-protocol-tcpip) [![License](https://img.shields.io/badge/License-Apache%20v2-green.svg)](https://claude.ai/chat/LICENSE)

TCP/IP protocol pack for the Sly Technologies Network SDK.

**sdk-protocol-tcpip** provides comprehensive protocol definitions for TCP/IP stack analysis including Ethernet, IPv4/IPv6, TCP, UDP, VLAN, MPLS, IPsec, and more.

------

## Table of Contents

1. [Overview](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#overview)
2. [Protocols](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#protocols)
3. [Quick Start](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#quick-start)
4. [Examples](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#examples)
5. [Protocol Details](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#protocol-details)
6. [Installation](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#installation)
7. [Documentation](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#documentation)

------

## Overview

The sdk-protocol-tcpip module provides:

- **Layer 2** - Ethernet, 802.3, VLAN (802.1Q), OUI resolution
- **Layer 3** - IPv4, IPv6, MPLS, IPsec (AH, ESP)
- **Layer 4** - TCP (with options), UDP
- **Extensions** - IPv6 extension headers, TCP options, IP options

All protocols follow the zero-allocation pattern for high-performance packet processing.

------

## Protocols

### Layer 2 - Data Link

| Protocol    | Class               | Description               |
| ----------- | ------------------- | ------------------------- |
| Ethernet II | `Ethernet`          | Standard Ethernet framing |
| 802.3       | `Eth8023Extensions` | IEEE 802.3 extensions     |
| VLAN        | `Vlan`              | 802.1Q VLAN tagging       |

### Layer 3 - Network

| Protocol  | Class      | Description                    |
| --------- | ---------- | ------------------------------ |
| IPv4      | `Ip4`      | Internet Protocol v4           |
| IPv6      | `Ip6`      | Internet Protocol v6           |
| MPLS      | `Mpls`     | Multi-Protocol Label Switching |
| IPsec AH  | `IpsecAh`  | Authentication Header          |
| IPsec ESP | `IpsecEsp` | Encapsulating Security Payload |

### Layer 4 - Transport

| Protocol | Class | Description                   |
| -------- | ----- | ----------------------------- |
| TCP      | `Tcp` | Transmission Control Protocol |
| UDP      | `Udp` | User Datagram Protocol        |

### Supporting Classes

| Class                | Description                                      |
| -------------------- | ------------------------------------------------ |
| `Ip4Options`         | IPv4 option parsing                              |
| `Ip4Flags`           | IPv4 flags (DF, MF, etc.)                        |
| `Ip6Extensions`      | IPv6 extension header chain                      |
| `TcpOptions`         | TCP option parsing (MSS, SACK, Timestamps, etc.) |
| `EtherTypes`         | EtherType constants and lookup                   |
| `OuiResolver`        | MAC address vendor resolution                    |
| `IpProtocolResolver` | IP protocol number lookup                        |

------

## Quick Start

### Using jnetpcap-sdk (Recommended)

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.slytechs.sdk</groupId>
            <artifactId>sdk-bom</artifactId>
            <version>3.0.0</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependencies>
    <!-- Pulls all dependencies including sdk-protocol-tcpip -->
    <dependency>
        <groupId>com.slytechs.sdk</groupId>
        <artifactId>jnetpcap-sdk</artifactId>
    </dependency>
</dependencies>
```

### Standalone Protocol Pack

```xml
<dependency>
    <groupId>com.slytechs.sdk</groupId>
    <artifactId>sdk-protocol-tcpip</artifactId>
</dependency>
```

### Module Declaration

```java
module your.module {
    requires com.slytechs.jnet.protocol.tcpip;
}
```

------

## Examples

### Basic Packet Processing

```java
void main() throws PcapException {
    // Pre-allocate headers ONCE outside hot path
    Ethernet ethernet = new Ethernet();
    Ip4 ip4 = new Ip4();
    Ip6 ip6 = new Ip6();
    Tcp tcp = new Tcp();
    Udp udp = new Udp();
    
    try (var pcap = NetPcap.openOffline("capture.pcap")) {
        
        pcap.dispatch(Pcap.LOOP_INFINITE, packet -> {
            
            // hasHeader() checks presence AND binds header
            if (packet.hasHeader(ethernet)) {
                System.out.printf("Ethernet: %s -> %s [%s]%n",
                    ethernet.src(), ethernet.dst(), 
                    EtherTypes.resolve(ethernet.type()));
            }
            
            if (packet.hasHeader(ip4)) {
                System.out.printf("IPv4: %s -> %s (TTL=%d, Proto=%s)%n",
                    ip4.src(), ip4.dst(), ip4.ttl(),
                    IpProtocolResolver.resolve(ip4.protocol()));
            }
            
            if (packet.hasHeader(ip6)) {
                System.out.printf("IPv6: %s -> %s (Hop=%d)%n",
                    ip6.src(), ip6.dst(), ip6.hopLimit());
            }
            
            if (packet.hasHeader(tcp)) {
                System.out.printf("TCP: %d -> %d [%s] Seq=%d%n",
                    tcp.srcPort(), tcp.dstPort(), 
                    tcp.flags(), tcp.seq());
            }
            
            if (packet.hasHeader(udp)) {
                System.out.printf("UDP: %d -> %d Len=%d%n",
                    udp.srcPort(), udp.dstPort(), udp.length());
            }
        });
    }
}
```

### VLAN Processing

```java
Ethernet ethernet = new Ethernet();
Vlan vlan = new Vlan();

pcap.dispatch(count, packet -> {
    
    if (packet.hasHeader(ethernet)) {
        // Check for VLAN tag
        if (packet.hasHeader(vlan)) {
            System.out.printf("VLAN ID: %d, Priority: %d%n",
                vlan.vid(), vlan.priority());
        }
    }
});
```

### Q-in-Q (Stacked VLANs)

```java
Vlan outerVlan = new Vlan();
Vlan innerVlan = new Vlan();

pcap.dispatch(count, packet -> {
    
    // Check for Q-in-Q (double VLAN tagging)
    if (packet.hasHeader(outerVlan, 0) && packet.hasHeader(innerVlan, 1)) {
        System.out.printf("Q-in-Q: Outer=%d, Inner=%d%n",
            outerVlan.vid(), innerVlan.vid());
    }
});
```

### TCP Options

```java
Tcp tcp = new Tcp();
TcpOptions options = new TcpOptions();

pcap.dispatch(count, packet -> {
    
    if (packet.hasHeader(tcp)) {
        // Access TCP options
        if (tcp.hasOptions()) {
            options.bind(tcp);
            
            if (options.hasMss()) {
                System.out.println("MSS: " + options.mss());
            }
            if (options.hasWindowScale()) {
                System.out.println("Window Scale: " + options.windowScale());
            }
            if (options.hasTimestamps()) {
                System.out.printf("Timestamps: TSval=%d, TSecr=%d%n",
                    options.tsVal(), options.tsEcr());
            }
            if (options.hasSackPermitted()) {
                System.out.println("SACK Permitted");
            }
        }
    }
});
```

### IPv4 Flags and Options

```java
Ip4 ip4 = new Ip4();
Ip4Options options = new Ip4Options();

pcap.dispatch(count, packet -> {
    
    if (packet.hasHeader(ip4)) {
        // Check fragmentation flags
        Ip4Flags flags = ip4.flags();
        System.out.printf("DF=%b, MF=%b, Offset=%d%n",
            flags.dontFragment(), 
            flags.moreFragments(),
            ip4.fragmentOffset());
        
        // Check for IP options
        if (ip4.hasOptions()) {
            options.bind(ip4);
            // Process options...
        }
    }
});
```

### IPsec Processing

```java
Ip4 ip4 = new Ip4();
IpsecAh ah = new IpsecAh();
IpsecEsp esp = new IpsecEsp();

pcap.dispatch(count, packet -> {
    
    if (packet.hasHeader(ip4)) {
        
        if (packet.hasHeader(ah)) {
            System.out.printf("IPsec AH: SPI=0x%08X, Seq=%d%n",
                ah.spi(), ah.sequence());
        }
        
        if (packet.hasHeader(esp)) {
            System.out.printf("IPsec ESP: SPI=0x%08X, Seq=%d%n",
                esp.spi(), esp.sequence());
        }
    }
});
```

### MPLS Processing

```java
Mpls mpls = new Mpls();

pcap.dispatch(count, packet -> {
    
    // Process MPLS label stack
    int depth = 0;
    while (packet.hasHeader(mpls, depth)) {
        System.out.printf("MPLS[%d]: Label=%d, TC=%d, S=%d, TTL=%d%n",
            depth, mpls.label(), mpls.tc(), 
            mpls.bottomOfStack(), mpls.ttl());
        depth++;
    }
});
```

------

## Protocol Details

### Ethernet

```java
Ethernet eth = new Ethernet();

// MAC addresses
MacAddress src = eth.src();
MacAddress dst = eth.dst();

// EtherType
int type = eth.type();
String typeName = EtherTypes.resolve(type);

// Vendor lookup
String vendor = OuiResolver.resolve(src);
```

### IPv4

```java
Ip4 ip4 = new Ip4();

// Addresses
Ip4Address src = ip4.src();
Ip4Address dst = ip4.dst();

// Header fields
int version = ip4.version();
int ihl = ip4.ihl();           // Header length in 32-bit words
int headerLen = ip4.headerLength();  // In bytes
int totalLen = ip4.totalLength();
int id = ip4.identification();
int ttl = ip4.ttl();
int protocol = ip4.protocol();
int checksum = ip4.checksum();

// Fragmentation
int offset = ip4.fragmentOffset();
boolean df = ip4.flags().dontFragment();
boolean mf = ip4.flags().moreFragments();

// Type of Service
Ip4TosFlags tos = ip4.tos();
int dscp = tos.dscp();
int ecn = tos.ecn();
```

### IPv6

```java
Ip6 ip6 = new Ip6();

// Addresses  
Ip6Address src = ip6.src();
Ip6Address dst = ip6.dst();

// Header fields
int version = ip6.version();
int trafficClass = ip6.trafficClass();
int flowLabel = ip6.flowLabel();
int payloadLength = ip6.payloadLength();
int nextHeader = ip6.nextHeader();
int hopLimit = ip6.hopLimit();

// Extension headers
if (ip6.hasExtensions()) {
    Ip6Extensions ext = ip6.extensions();
    // Process extension chain...
}
```

### TCP

```java
Tcp tcp = new Tcp();

// Ports
int srcPort = tcp.srcPort();
int dstPort = tcp.dstPort();

// Sequence numbers
long seq = tcp.seq();
long ack = tcp.ack();

// Flags
TcpFlags flags = tcp.flags();
boolean syn = flags.syn();
boolean ack = flags.ack();
boolean fin = flags.fin();
boolean rst = flags.rst();
boolean psh = flags.psh();
boolean urg = flags.urg();

// Window and checksum
int window = tcp.window();
int checksum = tcp.checksum();
int urgentPointer = tcp.urgentPointer();

// Data offset (header length)
int dataOffset = tcp.dataOffset();  // In 32-bit words
int headerLen = tcp.headerLength(); // In bytes
```

### UDP

```java
Udp udp = new Udp();

int srcPort = udp.srcPort();
int dstPort = udp.dstPort();
int length = udp.length();
int checksum = udp.checksum();
```

------

## Installation

### With SDK BOM (Recommended)

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.slytechs.sdk</groupId>
            <artifactId>sdk-bom</artifactId>
            <version>3.0.0</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependencies>
    <dependency>
        <groupId>com.slytechs.sdk</groupId>
        <artifactId>sdk-protocol-tcpip</artifactId>
    </dependency>
</dependencies>
```

### Gradle

```groovy
dependencies {
    implementation platform('com.slytechs.sdk:sdk-bom:3.0.0')
    implementation 'com.slytechs.sdk:sdk-protocol-tcpip'
}
```

------

## Documentation

- [GitHub Wiki](https://github.com/slytechs-repos/sdk-protocol-tcpip/wiki) - User guides
- [Javadocs](https://slytechs-repos.github.io/sdk-protocol-tcpip/) - API documentation
- [SDK BOM](https://github.com/slytechs-repos/sdk-bom) - Version management

------

## Related Projects

| Module                                                       | Description                               |
| ------------------------------------------------------------ | ----------------------------------------- |
| [sdk-protocol-core](https://github.com/slytechs-repos/sdk-protocol-core) | Protocol dissection framework             |
| [sdk-protocol-web](https://github.com/slytechs-repos/sdk-protocol-web) | Web protocols (HTTP, TLS, DNS)            |
| [sdk-protocol-infra](https://github.com/slytechs-repos/sdk-protocol-infra) | Infrastructure protocols (BGP, OSPF, STP) |
| [jnetpcap-api](https://github.com/slytechs-repos/jnetpcap-api) | Packet capture API                        |
| [jnetpcap-sdk](https://github.com/slytechs-repos/jnetpcap-sdk) | Complete SDK starter                      |

------

## Requirements

- **Java 22+** - Required for Panama FFM
- **sdk-protocol-core** - Dissection framework (transitive)
- **sdk-common** - Core utilities (transitive)

------

## License

Licensed under Apache License v2.0. See [LICENSE](https://claude.ai/chat/LICENSE) for details.

------

**Sly Technologies Inc.** - High-performance network analysis solutions

Website: [www.slytechs.com](https://www.slytechs.com/)

------
