# SDK Protocol TCP/IP

[![Java](https://img.shields.io/badge/Java-22%2B-orange.svg)](https://openjdk.java.net/projects/jdk/22/) [![Maven Central](https://img.shields.io/badge/Maven-Central-blue.svg)](https://search.maven.org/artifact/com.slytechs.sdk/sdk-protocol-tcpip) [![License](https://img.shields.io/badge/License-Apache%20v2-green.svg)](https://claude.ai/chat/LICENSE)

TCP/IP protocol pack for the Sly Technologies Network SDK.

**sdk-protocol-tcpip** provides comprehensive protocol definitions for TCP/IP stack analysis including Ethernet, IPv4/IPv6, TCP, UDP, VLAN, MPLS, IPsec, and more.

------

## Table of Contents

1. [Quick Start](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#quick-start)
2. [Protocols](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#protocols)
3. [Examples](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#examples)
4. [Protocol Details](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#protocol-details)
5. [Advanced Installation](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#advanced-installation)
6. [Documentation](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#documentation)

------

## Quick Start

### Installation (Recommended)

Use the starter which pulls all dependencies:

```xml
<dependency>
    <groupId>com.slytechs.sdk</groupId>
    <artifactId>jnetpcap-sdk</artifactId>
    <version>3.0.0</version>
</dependency>
```

The `jnetpcap-sdk` starter includes `sdk-protocol-tcpip` automatically.

### Basic Usage

```java
import com.slytechs.sdk.protocol.tcpip.ip.Ip4;
import com.slytechs.sdk.protocol.tcpip.tcp.Tcp;

// Pre-allocate headers outside hot path
Ip4 ip4 = new Ip4();
Tcp tcp = new Tcp();

pcap.dispatch(count, packet -> {
    
    // hasHeader() checks presence AND binds header
    if (packet.hasHeader(ip4)) {
        System.out.printf("IP: %s -> %s%n", ip4.src(), ip4.dst());
    }
    
    if (packet.hasHeader(tcp)) {
        System.out.printf("TCP: %d -> %d%n", tcp.srcPort(), tcp.dstPort());
    }
});
```

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

## Examples

### Ethernet and VLAN

```java
Ethernet ethernet = new Ethernet();
Vlan vlan = new Vlan();

pcap.dispatch(count, packet -> {
    
    if (packet.hasHeader(ethernet)) {
        System.out.printf("Ethernet: %s -> %s [%s]%n",
            ethernet.src(), ethernet.dst(), 
            EtherTypes.resolve(ethernet.type()));
        
        // Check for VLAN tag
        if (packet.hasHeader(vlan)) {
            System.out.printf("  VLAN ID: %d, Priority: %d%n",
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
    
    // Depth 0 = outer, Depth 1 = inner
    if (packet.hasHeader(outerVlan, 0) && packet.hasHeader(innerVlan, 1)) {
        System.out.printf("Q-in-Q: Outer=%d, Inner=%d%n",
            outerVlan.vid(), innerVlan.vid());
    }
});
```

### IPv4 with Flags

```java
Ip4 ip4 = new Ip4();

pcap.dispatch(count, packet -> {
    
    if (packet.hasHeader(ip4)) {
        System.out.printf("IPv4: %s -> %s (TTL=%d, Proto=%s)%n",
            ip4.src(), ip4.dst(), ip4.ttl(),
            IpProtocolResolver.resolve(ip4.protocol()));
        
        // Fragmentation info
        Ip4Flags flags = ip4.flags();
        if (flags.moreFragments() || ip4.fragmentOffset() > 0) {
            System.out.printf("  Fragment: DF=%b, MF=%b, Offset=%d%n",
                flags.dontFragment(), 
                flags.moreFragments(),
                ip4.fragmentOffset());
        }
    }
});
```

### TCP Options

```java
Tcp tcp = new Tcp();
TcpOptions options = new TcpOptions();

pcap.dispatch(count, packet -> {
    
    if (packet.hasHeader(tcp)) {
        System.out.printf("TCP: %d -> %d [%s] Seq=%d%n",
            tcp.srcPort(), tcp.dstPort(), 
            tcp.flags(), tcp.seq());
        
        if (tcp.hasOptions()) {
            options.bind(tcp);
            
            if (options.hasMss())
                System.out.println("  MSS: " + options.mss());
            if (options.hasWindowScale())
                System.out.println("  WScale: " + options.windowScale());
            if (options.hasTimestamps())
                System.out.printf("  TS: val=%d, ecr=%d%n",
                    options.tsVal(), options.tsEcr());
            if (options.hasSackPermitted())
                System.out.println("  SACK Permitted");
        }
    }
});
```

### IPsec

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

### MPLS Label Stack

```java
Mpls mpls = new Mpls();

pcap.dispatch(count, packet -> {
    
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

### IPv4 Fields

```java
Ip4 ip4 = new Ip4();

// Addresses
Ip4Address src = ip4.src();
Ip4Address dst = ip4.dst();

// Header fields
int version = ip4.version();
int ihl = ip4.ihl();              // In 32-bit words
int headerLen = ip4.headerLength(); // In bytes
int totalLen = ip4.totalLength();
int id = ip4.identification();
int ttl = ip4.ttl();
int protocol = ip4.protocol();
int checksum = ip4.checksum();

// Type of Service
Ip4TosFlags tos = ip4.tos();
int dscp = tos.dscp();
int ecn = tos.ecn();
```

### TCP Fields

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
boolean ackFlag = flags.ack();
boolean fin = flags.fin();
boolean rst = flags.rst();

// Window
int window = tcp.window();
int dataOffset = tcp.dataOffset();  // In 32-bit words
```

------

## Advanced Installation

### Standalone (With BOM)

For projects that don't use the starter:

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
    implementation 'com.slytechs.sdk:jnetpcap-sdk:3.0.0'
}
```

### Module Declaration

```java
module your.app {
    requires com.slytechs.sdk.protocol.tcpip;
}
```

------

## Documentation

- [GitHub Wiki](https://github.com/slytechs-repos/sdk-protocol-tcpip/wiki) - User guides
- [Javadocs](https://slytechs-repos.github.io/sdk-protocol-tcpip/) - API documentation

------

## Related Projects

| Module                                                       | Description                               |
| ------------------------------------------------------------ | ----------------------------------------- |
| [jnetpcap-sdk](https://github.com/slytechs-repos/jnetpcap-sdk) | Starter - pulls all dependencies          |
| [sdk-protocol-core](https://github.com/slytechs-repos/sdk-protocol-core) | Protocol dissection framework             |
| [sdk-protocol-web](https://github.com/slytechs-repos/sdk-protocol-web) | Web protocols (HTTP, TLS, DNS)            |
| [sdk-protocol-infra](https://github.com/slytechs-repos/sdk-protocol-infra) | Infrastructure protocols (BGP, OSPF, STP) |

------

## License

Licensed under Apache License v2.0. See [LICENSE](https://claude.ai/chat/LICENSE) for details.

------

**Sly Technologies Inc.** - High-performance network analysis solutions

Website: [www.slytechs.com](https://www.slytechs.com/)

------
