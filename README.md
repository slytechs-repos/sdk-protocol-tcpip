# Protocol TCP/IP Module

A modular TCP/IP protocol analysis pack for the Protocol Network Platform, extending the core `protocol-sdk` with comprehensive TCP/IP protocol support.

## Overview

The `protocol-tcpip` module is an extensible protocol pack designed to integrate seamlessly with the [Protocol Network Platform](https://github.com/slytechs/protocol-sdk). It provides robust support for analyzing and processing TCP/IP protocols, including IPv4, IPv6, TCP, UDP, and related protocols. This module is built to leverage the high-performance capabilities of the `protocol-sdk` and `jnetpcap-sdk` for real-time packet processing and analysis.

## Key Features

- **Comprehensive TCP/IP Support**: Full parsing and analysis for IPv4, IPv6, TCP, UDP, ICMP, and related protocols.
- **High Performance**: Optimized for low-latency packet processing using the `jnetpcap-sdk`.
- **Extensible Protocol Parsing**: Modular design allows easy integration of additional TCP/IP-related protocols.
- **Real-Time Analytics**: Compatible with the `intelligence-sdk` for real-time TCP/IP traffic insights.
- **Flexible Configuration**: Supports custom protocol parsing and formatting through the `protocol-sdk` pipeline.
- **Cross-Protocol Integration**: Works seamlessly with other protocol packs for layered analysis (e.g., HTTP, DNS).

## Architecture

The `protocol-tcpip` module is built as an extension of the `protocol-sdk`, adhering to its modular architecture:

- **Packet Capture**: Leverages `jnetpcap-sdk` for high-performance packet capture.
- **Protocol Parsing**: Implements TCP/IP-specific parsers within the `protocol-sdk` framework.
- **Analytics Integration**: Interfaces with the `intelligence-sdk` for advanced analytics and visualization.
- **Extensibility**: Supports custom protocol definitions and extensions through protocol packs.

## Quick Start

To use the `protocol-tcpip` module, ensure you have the `protocol-sdk` and `jnetpcap-sdk` installed. Below is a sample code snippet demonstrating how to capture and analyze TCP/IP packets:

```java
import com.slytechs.jnetpcap.NetPcap;
import com.slytechs.protocol.pack.tcpip.*;

try (NetPcap pcap = NetPcap.live()) {
    // Configure protocol processing with TCP/IP pack
    pcap.setPacketFormatter(new TcpIpPacketFormat());
    pcap.activate();

    // Process packets and extract TCP/IP headers
    pcap.loop(100, (String user, Packet packet) -> {
        if (packet.hasHeader(Ip4.ID)) {
            Ip4 ip4 = packet.getHeader(new Ip4());
            System.out.println("IPv4 Source: " + ip4.source());
            System.out.println("IPv4 Destination: " + ip4.destination());
        }
        if (packet.hasHeader(Tcp.ID)) {
            Tcp tcp = packet.getHeader(new Tcp());
            System.out.println("TCP Source Port: " + tcp.source());
            System.out.println("TCP Destination Port: " + tcp.destination());
        }
    }, null);
}
```

## Installation

1. Add the `protocol-tcpip` module as a dependency in your project:
   ```xml
   <dependency>
       <groupId>com.slytechs</groupId>
       <artifactId>protocol-tcpip</artifactId>
       <version>1.0.0</version>
   </dependency>
   ```

2. Ensure the `protocol-sdk` and `jnetpcap-sdk` dependencies are also included:
   ```xml
   <dependency>
       <groupId>com.slytechs</groupId>
       <artifactId>protocol-sdk</artifactId>
       <version>1.0.0</version>
   </dependency>
   <dependency>
       <groupId>com.slytechs</groupId>
       <artifactId>jnetpcap-sdk</artifactId>
       <version>1.0.0</version>
   </dependency>
   ```

3. Configure your project to include the necessary native libraries for `jnetpcap-sdk`.

## Documentation

- [TCP/IP Protocol API Reference](docs/protocol-tcpip-api.md)
- [Protocol Pack Guide](https://www.slytechs.com/docs/protocol-packs.md)
- [Analytics Integration](https://www.slytechs.com/docs/analytics.md)
- [Examples](examples/)

## License

The `protocol-tcpip` module is available under a commercial license, with the core `protocol-sdk` available under the Apache 2.0 license. Contact [Sly Technologies](https://www.slytechs.com) for licensing details.

## Support

- [Documentation](https://www.slytechs.com/docs)
- [Commercial Support](https://www.slytechs.com/support)
- [Training](https://www.slytechs.com/training)

