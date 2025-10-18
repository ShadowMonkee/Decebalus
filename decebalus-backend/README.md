
# Decebalus

> A network reconnaissance and security assessment tool built in Rust, inspired by the legendary [Bjorn](https://github.com/infinition/Bjorn) project. Name is inspired by the legendary Dacian king.

## Overview

Decebalus is a network scanning and vulnerability assessment tool designed to run on a Raspberry Pi Zero 2 W. It scans your network to discover hosts with open ports, detects services running on those ports, and flags potential vulnerabilities. It can provide real-time status updates on a physical HAT display where we can keep track of important information. It also has a web interface to control its functionalities and see the results of the background processes.

Think of it as a lightweight, portable alternative to enterprise security tools like Nessus, but built for learning, experimentation, and deep understanding of how network reconnaissance and exploitation works.

## Project Purpose

This project exists for three main reasons:

### 1. **Learn Rust in Depth**

For me personally Decebalus is a vehicle for mastering Rust and learning its quirks:
- Ownership and borrowing system
- Async/await with Tokio
- Error handling with `Result` and `Option`
- Systems programming concepts (sockets, threads, memory management)
- Building production-grade web services with Axum
- etc...
I had been looking for a practical way to learn rust. I learn best when applying the knowledge in the real world, so this is the perfect chance for me to get my hands dirty and add a new tool to my belt.
### 2. **Understand Offensive Cyber Security**

By building some of the reconnaissance tools myself instead of relying on existing tools, I'm learning:
- How network scanning actually works under the hood
- Host discovery techniques (ARP, ICMP, TCP)
- Port scanning methodologies
- Service fingerprinting and banner grabbing
- Vulnerability identification and risk assessment
- How attackers map networks and identify targets
### 3. **Curiosity-Driven Learning**

This is a sandbox project to explore:

- What's actually possible in offensive security
- How these techniques fit together in a real workflow
- The difference between theory and practical implementation
- Building tools from scratch rather than just using existing ones
- Having fun working on real-life applications

## What Decebalus Does

### Current Capabilities

- **Network Discovery**: Identify alive hosts on your network
- **Port Scanning**: Find open ports on discovered hosts
- **Service Detection**: Identify services and grab banners
- **Job Management**: Queue, track, and execute scans as background jobs
- **Real-time Updates**: WebSocket support for live progress tracking
- **REST API**: Full API for programmatic control
- **Persistent Storage**: SQLite database for scan results and history

### Planned Capabilities

- Full Nmap integration with NSE scripts (fully implementing nmap from scratch would take months and not even come close to the real thing)
- OS fingerprinting and device classification
- CVE matching and vulnerability assessment
- Brute force attacks (SSH, FTP, SMB, RDP)
- File exfiltration
- E-Paper display for standalone monitoring
- Web dashboard for visualization
- Scan scheduling and automation
- Historical tracking and change detection

## Architecture

Decebalus is built with a modular architecture designed for clarity and extensibility:

```
src/
├── main.rs           # Entry point and routing
├── api/              # HTTP endpoints
├── services/         # Business logic (scanning, job execution)
├── models/           # Data structures
├── db/               # Database layer
└── state.rs          # Shared application state
```

**Tech Stack:**

- **Web Framework**: Axum
- **Async Runtime**: Tokio
- **Database**: SQLite with SQLx
- **Protocol**: WebSocket for real-time updates
- **Frontend WebApp**: Svelte for a minimal footprint

## Why Rust?

Rust is the ideal language for this project because:

- **Safety**: Memory safety without garbage collection is critical for security tools
- **Performance**: Network scanning is I/O-bound but benefits from efficient async handling
- **Concurrency**: Tokio makes parallel scanning straightforward
- **Reliability**: The compiler catches many bugs before runtime
- **Learning Curve**: Challenging enough to be educational, powerful enough to build real tools

## Getting Started

### Prerequisites

- Rust 1.75+
- SQLite
- Linux/macOS/WSL (for network access)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/decebalus.git
cd decebalus

# Fetch dependencies to install sqlx command
cargo fetch

# Initialize database
mkdir -p data
cargo sqlx database create
cargo sqlx migrate run

# Run the application
cargo run
```

The server will start on `http://0.0.0.0:8080`

### Basic Usage

```bash
# Create a network discovery job
curl -X POST http://localhost:8080/api/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "discovery"}'

# List all jobs
curl http://localhost:8080/api/jobs

# List discovered hosts
curl http://localhost:8080/api/hosts

# Connect to WebSocket for real-time updates
websocat ws://localhost:8080/ws
```

## Learning Objectives

Through building Decebalus, I'm developing expertise in:

### Rust

- Systems-level programming
- Async Rust patterns
- Web framework development
- Database integration
- Error handling and custom types

### Cybersecurity

- TCP/IP networking fundamentals
- Host discovery and enumeration
- Port scanning techniques
- Service identification
- Vulnerability assessment
- Attack surface mapping

### Software Engineering

- Modular architecture design
- API design and RESTful principles
- Real-time data streaming
- Concurrent task management
- Testing and benchmarking

## Ethical Considerations

This tool is designed for:

- ✅ Authorized security testing
- ✅ Personal network monitoring
- ✅ Educational purposes
- ✅ Learning and experimentation

This tool should **NOT** be used for:

- ❌ Unauthorized network scanning
- ❌ Attacking systems you don't own
- ❌ Illegal activities

Always ensure you have explicit permission before scanning any network.

## Project Status

**Current Phase**: Foundation & Core Services

- [x] API structure and routing
- [x] Database integration (SQLite)
- [x] Job management system
- [x] Basic network discovery
- [x] WebSocket support
- [ ] Enhanced port scanning
- [ ] Service detection
- [ ] Vulnerability matching
- [ ] Web dashboard
- [ ] E-Paper display integration
- [ ] Attack modules

## Roadmap

### Phase 1 (Current)

Build the scanning foundation with proper network utilities, enhanced host discovery, parallel port scanning, and service detection.

### Phase 2 (Next)

Implement vulnerability assessment, OS fingerprinting, and Nmap integration.

### Phase 3 (Future)

Add offensive capabilities (brute force, exfiltration) and advanced features (scheduling, reporting, visualization).

### Phase 4 (Ultimate)

Full Raspberry Pi integration with e-Paper display, autonomous operation, and production-ready reliability.

## Contributing

This is a personal learning project, but feedback and discussions are welcome! If you're interested in:

- Rust best practices
- Network security techniques
- System design advice

Feel free to open issues or reach out.

## Resources & Inspiration

- [Bjorn](https://github.com/infinition/Bjorn) - The original inspiration
- [The Rust Book](https://doc.rust-lang.org/book/)
- [Tokio Documentation](https://tokio.rs/)
- [Network Scanning with Nmap](https://nmap.org/book/)

## License

Apache License Version 2.0 - See LICENSE file for details

## Author

ShadowMonkee

---

	**Remember what Iron Man said in The Justice League**: With great power comes great responsibility. Use this tool ethically and **legally**.