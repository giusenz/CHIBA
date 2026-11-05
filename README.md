# ClickHouse Ingestion and Behavioural Analysis (CHIBA)

**CHIBA** is a high-throughput network telemetry daemon written in C that captures NetFlow v9 streams—either in real time from a live network interface or offline from static PCAP traces—pipelines them into ClickHouse via zero-copy `RowBinary` HTTP streaming, and performs automated dual-horizon behavioral analysis to detect **Distributed Denial-of-Service (DDoS) floods**, **horizontal network sweeps**, **fast and slow stealth port scans**, and **anomalous data exfiltration**.

> 📄 **Full Technical Documentation:** Available in [`doc/chiba_report.pdf`](doc/chiba_report.pdf) (LaTeX source: [`doc/chiba_report.tex`](doc/chiba_report.tex)).

---

## Architecture Overview

```text
+------------------------------------------+
| BOOT: chiba [-h] [-r <path>] [-i <dev>]  |
| * Read chiba.conf / ENV                  |
| * fork() & execvp()                      |
+-------------------+------------------+---+
                    |                  |
                    v                  |
+------------------------------+       |
|   CHILD PROCESS: softflowd   |       |
|   (Live capture / PCAP file) |       |
+---------------+--------------+       |
                |                      |
                | UDP Datagrams        |
                v                      v
+---------------+----------------------+-----------------------------------+
|                   PARENT PROCESS: CHIBA Daemon                           |
|                                                                          |
| +--------------------+  +--------------------+  +--------------------+   |
| |  AUXILIARY THREAD  |  | SHARED RING BUFFER |  |    MAIN THREAD     |   |
| |    (Collector)     |  |  (Circular Queue)  |  |    (Exporter)      |   |
| |                    |  |                    |  |                    |   |
| |* poll() w/ 1s      |  |* Power-of-two FIFO |  |* Temporal trigger  |   |
| |  timeout           |  |* Single-mutex sync |  |* Volumetric        |   |
| |* NetFlow v9 parser |  |* Double buffering  |  |  trigger           |   |
| +---------+----------+  +----+----------+----+  +---------+----------+   |
|           |                  ^          |                 ^          |   |
|           +------------------+          +-----------------+          |   |
|                                                                      |   |
+----------------------------------------------------------------------+---+
                                                                       |
                                                            Bulk Transfer
                                                            HTTP POST (RowBinary)
                                                                       |
                                                                       v
+--------------------------------------------------------------------------+
|                            CLICKHOUSE SERVER                             |
|    ingest_flows (MergeTree) -> Materialized Views (*State) -> Views      |
+--------------------------------------------------------------------------+
                                                                       |
                                                                       v
+--------------------------------------------------------------------------+
|                            GRAFANA DASHBOARD                             |
|                  (Telemetry Visualization & Alerting)                    |
+--------------------------------------------------------------------------+
```

### Core Design Highlights

1. **Process Management & Privilege Drop (`softflowd`):**
   - Spawns `softflowd` as a background child process (`fork()` / `execvp()`), exporting NetFlow v9 datagrams over local UDP (`127.0.0.1:9995`), and drops parent daemon privileges to `nobody`.
   - Adapts flow timeouts automatically between **Live Mode** (balanced active/inactive timeouts) and **Offline PCAP Mode** (1s eviction for rapid dump ingestion aligned to current time).
2. **Stateful NetFlow v9 Parser & Unified Dual-Stack Addressing:**
   - Dynamically caches `Template FlowSet` definitions in static memory without heap allocations and decodes variable-length `Data FlowSet` fields.
   - Unifies IPv4 and IPv6 into a single 128-bit address space (`IPv4-mapped` `::ffff:a.b.c.d` and native 128-bit IPv6) inside a `__attribute__((packed))` `flow_data` structure matching ClickHouse's binary layout.
3. **Lock-Minimized Producer-Consumer & Double Buffering:**
   - Decouples UDP reception from HTTP I/O using a power-of-two ring buffer (`32768` entries) with bitwise index masking (`& (size - 1)`), batch extraction, and double buffering—avoiding condition variables and context-switch overhead.
   - Zero heap allocations (`malloc`/`free`) occur during steady-state monitoring; all resources follow a strict LIFO teardown verified with **Valgrind**.
4. **Zero-Copy `RowBinary` Ingestion & Continuous Pre-Aggregation:**
   - Streams linearized batches (`16384` records or every `5000 ms`) to ClickHouse over persistent HTTP connections via `libcurl-easy` in `RowBinary` format.
   - Write-time ClickHouse Materialized Views (`AggregatingMergeTree`) discretize traffic into 1-minute buckets (`TIME_BUCKET`) and persist combinatory states (`uniqState` HyperLogLog, `minState`, `maxState`, `sumState`) across three dimensions: source hosts (`host_src_mv`), target hosts (`host_dst_mv`), and L4 services (`service_mv`).

---

## Behavioral Anomaly Detection

Detection logic is decoupled from the C daemon and executed via ClickHouse logical views (`*Merge`) and Grafana queries across two time horizons:

### 1. Real-Time Detection (1-Minute Window)

| Threat Category | Direction | Trigger Condition (per 1m bucket) | `WARNING` | `CRITICAL` |
| :--- | :--- | :--- | :--- | :--- |
| **Distributed Flood / DDoS** | Inbound (`host_dst_view`) | Converging unique sources onto a single target | `UNIQUE_SRCADDR >= 50` | `>= 200` |
| **Horizontal Network Sweep** | Outbound (`host_src_view`) | Distinct destination IPs contacted by a local host | `UNIQUE_DSTADDR >= 50` | `>= 200` |
| **Vertical Port Scan** | Outbound (`host_src_view`) | Distinct destination ports probed by a local host | `UNIQUE_DSTPORT >= 20` | `>= 100` |
| **Excessive Outbound Volume** | Outbound (`host_src_view`) | Cumulative egress byte volume per host | `>= 20 MiB/min` | `>= 50 MiB/min` |

### 2. Extended-Horizon Detection (24-Hour Sliding Window)

Low-and-slow reconnaissance tools (e.g., `nmap -T1` or `--scan-delay`) that stay below per-minute thresholds (`UNIQUE_DSTPORT < 20`) are correlated by `slow_scanners_view` over a rolling 24-hour window:
- **Cardinality Threshold:** `UNIQUE_DSTPORT >= 50` or `UNIQUE_DSTADDR >= 100`
- **Temporal Persistence:** `ACTIVE_SPAN_MINUTES >= 30` (filtering out short transient bursts)
- **Normalized Probing Rate:** Exposes `PORTS_PER_HOUR` to quantify stealth scan velocity.

---

## Quick Start

### 1. Prerequisites
Ensure the following components are installed on your Linux system:
- **Build & Capture:** `gcc`, `make`, `libcurl` development headers (`libcurl4-openssl-dev` / `libcurl-devel`), and `softflowd`
- **Database & Visualization:** `clickhouse-server`, `clickhouse-client`, and `grafana-server` (with the `grafana-clickhouse-datasource` plugin)
- **Optional (Testing & Documentation):** `nmap`, `hping3`, `netcat`, `tcpreplay`, and `pdflatex`

### 2. Build & Database Provisioning

```bash
# Compile the daemon (outputs ./bin/chiba)
make

# Initialize ClickHouse database, tables, and materialized/logical views
make db-init

# Reset database (drops and re-initializes the 'chiba' database after confirmation)
make db-reset

# Compile the LaTeX technical report in doc/chiba_report.pdf
make doc
```

### 3. Configuration & Execution

ClickHouse connection settings are read from [`chiba.conf`](chiba.conf) and can be overridden via environment variables (`CH_HOST`, `CH_DB`, `CH_TABLE`):

```ini
CH_HOST=http://127.0.0.1:8123
CH_DB=chiba
CH_TABLE=ingest_flows
```

Run CHIBA in either live interface mode or offline PCAP mode:

```bash
# Live capture on a network interface (requires root privileges for raw sockets)
sudo ./bin/chiba -i <interface>

# Offline analysis of a static PCAP trace
./bin/chiba -r ./pcap/DHCPv6.pcap
```

### 4. Grafana Setup
1. Open Grafana at `http://localhost:3000` (default login: `admin` / `admin`).
2. Add a **ClickHouse** data source pointing to `127.0.0.1:8123` with default database `chiba`.
3. Import [`grafana/chiba_dashboard.json`](grafana/chiba_dashboard.json).

---

## Repository Structure

```text
.
├── chiba.conf                   # Default ClickHouse HTTP endpoint configuration
├── Makefile                     # Build, database provisioning, and documentation targets
├── doc/
│   ├── chiba_report.tex         # Full English technical report (LaTeX source)
│   └── chiba_report.pdf         # Compiled technical report (PDF)
├── grafana/
│   └── chiba_dashboard.json     # Grafana dashboard definition
├── img/                         # Dashboard telemetry & alerting screenshots
├── include/                     # C header files
├── pcap/                        # Sample PCAP traces for offline validation
├── sql/                         # ClickHouse DDL scripts (00_init.sql -> 05_views.sql)
└── src/                         # C daemon source files
```

---

## Author

**Giuseppe Nozza**

---

## Acknowledgments

Originally developed as a project for the *Network Management* course (A.Y. 2025/2026) taught by [Prof. Luca Deri](https://luca.ntop.org/).
