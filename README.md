// Copyright (c) 2026 Lionel Guo
// Author: Lionel Guo
// Email: lionelliguo@gmail.com

# Multi-protocol heartbeat toolkit

A lightweight C++ toolkit for experimenting with **heartbeat mechanisms, connection liveness, and timing semantics**
across multiple transport and application-layer protocols.

This project provides a unified client/server implementation to compare how heartbeat behaviors differ under:

- Plain TCP (raw)
- WebSocket
- HTTP request/response
- HTTP Server-Sent Events (SSE)

It focuses on **how heartbeats are initiated, delivered, and measured**, rather than on application business logic.

---

## Project Overview

`Multi-protocol heartbeat toolkit` allows you to run the same logical heartbeat concepts over different protocol stacks and observe:

- Client-initiated vs server-initiated heartbeats
- Bidirectional heartbeat exchanges
- Round-Trip Time (RTT) vs server-push lag
- Interaction between heartbeat traffic and normal HTTP traffic
- Threading behavior under different protocol modes

The toolkit follows two explicit timing rules:

> **Protocol field `ts` is always the sender's Unix epoch timestamp in milliseconds.**

> **Local RTT and timeout measurements use a monotonic clock and never mix clock domains.**

RTT is calculated locally by matching `seq` with the monotonic send time retained by
the initiating endpoint. SSE lag is calculated as the receiver's current epoch time
minus the server-provided `ts`; meaningful cross-host lag therefore requires clock
synchronization between the hosts.

---

## Build

### Requirements
- C++17 compatible compiler (`clang++` or `g++`)
- POSIX sockets
- `nlohmann/json` single-header library in the include path

### Build commands

Tested and verified on macOS using Apple Clang.

```bash
brew install nlohmann-json
clang++ -std=c++17 -O2 tcp-server.cpp -o server -I/opt/homebrew/include
clang++ -std=c++17 -O2 tcp-client.cpp -o client -I/opt/homebrew/include
```

---

## Execution Guide

Each protocol mode is controlled by its own client/server JSON configuration.

---

## 1. RAW mode (Plain TCP)

### Run

**Server**
```bash
./server server-config-raw.json
```

**Client**
```bash
./client client-config-raw.json
```

### Sequence Diagram

```
Client                                Server
  |--- PING seq=N ts=T0 --------------->|
  |<-- PONG seq=N ts=T1 ----------------|
  |
  |  RTT = monotonic_now() - monotonic_send_time[N]
```

---

## 2. WebSocket mode

### Run

**Server**
```bash
./server server-config-websocket.json
```

**Client**
```bash
./client client-config-websocket.json
```

### Sequence Diagram

```
Client                                Server
  |--- WS PING seq=N ts=T0 ----------->|
  |<-- WS PONG seq=N ts=T1 ------------|
  |
  |  RTT = monotonic_now() - monotonic_send_time[N]
```

---

## 3. HTTP mode

### Run

**Server**
```bash
./server server-config-http.json
```

**Client**
```bash
./client client-config-http.json
```

### Sequence Diagram

```
Client                                Server
  |--- GET /hello?seq=N --------------->|
  |<-- 200 OK --------------------------|
  |
  |--- GET /__hb?seq=K&ts=T0 ---------->|
  |<-- 200 OK (HEARTBEAT=PONG) ---------|
  |
  |  RTT = monotonic_now() - monotonic_send_time[K]
```

---

## 4. HTTP-SSE mode (Server-Sent Events)

### Run

**Server**
```bash
./server server-config-http-sse.json
```

**Client**
```bash
./client client-config-http-sse.json
```

### Sequence Diagram

```
Client                                Server
  |--- GET /__hb/sse ------------------>|
  |<-- 200 OK (text/event-stream) ------|
  |<-- data: HEARTBEAT=PONG seq=N ts=S0 |
  |
  |  lag = epoch_now() - S0
  |
  |--- GET /hello?seq=M --------------->|
  |<-- 200 OK --------------------------|
```

---

## Heartbeat Behavior Matrix

| Mode        | Transport / Channel   | Heartbeat Direction(s)           | Timing Metric | Threading Model |
|-------------|-----------------------|----------------------------------|---------------|-----------------|
| raw         | TCP payload           | client-only / server-only / bidi | RTT or lag    | Multi-threaded |
| websocket   | WebSocket frames      | client-only / server-only / bidi | RTT or lag    | Multi-threaded |
| http        | HTTP request/response | client-only                      | RTT           | Multi-threaded |
| http-sse    | HTTP SSE (push)       | server-only                      | lag           | Multi-threaded |

---

## Protocol Fields

### `seq`
Monotonically increasing sequence number used to correlate heartbeat messages.

### `ts`
Sender's Unix epoch timestamp in milliseconds, generated immediately before sending.
It is suitable for logs and cross-process correlation. RTT calculations do not use
this field; they use a local monotonic clock to remain stable if the system clock changes.

### `direction`
Defines which side initiates heartbeats: `client-only`, `server-only`, or `bidirectional`.

---
