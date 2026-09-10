// Copyright (c) 2026 Lionel Guo
// Author: Lionel Guo
// Email: lionelliguo@gmail.com

# multi-protocol-heartbeat-toolkit

[English](README.md) | 简体中文

一个轻量级 C++ 工具包，用于在多种传输层和应用层协议下测试和研究 **心跳机制、连接存活性以及时间测量语义**。

本项目提供统一的客户端/服务器端实现，可用于对比不同协议下的心跳行为，包括：

- 原生 TCP（raw）
- WebSocket
- HTTP 请求/响应
- HTTP Server-Sent Events（SSE）

本项目重点关注 **心跳如何发起、传输和测量**，而不是具体的应用业务逻辑。

---

## 项目概述

`multi-protocol-heartbeat-toolkit` 允许你在不同协议栈下运行相同的心跳逻辑，并观察以下行为：

- 客户端发起心跳与服务器端发起心跳的差异
- 双向心跳交互
- 往返时延（Round-Trip Time，RTT）与服务器推送延迟（lag）的差异
- 心跳流量与普通 HTTP 流量之间的交互
- 不同协议模式下的线程行为

该工具包采用两条明确的时间规则：

> **协议字段 `ts` 始终表示发送方的 Unix Epoch 时间戳，单位为毫秒。**

> **本地 RTT 与超时测量使用单调时钟，不混用不同时钟域。**

RTT 由发起端通过 `seq` 匹配本地保存的单调时钟发送时刻来计算。SSE lag
使用接收端当前 Epoch 时间减去服务器提供的 `ts`；因此跨主机测量 lag 时，
两台主机需要保持时钟同步。

---

## 编译

### 环境要求

- 支持 C++17 的编译器（`clang++` 或 `g++`）
- POSIX sockets
- include 路径中包含 `nlohmann/json` 单头文件库

### 编译命令

已在 macOS 上使用 Apple Clang 完成测试和验证。

```bash
brew install nlohmann-json
clang++ -std=c++17 -O2 tcp-server.cpp -o server -I/opt/homebrew/include
clang++ -std=c++17 -O2 tcp-client.cpp -o client -I/opt/homebrew/include
```

---

## 运行指南

每一种协议模式均通过各自独立的客户端/服务器端 JSON 配置文件进行控制。

---

## 1. RAW 模式（原生 TCP）

### 运行

**服务器端**

```bash
./server server-config-raw.json
```

**客户端**

```bash
./client client-config-raw.json
```

### 时序图

```
Client                                Server
  |--- PING seq=N ts=T0 --------------->|
  |<-- PONG seq=N ts=T1 ----------------|
  |
  |  RTT = monotonic_now() - monotonic_send_time[N]
```

---

## 2. WebSocket 模式

### 运行

**服务器端**

```bash
./server server-config-websocket.json
```

**客户端**

```bash
./client client-config-websocket.json
```

### 时序图

```
Client                                Server
  |--- WS PING seq=N ts=T0 ----------->|
  |<-- WS PONG seq=N ts=T1 ------------|
  |
  |  RTT = monotonic_now() - monotonic_send_time[N]
```

---

## 3. HTTP 模式

### 运行

**服务器端**

```bash
./server server-config-http.json
```

**客户端**

```bash
./client client-config-http.json
```

### 时序图

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

## 4. HTTP-SSE 模式（Server-Sent Events）

### 运行

**服务器端**

```bash
./server server-config-http-sse.json
```

**客户端**

```bash
./client client-config-http-sse.json
```

### 时序图

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

## 心跳行为对照表

| 模式 | 传输方式 / 通道 | 心跳方向 | 时间指标 | 线程模型 |
|------|-----------------|----------|----------|----------|
| raw | TCP payload | client-only / server-only / bidi | RTT 或 lag | 多线程 |
| websocket | WebSocket frames | client-only / server-only / bidi | RTT 或 lag | 多线程 |
| http | HTTP request/response | client-only | RTT | 多线程 |
| http-sse | HTTP SSE（push） | server-only | lag | 多线程 |

---

## 协议字段

### `seq`

单调递增的序列号，用于关联和匹配对应的心跳消息。

### `ts`

发送方在发送前生成的 Unix Epoch 毫秒时间戳，可用于日志记录和跨进程关联。
RTT 计算不使用该字段，而使用本地单调时钟，避免系统时间调整影响测量结果。

### `direction`

定义由哪一端发起心跳，可选值包括：`client-only`、`server-only` 或 `bidirectional`。

---
