// Copyright (c) 2026 Lionel Guo
// Author: Lionel Guo
// Email: lionelliguo@gmail.com

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <array>
#include <vector>
#include <random>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>

#include <nlohmann/json.hpp>

using json = nlohmann::json;



// Return cfg[key] if it is an object, otherwise return empty object.
static json get_obj_or_empty(const json& cfg, const std::string& key) {
    if (cfg.contains(key) && cfg.at(key).is_object()) return cfg.at(key);
    return json::object();
}
// -------------------- WebSocket (minimal RFC6455) helpers --------------------
// NOTE: This implementation is intentionally minimal:
// - Text frames only (opcode=0x1)
// - No compression / extensions
// - Supports payload lengths up to 65535
// - Client frames are masked; server frames are unmasked
// This is sufficient for Heartbeat + demo RAW messages.

static bool send_all_counted(int fd, const std::string& data, long long& bytes_out) {
    // Minimal helper for WS code paths: send all bytes and accumulate counters.
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = send(fd, data.data() + off, data.size() - off, 0);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
        bytes_out += static_cast<long long>(n);
    }
    return true;
}
static const char* WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

static std::string ws_trim(const std::string& s) {
    size_t b = 0;
    while (b < s.size() && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) b++;
    size_t e = s.size();
    while (e > b && (s[e-1] == ' ' || s[e-1] == '\t' || s[e-1] == '\r' || s[e-1] == '\n')) e--;
    return s.substr(b, e - b);
}

static std::string ws_sha1_base64(const std::string& input) {
    // Tiny SHA1 + Base64 using OpenSSL would be easier, but we keep it dependency-free.
    // Implement SHA1 directly (minimal, sufficient for handshake).
    struct Sha1 {
        uint32_t h0=0x67452301u, h1=0xEFCDAB89u, h2=0x98BADCFEu, h3=0x10325476u, h4=0xC3D2E1F0u;
        static uint32_t rol(uint32_t v, int s){ return (v<<s) | (v>>(32-s)); }
        void process(const uint8_t* data, size_t len) {
            uint64_t ml = (uint64_t)len * 8ULL;
            std::vector<uint8_t> msg(data, data+len);
            msg.push_back(0x80);
            while ((msg.size() % 64) != 56) msg.push_back(0x00);
            for (int i=7;i>=0;--i) msg.push_back((uint8_t)((ml >> (i*8)) & 0xFF));

            for (size_t off=0; off<msg.size(); off+=64) {
                uint32_t w[80];
                for (int i=0;i<16;i++){
                    w[i] = (uint32_t)msg[off+i*4+0]<<24 |
                           (uint32_t)msg[off+i*4+1]<<16 |
                           (uint32_t)msg[off+i*4+2]<<8  |
                           (uint32_t)msg[off+i*4+3];
                }
                for (int i=16;i<80;i++) w[i] = rol(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1);

                uint32_t a=h0,b=h1,c=h2,d=h3,e=h4;
                for (int i=0;i<80;i++){
                    uint32_t f,k;
                    if (i<20){ f=(b&c)|((~b)&d); k=0x5A827999u; }
                    else if (i<40){ f=b^c^d; k=0x6ED9EBA1u; }
                    else if (i<60){ f=(b&c)|(b&d)|(c&d); k=0x8F1BBCDCu; }
                    else { f=b^c^d; k=0xCA62C1D6u; }
                    uint32_t temp = rol(a,5) + f + e + k + w[i];
                    e=d; d=c; c=rol(b,30); b=a; a=temp;
                }
                h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
            }
        }
        std::array<uint8_t,20> digest() const {
            std::array<uint8_t,20> out{};
            auto put = [&](int i, uint32_t v){
                out[i+0]=(uint8_t)((v>>24)&0xFF);
                out[i+1]=(uint8_t)((v>>16)&0xFF);
                out[i+2]=(uint8_t)((v>>8)&0xFF);
                out[i+3]=(uint8_t)(v&0xFF);
            };
            put(0,h0); put(4,h1); put(8,h2); put(12,h3); put(16,h4);
            return out;
        }
    };

    Sha1 s;
    s.process(reinterpret_cast<const uint8_t*>(input.data()), input.size());
    auto d = s.digest();

    // Base64 encode
    static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(28);
    int val=0, valb=-6;
    for (uint8_t c : d) {
        val = (val<<8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(b64[(val>>valb)&0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(b64[((val<<8)>>(valb+8))&0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

static bool ws_read_http_headers(int fd, std::string& headers, long long& bytes_in, int& last_errno) {
    headers.clear();
    last_errno = 0;
    std::string buf;
    char tmp[1024];
    while (true) {
        ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0) { last_errno = errno; return false; }
        bytes_in += (long long)n;
        buf.append(tmp, tmp + n);
        auto pos = buf.find("\r\n\r\n");
        if (pos != std::string::npos) {
            headers = buf.substr(0, pos + 4);
            return true;
        }
        if (buf.size() > 32 * 1024) { last_errno = EMSGSIZE; return false; }
    }
}

static std::string ws_get_header_value(const std::string& headers, const std::string& key) {
    // Very small header parser (case-insensitive key match, first occurrence).
    auto lower = [](std::string s){
        for (auto& c : s) c = (char)std::tolower((unsigned char)c);
        return s;
    };
    std::string hk = lower(key);
    std::istringstream iss(headers);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto p = line.find(':');
        if (p == std::string::npos) continue;
        std::string k = lower(ws_trim(line.substr(0, p)));
        if (k == hk) return ws_trim(line.substr(p + 1));
    }
    return "";
}

static bool ws_handshake_server(int fd, const std::string& expected_path, long long& bytes_in, long long& bytes_out, int& last_errno) {
    std::string headers;
    if (!ws_read_http_headers(fd, headers, bytes_in, last_errno)) return false;

    // Request line: GET <path> HTTP/1.1
    std::istringstream iss(headers);
    std::string reqline;
    std::getline(iss, reqline);
    if (!reqline.empty() && reqline.back() == '\r') reqline.pop_back();
    if (reqline.rfind("GET ", 0) != 0) { last_errno = EPROTO; return false; }
    auto sp1 = reqline.find(' ');
    auto sp2 = reqline.find(' ', sp1 + 1);
    std::string path = (sp2 != std::string::npos) ? reqline.substr(sp1 + 1, sp2 - (sp1 + 1)) : "";
    if (!expected_path.empty() && path != expected_path) {
        // Return 404 to make debugging easy.
        std::string resp = "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        send_all_counted(fd, resp, bytes_out);
        last_errno = ENOENT;
        return false;
    }

    std::string key = ws_get_header_value(headers, "Sec-WebSocket-Key");
    if (key.empty()) { last_errno = EPROTO; return false; }

    std::string accept = ws_sha1_base64(key + WS_GUID);

    std::string resp =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + accept + "\r\n\r\n";

    if (!send_all_counted(fd, resp, bytes_out)) { last_errno = errno; return false; }
    return true;
}

static std::string ws_make_client_key() {
    // 16 bytes random -> base64
    std::array<uint8_t, 16> b{};
    for (auto& x : b) x = (uint8_t)(rand() & 0xFF);
    static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val=0, valb=-6;
    for (uint8_t c : b) { val = (val<<8) + c; valb += 8; while (valb >= 0) { out.push_back(b64[(val>>valb)&0x3F]); valb -= 6; } }
    if (valb > -6) out.push_back(b64[((val<<8)>>(valb+8))&0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

static bool ws_handshake_client(int fd, const std::string& host, int port, const std::string& path,
                                long long& bytes_in, long long& bytes_out, int& last_errno) {
    std::string key = ws_make_client_key();
    std::string req =
        "GET " + (path.empty() ? std::string("/ws") : path) + " HTTP/1.1\r\n"
        "Host: " + host + ":" + std::to_string(port) + "\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: " + key + "\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n";

    if (!send_all_counted(fd, req, bytes_out)) { last_errno = errno; return false; }

    std::string headers;
    if (!ws_read_http_headers(fd, headers, bytes_in, last_errno)) return false;

    if (headers.find(" 101 ") == std::string::npos) { last_errno = EPROTO; return false; }

    std::string accept = ws_get_header_value(headers, "Sec-WebSocket-Accept");
    std::string expect = ws_sha1_base64(key + WS_GUID);
    if (accept != expect) { last_errno = EPROTO; return false; }
    return true;
}

static bool ws_recv_text_frame(int fd, std::string& payload, bool is_server_side,
                               long long& bytes_in, int& last_errno) {
    payload.clear();
    last_errno = 0;
    uint8_t hdr[2];
    ssize_t n = recv(fd, hdr, 2, MSG_WAITALL);
    if (n != 2) { last_errno = errno; return false; }
    bytes_in += 2;

    bool fin = (hdr[0] & 0x80) != 0;
    uint8_t opcode = hdr[0] & 0x0F;
    bool masked = (hdr[1] & 0x80) != 0;
    uint64_t len = (uint64_t)(hdr[1] & 0x7F);

    if (!fin) { last_errno = EPROTO; return false; }
    if (opcode == 0x8) { last_errno = 0; return false; } // close
    if (opcode != 0x1) { last_errno = EPROTO; return false; } // text only

    if (len == 126) {
        uint8_t ext[2];
        if (recv(fd, ext, 2, MSG_WAITALL) != 2) { last_errno = errno; return false; }
        bytes_in += 2;
        len = ((uint64_t)ext[0] << 8) | (uint64_t)ext[1];
    } else if (len == 127) {
        last_errno = EMSGSIZE;
        return false;
    }

    
    uint8_t maskkey[4] = {0,0,0,0};
    if (masked) {
        if (recv(fd, maskkey, 4, MSG_WAITALL) != 4) { last_errno = errno; return false; }
        bytes_in += 4;
        // When we are the CLIENT receiving from a server, masked frames are atypical but can be tolerated.
        // When we are the SERVER receiving from a client, masked MUST be true (enforced below).
    } else {
        // WebSocket masking rule:
        // - Client -> Server frames MUST be masked.
        // - Server -> Client frames MUST NOT be masked.
        if (is_server_side) { last_errno = EPROTO; return false; }
    }
    

    payload.resize((size_t)len);
    if (len > 0) {
        if (recv(fd, payload.data(), (size_t)len, MSG_WAITALL) != (ssize_t)len) { last_errno = errno; return false; }
        bytes_in += (long long)len;
    }
    if (masked) {
        for (size_t i=0;i<payload.size();++i) payload[i] = (char)((uint8_t)payload[i] ^ maskkey[i % 4]);
    }
    return true;
}

static bool ws_send_text_frame(int fd, const std::string& payload, bool mask,
                               long long& bytes_out) {
    std::string frame;
    frame.reserve(payload.size() + 14);

    uint8_t b0 = 0x80 | 0x1; // FIN + text
    frame.push_back((char)b0);

    size_t len = payload.size();
    if (len <= 125) {
        frame.push_back((char)((mask ? 0x80 : 0x00) | (uint8_t)len));
    } else if (len <= 65535) {
        frame.push_back((char)((mask ? 0x80 : 0x00) | 126));
        frame.push_back((char)((len >> 8) & 0xFF));
        frame.push_back((char)(len & 0xFF));
    } else {
        return false;
    }

    uint8_t maskkey[4] = {0,0,0,0};
    std::string masked_payload = payload;

    if (mask) {
        for (int i=0;i<4;i++) maskkey[i] = (uint8_t)(rand() & 0xFF);
        frame.append((char*)maskkey, (char*)maskkey + 4);
        for (size_t i=0;i<masked_payload.size();++i) masked_payload[i] = (char)((uint8_t)masked_payload[i] ^ maskkey[i % 4]);
        frame += masked_payload;
    } else {
        frame += payload;
    }

    return send_all_counted(fd, frame, bytes_out);
}
// ---------------------------------------------------------------------------


static inline bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), s.begin());
}

static inline std::string trim_newline_crlf(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    return s;
}

enum class Role { Client, Server };
enum class HbDirection { Bidirectional, ClientOnly, ServerOnly };

static HbDirection parse_hb_direction(const std::string& s) {
    std::string t = s;
    std::transform(t.begin(), t.end(), t.begin(), [](unsigned char c){ return std::tolower(c); });
    if (t == "bidirectional") return HbDirection::Bidirectional;
    if (t == "client-only" || t == "client_only" || t == "clientonly") return HbDirection::ClientOnly;
    if (t == "server-only" || t == "server_only" || t == "serveronly") return HbDirection::ServerOnly;
    return HbDirection::Bidirectional;
}

// Convert heartbeat direction enum to stable log string.
static inline const char* hb_direction_to_string(HbDirection d) {
    switch (d) {
        case HbDirection::Bidirectional: return "bidirectional";
        case HbDirection::ClientOnly:    return "client-only";
        case HbDirection::ServerOnly:    return "server-only";
        default:                         return "unknown";
    }
}

static bool hb_can_tx_ping(Role role, HbDirection dir) {
    if (dir == HbDirection::Bidirectional) return true;
    if (dir == HbDirection::ClientOnly) return role == Role::Client;
    if (dir == HbDirection::ServerOnly) return role == Role::Server;
    return true;
}

// Decide whether this side is allowed to transmit PONG in the selected heartbeat direction.
static bool hb_can_tx_pong(Role role, HbDirection dir) {
    // PONG is a reply to a received PING. In one-way modes, only the non-initiator replies.
    if (dir == HbDirection::Bidirectional) return true;
    if (dir == HbDirection::ClientOnly)   return role == Role::Server; // client initiates, server replies
    if (dir == HbDirection::ServerOnly)   return role == Role::Client; // server initiates, client replies
    return true;
}


static long long now_ms() {
    using Clock = std::chrono::steady_clock;
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
}

// Wall-clock timestamp for logs / wire formats that should be meaningful outside this process.
static long long now_epoch_ms() {
    using Clock = std::chrono::system_clock;
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
}

// Parse "HEARTBEAT=PING/PONG seq=123 ts=456"
static bool parse_http_hb_line(const std::string& s, std::string& kind, uint64_t& seq, long long& ts, long long& rtt_hint_ms) {
    kind.clear(); seq = 0; ts = 0; rtt_hint_ms = -1;
    auto p = s.find("HEARTBEAT=");
    if (p == std::string::npos) return false;
    std::string t = s.substr(p);

    // Expected:
    //   HEARTBEAT=PING seq=123 ts=456
    //   HEARTBEAT=PONG seq=123 ts=456 rtt=12
    std::istringstream iss(t);
    std::string hbkv, seqkv, tskv, rttkv;
    if (!(iss >> hbkv)) return false;
    if (!(iss >> seqkv)) return false;
    if (!(iss >> tskv)) return false;
    (void)(iss >> rttkv); // optional

    // hbkv: HEARTBEAT=PONG
    auto eq = hbkv.find('=');
    if (eq == std::string::npos) return false;
    kind = hbkv.substr(eq + 1);

    auto eq2 = seqkv.find('=');
    auto eq3 = tskv.find('=');
    if (eq2 == std::string::npos || eq3 == std::string::npos) return false;

    try {
        seq = (uint64_t)std::stoull(seqkv.substr(eq2 + 1));
        ts  = (long long)std::stoll(tskv.substr(eq3 + 1));
        if (!rttkv.empty()) {
            auto eq4 = rttkv.find('=');
            if (eq4 != std::string::npos) {
                rtt_hint_ms = (long long)std::stoll(rttkv.substr(eq4 + 1));
            }
        }
        return true;
    } catch (...) {
        return false;
    }
}

static bool http_read_some_with_timeout(int fd, std::string& out, int timeout_ms, int& last_errno) {
    out.clear();
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int r = select(fd + 1, &rfds, nullptr, nullptr, &tv);
    if (r <= 0) { last_errno = (r == 0) ? ETIMEDOUT : errno; return false; }
    char buf[4096];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) { last_errno = (n == 0) ? 0 : errno; return false; }
    out.assign(buf, buf + n);
    return true;
}

static std::vector<std::string> split_char(const std::string& s, char delim) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == delim) {
            out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    out.push_back(cur);
    return out;
}

struct HbConfig {
    bool enable{false};
    HbDirection direction{HbDirection::Bidirectional};
    int interval_ms{5000};
    int timeout_ms{3000};
    int max_missed{3};
};

// Enforce mode-direction constraints to avoid ambiguous semantics.
// - http      : only client-only heartbeat is allowed (client initiates, server replies)
// - http-sse  : only server-only heartbeat is allowed (server pushes, client receives)
static void validate_mode_hb_or_exit(const std::string& mode, HbDirection dir) {
    if (mode == "http") {
        if (dir != HbDirection::ClientOnly) {
            std::cerr << "[FATAL] Invalid heartbeat.direction for mode=http. Expected client-only, got "
                      << hb_direction_to_string(dir) << std::endl;
            std::exit(1);
        }
    } else if (mode == "http-sse") {
        if (dir != HbDirection::ServerOnly) {
            std::cerr << "[FATAL] Invalid heartbeat.direction for mode=http-sse. Expected server-only, got "
                      << hb_direction_to_string(dir) << std::endl;
            std::exit(1);
        }
    }
}

static HbConfig load_hb_config(const json& cfg) {
    HbConfig hb;
    if (!cfg.contains("heartbeat")) return hb;
    auto hbj = cfg["heartbeat"];
    hb.enable = hbj.value("enable", true);
    hb.direction = parse_hb_direction(hbj.value("direction", "bidirectional"));
    hb.interval_ms = (int)hbj.value("interval-ms", (long long)5000);
    hb.timeout_ms  = (int)hbj.value("timeout-ms", (long long)3000);
    hb.max_missed  = (int)hbj.value("max-missed", (long long)3);
    return hb;
}

static json load_config(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open config file");
    json j;
    in >> j;
    return j;
}

static void sleep_sec(int sec) {
    if (sec > 0) std::this_thread::sleep_for(std::chrono::seconds(sec));
}

// Print payload as visible ASCII: \r => "\\r", \n => "\\n" + newline
static void print_payload_visible_ascii(const std::string& dir, const std::string& proto, const std::string& s) {
    std::cout << "[Client][" << proto << "][" << dir << "]\n";
    for (unsigned char c : s) {
        if (c == '\r') {
            std::cout << "\\r";
        } else if (c == '\n') {
            std::cout << "\\n\n";
        } else {
            std::cout << (char)c;
        }
    }
    if (s.empty() || s.back() != '\n') std::cout << "\n";
}

static int read_interval_sec_with_legacy_ms(const json& obj,
                                            const std::string& sec_key,
                                            const std::string& legacy_ms_key,
                                            int default_sec) {
    if (obj.contains(sec_key)) {
        try {
            int v = obj.value(sec_key, default_sec);
            return (v < 0) ? default_sec : v;
        } catch (...) {
            return default_sec;
        }
    }

    if (obj.contains(legacy_ms_key)) {
        try {
            int ms = obj.value(legacy_ms_key, default_sec * 1000);
            if (ms <= 0) return 0;
            return (ms + 999) / 1000;
        } catch (...) {
            return default_sec;
        }
    }

    return default_sec;
}

static void set_tcp_keepalive(int fd) {
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
}

static bool send_all(int fd, const std::string& s) {
    size_t off = 0;
    while (off < s.size()) {
        ssize_t n = send(fd, s.data() + off, s.size() - off, 0);
        if (n <= 0) return false;
        off += (size_t)n;
    }
    return true;
}

static bool recv_line(int fd, std::string& line) {
    line.clear();
    char c;
    while (true) {
        ssize_t n = recv(fd, &c, 1, 0);
        if (n <= 0) return false;
        line.push_back(c);
        if (c == '\n') return true;
    }
}

static bool recv_n(int fd, std::string& out, size_t n) {
    out.clear();
    out.reserve(n);
    while (out.size() < n) {
        char buf[4096];
        size_t need = n - out.size();
        ssize_t r = recv(fd, buf, (need < sizeof(buf) ? need : sizeof(buf)), 0);
        if (r <= 0) return false;
        out.append(buf, buf + r);
    }
    return true;
}

static bool recv_http_headers(int fd, std::string& buf, size_t max_buf = 512 * 1024) {
    buf.clear();
    char tmp[4096];
    while (buf.find("\r\n\r\n") == std::string::npos) {
        ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0) return false;
        buf.append(tmp, tmp + n);
        if (buf.size() > max_buf) return false;
    }
    return true;
}

static int parse_http_status(const std::string& headers) {
    auto pos = headers.find("\r\n");
    std::string line = (pos == std::string::npos) ? headers : headers.substr(0, pos);
    std::istringstream iss(line);
    std::string ver;
    int code = 0;
    iss >> ver >> code;
    return code;
}

static long long parse_content_length(const std::string& headers) {
    std::string lower = headers;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });

    std::string key = "content-length:";
    auto pos = lower.find(key);
    if (pos == std::string::npos) return -1;

    pos += key.size();
    while (pos < lower.size() && (lower[pos] == ' ' || lower[pos] == '\t')) pos++;

    long long v = 0;
    while (pos < lower.size() && std::isdigit((unsigned char)lower[pos])) {
        v = v * 10 + (lower[pos] - '0');
        pos++;
    }
    return v;
}

static std::string build_http_path_with_seq(const json& http, long long seq) {
    std::string base_path = http.value("path", std::string("/hello"));
    std::string path = base_path;
    if (path.find('?') == std::string::npos) {
        path += "?seq=" + std::to_string(seq);
    } else {
        path += "&seq=" + std::to_string(seq);
    }
    return path;
}

static std::string build_http_get_request(const json& http, const std::string& path_with_seq) {
    std::string host = http.value("host", std::string("localhost"));
    bool keep = http.value("keep-alive", true);

    std::ostringstream oss;
    oss << "GET " << path_with_seq << " HTTP/1.1\r\n";
    oss << "Host: " << host << "\r\n";
    oss << "Accept: */*\r\n";
    oss << "Connection: " << (keep ? "keep-alive" : "close") << "\r\n";
    oss << "\r\n";
    return oss.str();
}

// Accept both "receive seq=N" and "received seq=N"
static bool parse_raw_receive_seq(const std::string& line_no_nl, long long& seq_out) {
    std::string s = line_no_nl;
    if (!s.empty() && s.back() == '\r') s.pop_back();

    const std::string p1 = "receive seq=";
    const std::string p2 = "received seq=";

    size_t off = std::string::npos;
    if (s.rfind(p1, 0) == 0) off = p1.size();
    else if (s.rfind(p2, 0) == 0) off = p2.size();
    else return false;

    std::string num = s.substr(off);
    if (num.empty()) return false;

    for (char c : num) {
        if (!std::isdigit((unsigned char)c)) return false;
    }

    try {
        seq_out = std::stoll(num);
    } catch (...) {
        return false;
    }
    return true;
}

int main(int argc, char* argv[]) {
    const char* role_str = "client";

    auto cfg = load_config(argc > 1 ? argv[1] : "client-config.json");

    std::string mode = cfg.value("mode", "raw");

        // Common runtime context for all modes (RAW/HTTP/HTTP-SSE/WebSocket)
        const Role role = Role::Client;
        json logging = get_obj_or_empty(cfg, "logging");
        bool log_enable = logging.value("enable", true);
        HbConfig hb = load_hb_config(cfg);
        // Runtime heartbeat direction string for symmetric HB logs.
        const std::string hb_dir_str = hb_direction_to_string(hb.direction);

    std::string server_ip = cfg["server-ip"];
    int port = cfg["port"];

    // --- Enhanced startup logs (startup only; runtime logic unchanged) ---
    {
        bool tcp_keepalive_cfg = cfg.value("tcp-keep-alive", false);
        HbConfig hb_start = load_hb_config(cfg);
        std::string hb_dir_start = (cfg.contains("heartbeat") ? cfg["heartbeat"].value("direction", "bidirectional")
                                                           : std::string("bidirectional"));

        std::cout << "[Client] Starting mini-tcp-client-heartbeat" << std::endl;
        std::cout << "[Client] Role            : client" << std::endl;
        std::cout << "[Client] Mode            : " << mode << std::endl;
        std::cout << "[Client] Connect         : " << server_ip << ":" << port << std::endl;
        std::cout << "[Client] TCP KeepAlive   : " << (tcp_keepalive_cfg ? "enabled" : "disabled") << std::endl;
        std::cout << std::endl;
        std::cout << "[HB] enabled=" << (hb_start.enable ? "true" : "false") << std::endl;
        std::cout << "[HB] direction=" << hb_dir_start << std::endl;
        std::cout << "[HB] interval=" << hb_start.interval_ms << "ms" << std::endl;
        std::cout << "[HB] timeout=" << hb_start.timeout_ms << "ms" << std::endl;
        std::cout << "[HB] max-missed=" << hb_start.max_missed << std::endl;
        std::cout << std::endl;

        // Enforce mode-direction constraints early.
        validate_mode_hb_or_exit(mode, hb_start.direction);

        std::cout << "[Client] Connecting..." << std::endl;
    }
    // --- End enhanced startup logs ---


    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    if (cfg.value("tcp-keep-alive", false)) {
        set_tcp_keepalive(fd);
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip.c_str(), &addr.sin_addr);

    if (connect(fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return 1;
    }

    
if (mode == "raw") {
    auto raw = cfg["raw"];
    int raw_interval_sec = read_interval_sec_with_legacy_ms(
        raw, "send-interval-sec", "send-interval-ms", 1);

    HbConfig hb = load_hb_config(cfg);
    const Role role = Role::Client;
    const std::string hb_prefix = "HB|";

    std::cout << "[HB] enabled=" << (hb.enable ? "true" : "false")
              << " mode=raw direction=" << (cfg.contains("heartbeat") ? cfg["heartbeat"].value("direction", "bidirectional") : std::string("bidirectional"))
              << " interval=" << hb.interval_ms << "ms timeout=" << hb.timeout_ms << "ms"
              << " max-missed=" << hb.max_missed
              << std::endl;

    std::atomic<bool> running{true};
    std::mutex send_mu;
    std::mutex hb_mu;
    // RTT bookkeeping uses steady-clock milliseconds; protocol timestamps use
    // epoch milliseconds so they have consistent cross-process semantics.
    std::unordered_map<long long, long long> ping_sent_ms;
    std::atomic<long long> last_ok_ms{now_ms()};
    std::atomic<int> missed{0};

    auto safe_send = [&](const std::string& line) -> bool {
        std::lock_guard<std::mutex> lk(send_mu);
        return send_all(fd, line);
    };

    std::thread rx_thread([&](){
        while (running.load()) {
            std::string line;
            if (!recv_line(fd, line)) {
                running.store(false);
                break;
            }
            std::string t = trim_newline_crlf(line);

        // Heartbeat message path (symmetric logging on both client/server).
            if (starts_with(t, hb_prefix)) {
                auto parts = split_char(t, '|');
                if (parts.size() >= 4) {
                    std::string type = parts[1];
                    long long seq = -1;
                    try { seq = std::stoll(parts[2]); } catch (...) { seq = -1; }

                    

                    long long ts_msg = -1;
                    try { ts_msg = std::stoll(parts[3]); } catch (...) { ts_msg = -1; }
                    if (type == "PING") {
                        if (hb.enable) {
                            // Heartbeat RX (server-only: client is responder)
                            std::cout << "[HB][RX] PING role=client dir=" << hb_dir_str << " seq=" << seq << " ts=" << ts_msg << std::endl;

                            // Mark link as alive
                            last_ok_ms.store(now_ms());
                            missed.store(0);

                            // Heartbeat TX
                            std::string pong = "HB|PONG|" + std::to_string(seq) + "|" + std::to_string(now_epoch_ms()) + "\n";
                            bool ok = safe_send(pong);
                            if (ok) {
                                std::cout << "[HB][TX] PONG role=client dir=" << hb_dir_str << " seq=" << seq << std::endl;
                            } else {
                                std::cerr << "[HB][TX] PONG role=client dir=" << hb_dir_str << " seq=" << seq << " FAILED" << std::endl;
                            }
                        }
                    } else if (type == "PONG") {
                        long long rtt = -1;
                        {
                            std::lock_guard<std::mutex> lk(hb_mu);
                            auto it = ping_sent_ms.find(seq);
                            if (it != ping_sent_ms.end()) {
                                rtt = now_ms() - it->second;
                                ping_sent_ms.erase(it);
                            }
                        }
                        last_ok_ms.store(now_ms());
                        missed.store(0);
                        if (rtt >= 0) {
                            std::cout << "[HB][RX] PONG role=client dir=" << hb_dir_str << " seq=" << seq << " ts=" << ts_msg << " rtt=" << rtt << "ms" << std::endl;
                        } else {
                            // Still print for visibility even if rtt missing
                            std::cout << "[HB][RX] PONG role=client dir=" << hb_dir_str << " seq=" << seq << " ts=" << ts_msg << " rtt=?ms" << std::endl;
                        }
                    }
                }
                continue;
            }

            // RAW line
            if (starts_with(t, "seq=")) {
                long long rx_seq = -1;
                try { rx_seq = std::stoll(t.substr(4)); } catch (...) { rx_seq = -1; }
                if (rx_seq >= 0) {
                    std::cout << "[RAW][RX] role=" + std::string(role_str) + " seq=" << rx_seq << std::endl;
                } else {
                    std::cerr << "[RAW][RX] WARN unexpected: " << t << std::endl;
                }
                continue;
            }

            std::cerr << "[RAW][RX] WARN unknown line: " << t << std::endl;
        }
    });

    std::thread raw_tx_thread([&](){
        long long seq = 0;
        while (running.load()) {
            seq++;
            std::string msg = "seq=" + std::to_string(seq) + "\n";
            std::cout << "[RAW][TX] role=" + std::string(role_str) + " seq=" << seq << std::endl;
            if (!safe_send(msg)) {
                running.store(false);
                break;
            }
            sleep_sec(raw_interval_sec);
        }
    });

    std::thread hb_tx_thread([&](){
        if (!hb.enable) return;
        if (!hb_can_tx_ping(role, hb.direction)) return;

        long long hb_seq = 0;
        // Delay first ping by interval to avoid "startup false timeout"
        std::this_thread::sleep_for(std::chrono::milliseconds(hb.interval_ms));

        while (running.load()) {
            hb_seq++;
            long long ts = now_epoch_ms();
            {
                std::lock_guard<std::mutex> lk(hb_mu);
                ping_sent_ms[hb_seq] = now_ms();
            }
            std::string ping = "HB|PING|" + std::to_string(hb_seq) + "|" + std::to_string(ts) + "\n";
            std::cout << "[HB][TX] PING role=client dir=" << hb_dir_str << " seq=" << hb_seq << " ts=" << ts << std::endl;
            if (!safe_send(ping)) {
                running.store(false);
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(hb.interval_ms));
        }
    });

    std::thread hb_watchdog([&](){
        if (!hb.enable) return;
        if (!hb_can_tx_ping(role, hb.direction)) return;

        while (running.load()) {
            long long now = now_ms();
            long long last = last_ok_ms.load();
            if (now - last > hb.timeout_ms) {
                int m = missed.fetch_add(1) + 1;
                if (m >= hb.max_missed) {
                    std::cerr << "[HB][TIMEOUT] missed=" << m << " closing socket" << std::endl;
                    running.store(false);
                    shutdown(fd, SHUT_RDWR);
                    close(fd);
                    break;
                }
                // Move last_ok forward to avoid spamming too fast
                last_ok_ms.store(now);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    });

    // Wait for threads
    if (raw_tx_thread.joinable()) raw_tx_thread.join();
    if (hb_tx_thread.joinable()) hb_tx_thread.join();
    if (hb_watchdog.joinable()) hb_watchdog.join();
    if (rx_thread.joinable()) rx_thread.join();

    close(fd);
    return 0;
}

    
    if (mode == "websocket") {
        json ws = get_obj_or_empty(cfg, "websocket");
        std::string ws_path = ws.value("path", std::string("/ws"));

        // WebSocket I/O counters (best-effort) and logging toggle.
        long long bytes_in = 0; long long bytes_out = 0;
        bool log_enable = true;
        if (cfg.contains("logging") && cfg["logging"].is_object()) {
            log_enable = cfg["logging"].value("enable", true);
        }

        // WebSocket handshake (client side). Path is configurable via config.websocket.path.
        int ws_errno = 0;
        if (!ws_handshake_client(fd, server_ip, port, ws_path, bytes_in, bytes_out, ws_errno)) {
            std::cerr << "[Client] WebSocket handshake failed" << std::endl;
            close(fd);
            return 2;
        }

        HbConfig hb = load_hb_config(cfg);
        const Role role = Role::Client;
        const std::string hb_prefix = "HB|";

        if (log_enable) {
            std::cout << "[HB] enabled=" << (hb.enable ? "true" : "false")
                      << " mode=websocket direction=" << (cfg.contains("heartbeat") ? cfg["heartbeat"].value("direction", "bidirectional") : std::string("bidirectional"))
                      << " interval=" << hb.interval_ms << "ms timeout=" << hb.timeout_ms << "ms"
                      << " max-missed=" << hb.max_missed
                      << std::endl;
            std::cout << "[WS] path=" << ws_path << std::endl;
        }

        std::atomic<bool> running{true};
        std::mutex send_mu;
        std::mutex hb_mu;
        std::unordered_map<long long, long long> ping_sent_ms;
        std::atomic<long long> last_ok_ms{now_ms()};
        std::atomic<int> missed{0};

        // Client frames MUST be masked.
        auto safe_send = [&](const std::string& line) -> bool {
            std::lock_guard<std::mutex> lk(send_mu);
            return ws_send_text_frame(fd, line, /*mask=*/true, bytes_out);
        };

        std::thread hb_tx_thread([&](){
            if (!hb.enable) return;
            if (!hb_can_tx_ping(role, hb.direction)) return;

            long long hb_seq = 0;
            std::this_thread::sleep_for(std::chrono::milliseconds(hb.interval_ms));

            while (running.load()) {
                hb_seq++;
                long long ts = now_epoch_ms();
                {
                    std::lock_guard<std::mutex> lk(hb_mu);
                    ping_sent_ms[hb_seq] = now_ms();
                }
                std::string ping = "HB|PING|" + std::to_string(hb_seq) + "|" + std::to_string(ts) + "\n";
                if (log_enable) std::cout << "[HB][TX] PING role=client dir=" << hb_dir_str << " seq=" << hb_seq << " ts=" << ts << std::endl;
                if (!safe_send(ping)) {
                    running.store(false);
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(hb.interval_ms));
            }
        });

        std::thread hb_watchdog([&](){
            if (!hb.enable) return;
            if (!hb_can_tx_ping(role, hb.direction)) return;

            while (running.load()) {
                long long now = now_ms();
                long long last = last_ok_ms.load();
                if (now - last > hb.timeout_ms) {
                    int m = missed.fetch_add(1) + 1;
                    if (m >= hb.max_missed) {
                        std::cerr << "[HB][TIMEOUT] missed=" << m << " closing socket" << std::endl;
                        running.store(false);
                        shutdown(fd, SHUT_RDWR);
                        close(fd);
                        break;
                    }
                    last_ok_ms.store(now);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
        });

        int last_errno = 0;
        std::string ws_buf;

        auto ws_recv_line = [&](std::string& line) -> bool {
            line.clear();
            while (true) {
                auto pos = ws_buf.find('\n');
                if (pos != std::string::npos) {
                    line = ws_buf.substr(0, pos + 1);
                    ws_buf.erase(0, pos + 1);
                    return true;
                }
                std::string msg;
                if (!ws_recv_text_frame(fd, msg, /*is_server_side=*/false, bytes_in, last_errno)) {
                    return false;
                }
                ws_buf += msg;
                if (ws_buf.size() > 1024 * 1024) { last_errno = EMSGSIZE; return false; }
            }
        };

        // RAW sending thread (keep behavior consistent with raw mode's periodic sender if enabled).
        json raw = get_obj_or_empty(cfg, "raw");
        long long send_interval_ms = raw.value("send-interval-ms", 1000);
        std::atomic<long long> seq{0};

        std::thread raw_tx_thread([&](){
            while (running.load()) {
                seq++;
                std::string line = "seq=" + std::to_string(seq.load()) + "\n";
                if (log_enable) std::cout << "[WS][TX] role=client seq=" << seq.load() << std::endl;
                if (!safe_send(line)) { running.store(false); break; }
                std::this_thread::sleep_for(std::chrono::milliseconds((int)send_interval_ms));
            }
        });

        while (running.load()) {
            std::string line;
            if (!ws_recv_line(line)) {
                break;
            }

            std::string t = trim_newline_crlf(line);

            if (starts_with(t, hb_prefix)) {
                auto parts = split_char(t, '|');
                if (parts.size() >= 4) {
                    std::string type = parts[1];
                    long long seqn = -1;
                    try { seqn = std::stoll(parts[2]); } catch (...) { seqn = -1; }

                    long long ts_msg = -1;
                    try { ts_msg = std::stoll(parts[3]); } catch (...) { ts_msg = -1; }

                    if (type == "PING") {
                        if (hb.enable) {
                            if (log_enable) std::cout << "[HB][RX] PING role=client dir=" << hb_dir_str << " seq=" << seqn << " ts=" << ts_msg << std::endl;
                            std::string pong = "HB|PONG|" + std::to_string(seqn) + "|" + std::to_string(now_epoch_ms()) + "\n";
                            if (hb_can_tx_pong(role, hb.direction)) {
                                if (log_enable) std::cout << "[HB][TX] PONG role=client dir=" << hb_dir_str << " seq=" << seqn << std::endl;
                                safe_send(pong);
                            }
                            last_ok_ms.store(now_ms());
                            missed.store(0);
                        }
                        continue;
                    } else if (type == "PONG") {
                        if (hb.enable) {
                            long long now = now_ms();
                            long long sent = -1;
                            {
                                std::lock_guard<std::mutex> lk(hb_mu);
                                auto it = ping_sent_ms.find(seqn);
                                if (it != ping_sent_ms.end()) { sent = it->second; ping_sent_ms.erase(it); }
                            }
                            if (sent >= 0) {
                                long long rtt = now - sent;
                                if (log_enable) std::cout << "[HB][RX] PONG role=client dir=" << hb_dir_str << " seq=" << seqn << " ts=" << ts_msg << " rtt=" << rtt << "ms" << std::endl;
                            } else {
                                if (log_enable) std::cout << "[HB][RX] PONG role=client dir=" << hb_dir_str << " seq=" << seqn << " ts=" << ts_msg << " rtt=?ms" << std::endl;
                            }
                            last_ok_ms.store(now);
                            missed.store(0);
                        }
                        continue;
                    }
                }
            }

            if (starts_with(t, "seq=")) {
                long long s = -1;
                try { s = std::stoll(t.substr(4)); } catch (...) { s = -1; }
                if (log_enable) std::cout << "[RAW][RX] role=client seq=" << s << std::endl;
                continue;
            }
        }

        running.store(false);
        if (raw_tx_thread.joinable()) raw_tx_thread.join();
        if (hb_tx_thread.joinable()) hb_tx_thread.join();
        if (hb_watchdog.joinable()) hb_watchdog.join();
        close(fd);
        return 0;
    }


if (mode == "http-sse") {
    // Server-Sent Events: server-only heartbeat (server pushes PING on /__hb/sse)
    const std::string sse_path = cfg.value("sse-path", std::string("/__hb/sse"));

    int sse_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sse_fd < 0) throw std::runtime_error("socket() failed");

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (::inet_pton(AF_INET, server_ip.c_str(), &addr.sin_addr) != 1) throw std::runtime_error("inet_pton() failed");
    if (::connect(sse_fd, (sockaddr*)&addr, sizeof(addr)) != 0) throw std::runtime_error("connect() failed");

    std::ostringstream oss;
    oss << "GET " << sse_path << " HTTP/1.1\r\n"
        << "Host: " << server_ip << "\r\n"
        << "Accept: text/event-stream\r\n"
        << "Connection: keep-alive\r\n"
        << "\r\n";
    std::string req = oss.str();
    if (log_enable) {
        std::cout << "[Client][HTTP-SSE][TX]" << std::endl;
        print_payload_visible_ascii("TX", "HTTP-SSE", req);
    }
    if (!send_all(sse_fd, req)) throw std::runtime_error("send() failed");

    // Read response headers
    std::string buf;
    while (buf.find("\r\n\r\n") == std::string::npos) {
        std::string chunk;
        int e = 0;
        if (!http_read_some_with_timeout(sse_fd, chunk, 3000, e)) throw std::runtime_error("SSE recv header timeout");
        buf += chunk;
        if (buf.size() > 64 * 1024) throw std::runtime_error("SSE header too large");
    }
    if (log_enable) {
        auto hlen = buf.find("\r\n\r\n") + 4;
        std::cout << "[Client][HTTP-SSE][RX]" << std::endl;
        
    // Optional: keep "normal" HTTP requests running in parallel with SSE stream.
// Uses the existing "http" block (path / interval) if present.
// Requirement: In http-sse mode, the output/log behavior of normal HTTP must stay
// strictly consistent with http mode (except the additional HB lines).
std::thread normal_http_thread;
if (cfg.contains("http")) {
    json http = cfg["http"];
    bool keep = http.value("keep-alive", true);
    int interval_sec = read_interval_sec_with_legacy_ms(
        http, "request-interval-sec", "request-interval-ms", 1);

    // Only start if interval is positive and a path is configured.
    std::string base_path = http.value("path", std::string(""));
    if (interval_sec > 0 && !base_path.empty()) {
        normal_http_thread = std::thread([&, http, keep, interval_sec]() {
            // Create a dedicated connection for normal HTTP traffic (separate from SSE).
            int fd2 = ::socket(AF_INET, SOCK_STREAM, 0);
            if (fd2 < 0) return;

            sockaddr_in addr2{};
            addr2.sin_family = AF_INET;
            addr2.sin_port = htons((uint16_t)port);
            if (::inet_pton(AF_INET, server_ip.c_str(), &addr2.sin_addr) != 1) {
                ::close(fd2);
                return;
            }
            if (::connect(fd2, (sockaddr*)&addr2, sizeof(addr2)) != 0) {
                ::close(fd2);
                return;
            }

            long long seq = 0;
            while (true) {
                seq++;

                std::string path = build_http_path_with_seq(http, seq);
                std::string req = build_http_get_request(http, path);

                // Keep output strictly consistent with HTTP mode
                print_payload_visible_ascii("TX", "HTTP", req);
                long long t0 = now_ms();
                if (!send_all(fd2, req)) break;

                std::string headers;
                if (!recv_http_headers(fd2, headers)) break;
                print_payload_visible_ascii("RX", "HTTP", headers);

                int code = parse_http_status(headers);

                long long cl = parse_content_length(headers);
                if (cl > 0) {
                    std::string body;
                    if (!recv_n(fd2, body, (size_t)cl)) break;
                    print_payload_visible_ascii("RX", "HTTP", body);
                }

                long long t1 = now_ms();
                long long rtt_ms = t1 - t0;

                std::cout << "[Client][HTTP] receive status=" << code
                          << " seq=" << seq
                          << " rtt=" << rtt_ms << "ms"
                          << std::endl;

                if (!keep) break;
                sleep_sec(interval_sec);
            }

            ::close(fd2);
        });
        normal_http_thread.detach(); // keep running alongside SSE stream
    }
}

print_payload_visible_ascii("RX", "HTTP-SSE", buf.substr(0, hlen));
    }

    // Stream events
    std::string stream = buf.substr(buf.find("\r\n\r\n") + 4);
    long long sse_last_rx_ms = now_epoch_ms();
    int sse_missed = 0;
    // --- HTTP-SSE lag (server->client only) ---
    // In http-sse mode, we do NOT send /__hb from the client (to avoid affecting normal HTTP and
    // to avoid direction conflicts when hb.direction is server-only).
    // We only compute and print lag on the client:
    //   lag_ms = client_recv_epoch_ms - ts_in_sse_payload

    while (true) {
        // split by line
        auto nl = stream.find('\n');
        if (nl == std::string::npos) {
            std::string chunk;
            int e = 0;
            if (!http_read_some_with_timeout(sse_fd, chunk, hb.timeout_ms > 0 ? hb.timeout_ms : 3000, e)) {
                // No data within timeout window.
                sse_missed++;
                if (hb.enable && sse_missed > hb.max_missed) {
                    throw std::runtime_error("SSE heartbeat timeout");
                }
                continue;
            }
            sse_last_rx_ms = now_epoch_ms();
            sse_missed = 0;
            stream += chunk;
            continue;
        }
        std::string line = stream.substr(0, nl + 1);
        stream.erase(0, nl + 1);

        if (line.rfind("data:", 0) == 0) {
            std::string payload = line.substr(5);
            std::string kind;
            uint64_t seqn = 0;
            long long ts_msg = 0;
            long long rtt_hint = -1;
            // Keep heartbeat content consistent with HTTP /__hb: server sends HEARTBEAT=PONG seq=... ts=...
            if (parse_http_hb_line(payload, kind, seqn, ts_msg, rtt_hint) && kind == "PONG") {
                // Compute SSE lag on the client: recv_epoch_ms - ts_in_payload
                long long recv_epoch = now_epoch_ms();
                long long lag_ms = (ts_msg > 0) ? (recv_epoch - ts_msg) : -1;

                if (log_enable) {
                    // Keep prefix consistent across modes: use [HB] for heartbeat output.
                    std::cout << "[HB][RX] PONG role=client dir=server-only"
                              << " seq=" << seqn
                              << " ts=" << ts_msg
                              << " lag=" << lag_ms << "ms"
                              << std::endl;
                }

                // NOTE: In http-sse mode we do NOT trigger /__hb (no extra HB TX/RX logs).
            }
        }
    }

    ::close(sse_fd);
    return 0;
}

if (mode == "http") {

// Start HTTP heartbeat scheduler (client-only): periodically GET /__hb on a separate connection.
std::atomic<bool> hb_running(true);
std::thread hb_thread;
if (hb.enable && hb_can_tx_ping(role, hb.direction)) {
    hb_thread = std::thread([&]() {
        uint64_t hb_seq = 0;
        while (hb_running.load()) {
            hb_seq++;
            // Use wall-clock epoch ms for the wire timestamp so it is meaningful in logs.
            long long ts = now_epoch_ms();

            if (log_enable) {
                std::cout << "[HB][TX] PING role=client dir=" << hb_dir_str
                          << " seq=" << hb_seq << " ts=" << ts << std::endl;
            }

            // One-shot connection for simplicity and to avoid mixing with /hello traffic.
            // RTT measurement:
            // - t_send_ms: right before sending the HTTP request
            // - t_first_byte_ms: when first response bytes arrive (TTFB)
            // - t_done_ms: after finishing reads (or timeout)
            int fd2 = ::socket(AF_INET, SOCK_STREAM, 0);
            if (fd2 < 0) { std::this_thread::sleep_for(std::chrono::milliseconds(hb.interval_ms)); continue; }

            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons((uint16_t)port);
            if (::inet_pton(AF_INET, server_ip.c_str(), &addr.sin_addr) != 1) { ::close(fd2); continue; }
            if (::connect(fd2, (sockaddr*)&addr, sizeof(addr)) != 0) { ::close(fd2); continue; }

            std::ostringstream oss;
            oss << "GET /__hb?seq=" << hb_seq << "&ts=" << ts << " HTTP/1.1\r\n"
                << "Host: " << server_ip << "\r\n"
                << "Accept: */*\r\n"
                << "Connection: close\r\n"
                << "\r\n";
            std::string req = oss.str();

            long long t_send_ms = now_ms();
            (void)send_all(fd2, req);

            long long t_first_byte_ms = -1;
            std::string resp_all;
            while (true) {
                std::string chunk;
                int e = 0;
                if (!http_read_some_with_timeout(fd2, chunk, hb.timeout_ms > 0 ? hb.timeout_ms : 3000, e)) break;
                if (t_first_byte_ms < 0) t_first_byte_ms = now_ms();
                resp_all += chunk;
                // The heartbeat response is tiny; once we see the marker, stop immediately to avoid
                // inflating RTT due to waiting for connection close / timeouts.
                if (resp_all.find("HEARTBEAT=") != std::string::npos) break;
                if (resp_all.size() > 128 * 1024) break;
            }
            long long t_done_ms = now_ms();
            ::close(fd2);

            std::string kind;
            uint64_t seqn = 0;
            long long ts_msg = 0;
            long long rtt_hint = -1;
            if (parse_http_hb_line(resp_all, kind, seqn, ts_msg, rtt_hint) && kind == "PONG") {
                // RTT is measured until we have received the heartbeat payload (or timed out).
                long long rtt_ms = t_done_ms - t_send_ms;
                if (log_enable) {
                    std::cout << "[HB][RX] PONG role=client dir=" << hb_dir_str
                              << " seq=" << seqn << " ts=" << ts_msg
                              << " client_rtt=" << rtt_ms << "ms" << std::endl;
                }
            } else {
                // Do NOT label this as PONG: if we didn't parse the heartbeat payload, treat it as non-heartbeat.
                long long rtt_ms = t_done_ms - t_send_ms;
                if (log_enable) {
                    std::cout << "[HB][RX] IGNORE role=client dir=" << hb_dir_str
                              << " seq=" << hb_seq
                              << " reason=non-heartbeat-payload"
                              << " client_rtt=" << rtt_ms << "ms" << std::endl;
                }
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(std::max(200, hb.interval_ms)));
        }
    });
}

        auto http = cfg["http"];
        bool keep = http.value("keep-alive", true);

        int interval_sec = read_interval_sec_with_legacy_ms(
            http, "request-interval-sec", "request-interval-ms", 1);

        long long seq = 0;
        while (true) {
            seq++;

            std::string path = build_http_path_with_seq(http, seq);
            std::string req = build_http_get_request(http, path);

            print_payload_visible_ascii("TX", "HTTP", req);
            long long t0 = now_ms();
            if (!send_all(fd, req)) break;

            std::string headers;
            if (!recv_http_headers(fd, headers)) break;
            print_payload_visible_ascii("RX", "HTTP", headers);

            int code = parse_http_status(headers);

            long long cl = parse_content_length(headers);
            if (cl > 0) {
                std::string body;
                if (!recv_n(fd, body, (size_t)cl)) break;
                // Body is also part of RX payload
                print_payload_visible_ascii("RX", "HTTP", body);
            }

            long long t1 = now_ms();
            long long rtt_ms = t1 - t0;

            std::cout << "[Client][HTTP] receive status=" << code
                      << " seq=" << seq
                      << " rtt=" << rtt_ms << "ms"
                      << std::endl;

            if (!keep) break;
            sleep_sec(interval_sec);
        }

        close(fd);
        
hb_running.store(false);
if (hb_thread.joinable()) hb_thread.join();

return 0;
    }

    std::cerr << "[Client] Error: unsupported mode=" << mode << std::endl;
    close(fd);
    return 1;
}
