// Copyright (c) 2026 Lionel Guo
// Author: Lionel Guo
// Email: lionelliguo@gmail.com

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cerrno>
#include <cstring>
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


// Parse "GET /path?x=y HTTP/1.1" -> "/path?x=y"
static std::string http_request_target(const std::string& req) {
    auto eol = req.find("\r\n");
    std::string line = (eol == std::string::npos) ? req : req.substr(0, eol);
    std::istringstream iss(line);
    std::string method, target;
    iss >> method >> target;
    return target;
}

static std::string http_path_only(const std::string& target) {
    auto q = target.find('?');
    return (q == std::string::npos) ? target : target.substr(0, q);
}

static bool http_query_u64(const std::string& target, const std::string& key, uint64_t& out) {
    auto q = target.find('?');
    if (q == std::string::npos) return false;
    std::string qs = target.substr(q + 1);
    std::istringstream iss(qs);
    std::string kv;
    while (std::getline(iss, kv, '&')) {
        auto eq = kv.find('=');
        if (eq == std::string::npos) continue;
        std::string k = kv.substr(0, eq);
        std::string v = kv.substr(eq + 1);
        if (k == key) {
            try {
                out = (uint64_t)std::stoull(v);
                return true;
            } catch (...) {
                return false;
            }
        }
    }
    return false;
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
    // Only enforce for HTTP-based modes.
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
using Clock = std::chrono::steady_clock;

static json load_config(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open config file");
    json j;
    in >> j;
    return j;
}

static void set_tcp_keepalive(int fd) {
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
}

static void set_recv_timeout(int fd, int sec) {
    if (sec <= 0) return;
    timeval tv{};
    tv.tv_sec = sec;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

// Print payload as visible ASCII: \r => "\\r", \n => "\\n" + newline
static void print_payload_visible_ascii(const std::string& who,
                                        const std::string& proto,
                                        const std::string& dir,
                                        const std::string& s) {
    std::cout << "[" << who << "][" << proto << "][" << dir << "]\n";
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


static bool recv_line_counted(int fd, std::string& line, long long& bytes_in, int& last_errno) {
    line.clear();
    last_errno = 0;

    char c;
    while (true) {
        ssize_t n = recv(fd, &c, 1, 0);
        if (n <= 0) {
            last_errno = (n < 0) ? errno : 0;
            return false;
        }
        bytes_in += (long long)n;
        line.push_back(c);
        if (c == '\n') return true;
    }
}

static bool recv_http_headers_counted(int fd,
                                      std::string& buf,
                                      size_t max_buf,
                                      size_t chunk,
                                      long long& bytes_in,
                                      int& last_errno) {
    buf.clear();
    last_errno = 0;

    char tmp[4096];
    while (buf.find("\r\n\r\n") == std::string::npos) {
        ssize_t n = recv(fd, tmp, std::min(chunk, sizeof(tmp)), 0);
        if (n <= 0) {
            last_errno = (n < 0) ? errno : 0;
            return false;
        }
        bytes_in += (long long)n;
        buf.append(tmp, tmp + n);
        if (buf.size() > max_buf) {
            last_errno = EMSGSIZE;
            return false;
        }
    }
    return true;
}

static std::string first_line(const std::string& headers) {
    auto pos = headers.find("\r\n");
    if (pos == std::string::npos) return headers;
    return headers.substr(0, pos);
}

// Fix for libc++: use explicit stream-state check
static bool parse_method_path(const std::string& request_line, std::string& method, std::string& path) {
    std::istringstream iss(request_line);
    std::string version;
    if (!(iss >> method >> path >> version)) return false;
    return true;
}

static bool client_wants_close(const std::string& headers) {
    std::string lower = headers;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });

    return lower.find("\r\nconnection: close") != std::string::npos ||
           lower.rfind("connection: close", 0) == 0;
}

static std::string build_http_response(const json& http,
                                       bool keep_alive,
                                       int timeout_sec,
                                       int remain,
                                       int status_code,
                                       const std::string& body) {
    std::string server_name = http.value("server-name", std::string("mini-cpp-server/1.0"));
    std::string content_type = http.value("content-type", std::string("text/plain; charset=utf-8"));

    std::ostringstream oss;
    if (status_code == 200) oss << "HTTP/1.1 200 OK\r\n";
    else oss << "HTTP/1.1 " << status_code << " Error\r\n";

    oss << "Server: " << server_name << "\r\n";
    oss << "Content-Type: " << content_type << "\r\n";
    oss << "Content-Length: " << body.size() << "\r\n";

    if (keep_alive) {
        oss << "Connection: keep-alive\r\n";
        oss << "Keep-Alive: timeout=" << timeout_sec << ", max=" << remain << "\r\n";
    } else {
        oss << "Connection: close\r\n";
    }

    oss << "\r\n";
    oss << body;
    return oss.str();
}

static long long extract_seq_from_raw_send_line(const std::string& line) {
    std::istringstream iss(line);
    std::string a, b;
    long long seq = -1;
    iss >> a >> b;
    if (a != "send") return -1;
    if (b.rfind("seq=", 0) != 0) return -1;
    try {
        seq = std::stoll(b.substr(4));
    } catch (...) {
        return -1;
    }
    return seq;
}

static std::string reason_from_recv_failure(int last_errno) {
    if (last_errno == 0) return "client-close";
    if (last_errno == EAGAIN || last_errno == EWOULDBLOCK) return "read-timeout";
    if (last_errno == EMSGSIZE) return "protocol-error";
    return "io-error";
}

// Return a child object if it's an object; otherwise return empty object.
static json get_obj_or_empty(const json& parent, const std::string& key) {
    if (!parent.contains(key)) return json::object();
    const json& v = parent.at(key);
    if (!v.is_object()) return json::object();
    return v;
}

int main(int argc, char* argv[]) {
    const char* role_str = "server";

#ifdef SIGPIPE
    // Prevent SIGPIPE from terminating the process when writing to a closed socket (macOS default behavior).
    signal(SIGPIPE, SIG_IGN);
#endif

    auto cfg = load_config(argc > 1 ? argv[1] : "server-config.json");

    bool daemon = cfg.value("daemon-mode", true);
    std::string mode = cfg.value("mode", "raw");
    std::string ip = cfg.value("listen-ip", std::string("0.0.0.0"));
    int port = cfg.value("port", 9000);


    // --- Enhanced startup logs (startup only; runtime logic unchanged) ---
    {
        bool tcp_keepalive_cfg = cfg.value("tcp-keep-alive", false);
        HbConfig hb_start = load_hb_config(cfg);
        std::string hb_dir_str = (cfg.contains("heartbeat") ? cfg["heartbeat"].value("direction", "bidirectional")
                                                           : std::string("bidirectional"));

        std::cout << "[Server] Starting mini-tcp-server-heartbeat" << std::endl;
        std::cout << "[Server] Role            : server" << std::endl;
        std::cout << "[Server] Mode            : " << mode << std::endl;
        std::cout << "[Server] Listen          : " << ip << ":" << port << std::endl;
        std::cout << "[Server] TCP KeepAlive   : " << (tcp_keepalive_cfg ? "enabled" : "disabled") << std::endl;
        std::cout << std::endl;
        std::cout << "[HB] enabled=" << (hb_start.enable ? "true" : "false") << std::endl;
        std::cout << "[HB] direction=" << hb_dir_str << std::endl;
        std::cout << "[HB] interval=" << hb_start.interval_ms << "ms" << std::endl;
        std::cout << "[HB] timeout=" << hb_start.timeout_ms << "ms" << std::endl;
        std::cout << "[HB] max-missed=" << hb_start.max_missed << std::endl;
        std::cout << std::endl;

        // Enforce mode-direction constraints early.
        validate_mode_hb_or_exit(mode, hb_start.direction);

        std::cout << "[Server] Waiting for client connection..." << std::endl;
    }
    // --- End enhanced startup logs ---

    // Runtime heartbeat direction string for symmetric HB logs.
    const std::string hb_dir_str = (cfg.contains("heartbeat") ? cfg["heartbeat"].value("direction", "bidirectional")
                                                       : std::string("bidirectional"));



    json sockcfg = get_obj_or_empty(cfg, "socket");
    int backlog = sockcfg.value("listen-backlog", 16);
    bool reuse = sockcfg.value("reuse-address", true);

    json logging = get_obj_or_empty(cfg, "logging");
    bool log_enable = logging.value("enable", true);
    bool log_lifecycle = logging.value("log-connection-lifecycle", true);
    bool log_each_http = logging.value("log-each-http-request", true);

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }

    if (reuse) {
        int yes = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    if (bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(listen_fd, backlog) < 0) {
        perror("listen");
        return 1;
    }

    if (log_enable) {
        std::cout << "[Server] Listening on " << ip << ":" << port
                  << " mode=" << mode << std::endl;
    }

    do {
        sockaddr_in peer{};
        socklen_t peer_len = sizeof(peer);
        int fd = accept(listen_fd, (sockaddr*)&peer, &peer_len);
        if (fd < 0) continue;

        char peer_ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof(peer_ip));
        int peer_port = ntohs(peer.sin_port);
        std::string remote = std::string(peer_ip) + ":" + std::to_string(peer_port);

        if (cfg.value("tcp-keep-alive", false)) {
            set_tcp_keepalive(fd);
        }

                // Spawn a detached thread per accepted connection so keep-alive sessions
        // do not block the accept loop (required for concurrent /__hb heartbeats).
        auto session_worker = [fd, remote, cfg, mode, log_enable, hb_dir_str, role_str, log_lifecycle, log_each_http]() mutable {
            auto conn_start = Clock::now();
                    auto last_activity = conn_start;

                    long long bytes_in = 0;
                    long long bytes_out = 0;
                    long long requests = 0;
                    std::string close_reason = "client-close";


            if (mode == "raw") {
                json raw = get_obj_or_empty(cfg, "raw");
                set_recv_timeout(fd, raw.value("recv-timeout-sec", 0));
                long long max_msgs = raw.value("keep-alive-max-messages", 0LL);

                HbConfig hb = load_hb_config(cfg);
                const Role role = Role::Server;
                const std::string hb_prefix = "HB|";

                if (log_enable) {
                    std::cout << "[HB] enabled=" << (hb.enable ? "true" : "false")
                              << " mode=raw direction=" << (cfg.contains("heartbeat") ? cfg["heartbeat"].value("direction", "bidirectional") : std::string("bidirectional"))
                              << " interval=" << hb.interval_ms << "ms timeout=" << hb.timeout_ms << "ms"
                              << " max-missed=" << hb.max_missed
                              << std::endl;
                }

                std::atomic<bool> running{true};
                std::mutex send_mu;
                std::mutex hb_mu;
                // RTT must use a monotonic clock. The timestamp sent on the wire is
                // wall-clock epoch time and is intentionally kept separate.
                std::unordered_map<long long, long long> ping_sent_ms;
                std::atomic<long long> last_ok_ms{now_ms()};
                std::atomic<int> missed{0};

                auto safe_send = [&](const std::string& line) -> bool {
                    std::lock_guard<std::mutex> lk(send_mu);
                    return send_all_counted(fd, line, bytes_out);
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
                        if (log_enable) std::cout << "[HB][TX] PING role=server dir=" << hb_dir_str << " seq=" << hb_seq << " ts=" << ts << std::endl;
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
                while (running.load() && (max_msgs == 0 || requests < max_msgs)) {
                    std::string line;
                    if (!recv_line_counted(fd, line, bytes_in, last_errno)) {
                        close_reason = reason_from_recv_failure(last_errno);
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
                                    if (log_enable) std::cout << "[HB][RX] PING role=server dir=" << hb_dir_str << " seq=" << seq << " ts=" << ts_msg << std::endl;
                                    std::string pong = "HB|PONG|" + std::to_string(seq) + "|" + std::to_string(now_epoch_ms()) + "\n";
                                    if (log_enable) std::cout << "[HB][TX] PONG role=server dir=" << hb_dir_str << " seq=" << seq << std::endl;
                                    bool ok = safe_send(pong);
                                    if (!ok) {
                                        running.store(false);
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
                                if (log_enable) {
                                    if (rtt >= 0) {
                                        std::cout << "[HB][RX] PONG role=server dir=" << hb_dir_str << " seq=" << seq << " ts=" << ts_msg << " rtt=" << rtt << "ms" << std::endl;
                                    } else {
                                        std::cout << "[HB][RX] PONG role=server dir=" << hb_dir_str << " seq=" << seq << " ts=" << ts_msg << " rtt=?ms" << std::endl;
                                    }
                                }
                            }
                        }
                        continue;
                    }

                    if (starts_with(t, "seq=")) {
                        long long seq = -1;
                        try { seq = std::stoll(t.substr(4)); } catch (...) { seq = -1; }
                        if (seq >= 0) {
                            if (log_enable) std::cout << "[RAW][RX] role=" + std::string(role_str) + " seq=" << seq << std::endl;
                            std::string reply = "seq=" + std::to_string(seq) + "\n";
                            if (log_enable) std::cout << "[RAW][TX] role=" + std::string(role_str) + " seq=" << seq << std::endl;
                            if (!safe_send(reply)) {
                                close_reason = "io-error";
                                break;
                            }
                            requests++;
                            last_activity = Clock::now();
                            if (max_msgs > 0 && requests >= max_msgs) {
                                close_reason = "max-requests";
                                break;
                            }
                            continue;
                        } else {
                            std::cerr << "[RAW][RX] WARN unexpected: " << t << std::endl;
                            continue;
                        }
                    }

                    std::cerr << "[RAW][RX] WARN unknown line: " << t << std::endl;
                }

                running.store(false);
                if (hb_tx_thread.joinable()) hb_tx_thread.join();
                if (hb_watchdog.joinable()) hb_watchdog.join();

                close(fd);

                if (log_enable && log_lifecycle) {
                    auto now = Clock::now();
                    auto duration_ms =
                        std::chrono::duration_cast<std::chrono::milliseconds>(now - conn_start).count();
                    std::cout << "[Server] Connection closed reason=" << close_reason
                              << " duration_ms=" << duration_ms
                              << " requests=" << requests
                              << " bytes_in=" << bytes_in
                              << " bytes_out=" << bytes_out
                              << std::endl;
                }
                return;
            }


                    if (mode == "websocket") {
                        json ws = get_obj_or_empty(cfg, "websocket");
                        std::string ws_path = ws.value("path", std::string("/ws"));

                    // WebSocket I/O counters (best-effort).
                    long long bytes_in = 0; long long bytes_out = 0;

                        // WebSocket handshake (server side). Path is configurable via config.websocket.path.
                        int ws_errno = 0;
                        if (!ws_handshake_server(fd, ws_path, bytes_in, bytes_out, ws_errno)) {
                            close_reason = "ws-handshake-failed";
                            // If handshake failed, the fd may already be closed by the peer.
                            return;
                        }

                        HbConfig hb = load_hb_config(cfg);
                        const Role role = Role::Server;
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
                        // RTT bookkeeping uses steady-clock milliseconds; protocol
                        // timestamps use epoch milliseconds.
                        std::unordered_map<long long, long long> ping_sent_ms;
                        std::atomic<long long> last_ok_ms{now_ms()};
                        std::atomic<int> missed{0};

                        // Server frames are NOT masked.
                        auto safe_send = [&](const std::string& line) -> bool {
                            std::lock_guard<std::mutex> lk(send_mu);
                            return ws_send_text_frame(fd, line, /*mask=*/false, bytes_out);
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
                                if (log_enable) std::cout << "[HB][TX] PING role=server dir=" << hb_dir_str << " seq=" << hb_seq << " ts=" << ts << std::endl;
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
                                if (!ws_recv_text_frame(fd, msg, /*is_server_side=*/true, bytes_in, last_errno)) {
                                    return false;
                                }
                                ws_buf += msg;
                                if (ws_buf.size() > 1024 * 1024) { last_errno = EMSGSIZE; return false; }
                            }
                        };

                        while (true) {
                            std::string line;
                            if (!ws_recv_line(line)) {
                                close_reason = reason_from_recv_failure(last_errno);
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
                                            if (log_enable) std::cout << "[HB][RX] PING role=server dir=" << hb_dir_str << " seq=" << seq << " ts=" << ts_msg << std::endl;

                                            std::string pong = "HB|PONG|" + std::to_string(seq) + "|" + std::to_string(now_epoch_ms()) + "\n";
                                            if (hb_can_tx_pong(role, hb.direction)) {
                                                if (log_enable) std::cout << "[HB][TX] PONG role=server dir=" << hb_dir_str << " seq=" << seq << std::endl;
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
                                                auto it = ping_sent_ms.find(seq);
                                                if (it != ping_sent_ms.end()) { sent = it->second; ping_sent_ms.erase(it); }
                                            }
                                            if (sent >= 0) {
                                                long long rtt = now - sent;
                                                if (log_enable) std::cout << "[HB][RX] PONG role=server dir=" << hb_dir_str << " seq=" << seq << " ts=" << ts_msg << " rtt=" << rtt << "ms" << std::endl;
                                            } else {
                                                if (log_enable) std::cout << "[HB][RX] PONG role=server dir=" << hb_dir_str << " seq=" << seq << " ts=" << ts_msg << " rtt=?ms" << std::endl;
                                            }
                                            last_ok_ms.store(now);
                                            missed.store(0);
                                        }
                                        continue;
                                    }
                                }
                            }

                            // RAW echo path: accept seq=... lines (same behavior as RAW mode).
                            if (starts_with(t, "seq=")) {
                                requests++;
                                if (log_enable) std::cout << "[WS][RX] role=server seq=" << t.substr(4) << std::endl;
                                std::string resp = t + "\n";
                                if (log_enable) std::cout << "[WS][TX] role=server seq=" << t.substr(4) << std::endl;
                                safe_send(resp);
                                continue;
                            }

                            // Ignore unknown lines in websocket mode.
                        }

                        running.store(false);
                        if (hb_tx_thread.joinable()) hb_tx_thread.join();
                        if (hb_watchdog.joinable()) hb_watchdog.join();
                    }

            if (mode == "http" || mode == "http-sse") {
                        // HB config for HTTP endpoints (/__hb and /__hb/sse)
                        const Role role = Role::Server;
                        HbConfig hb = load_hb_config(cfg);
                        const char* hb_dir_str = hb_direction_to_string(hb.direction);

                        json http = get_obj_or_empty(cfg, "http");
                        bool ka = http.value("keep-alive", true);
                        int timeout_sec = http.value("keep-alive-timeout-sec", 30);
                        int max_req = http.value("keep-alive-max-requests", 100);
                        size_t chunk = (size_t)http.value("read-buffer-size", 4096);
                        size_t max_buf = (size_t)http.value("max-request-buffer-size", 262144);

                        if (ka) set_recv_timeout(fd, timeout_sec);

                        std::string headers;
                        int last_errno = 0;

                        while (requests < max_req) {
                            if (!recv_http_headers_counted(fd, headers, max_buf, chunk, bytes_in, last_errno)) {
                                close_reason = reason_from_recv_failure(last_errno);
                                break;
                            }

                            auto http_req_start = Clock::now();

                            // RX payload (request headers)
                            if (log_enable && log_each_http) {
                                print_payload_visible_ascii("Server", "HTTP", "RX", headers);
                            }

                            requests++;
                            last_activity = Clock::now();

                            std::string line = first_line(headers);
                            std::string method = "GET";
                            std::string path = "/";

                            if (!parse_method_path(line, method, path)) {
                                close_reason = "protocol-error";
                                break;
                            }

                            bool close_requested = client_wants_close(headers);
                            bool keep = ka && !close_requested;

                            int status = 200;
                            std::string body = "";

            // Heartbeat endpoints (HTTP /__hb and SSE /__hb/sse). Only active in HTTP mode.
            const std::string target = path;
            const std::string path_only = http_path_only(target);

            if (path_only == "/__hb/sse") {
                // SSE: server-initiated heartbeat.
                // IMPORTANT: disable recv timeout for SSE. This connection is write-dominant.
                set_recv_timeout(fd, 0);

                // Keep the HTTP connection open and stream events.
                std::string hdr;
                hdr += "HTTP/1.1 200 OK\r\n";
                hdr += "Server: mini-cpp-server/1.0\r\n";
                hdr += "Content-Type: text/event-stream\r\n";
                hdr += "Cache-Control: no-cache\r\n";
                hdr += "Connection: keep-alive\r\n";
                hdr += "\r\n";
                if (!send_all_counted(fd, hdr, bytes_out)) break;

                // Emit an initial SSE comment line to flush data to clients quickly
                {
                    // Use LF for SSE framing (data/comment lines end with \n; event ends with a blank \n).
                    std::string hello = ":ok\n\n";
                    if (!send_all_counted(fd, hello, bytes_out)) break;
                }

                uint64_t hb_seq = 0;
                while (true) {
                    // Keep payload consistent with HTTP heartbeat (/__hb): HEARTBEAT=PONG seq=... ts=...
                    if (hb.enable) {
                        hb_seq++;
                        long long ts = now_epoch_ms();
                        std::ostringstream oss;
                        // Keep payload consistent with HTTP heartbeat (/__hb): "HEARTBEAT=PONG ...\n"
                        // and keep SSE framing spec-compliant using LF newlines.
                        oss << "data: HEARTBEAT=PONG seq=" << hb_seq << " ts=" << ts << "\n\n";
                        std::string ev = oss.str();

                        if (log_enable) {
                            std::cout << "[HB][TX] PONG role=server dir=" << hb_dir_str
                                      << " seq=" << hb_seq << " ts=" << ts << std::endl;
                        }

                        if (!send_all_counted(fd, ev, bytes_out)) break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(std::max(200, hb.interval_ms)));
                }
                break; // close this connection
            }

                        if (path_only == "/__hb") {
                // HTTP heartbeat endpoint.
                uint64_t seqn = 0;
                uint64_t ts_in = 0;
                (void)http_query_u64(target, "seq", seqn);
                (void)http_query_u64(target, "ts", ts_in);

                if (hb.enable) {
                    if (log_enable) {
                        std::cout << "[HB][RX] PING role=server dir=" << hb_dir_str
                                  << " seq=" << seqn << " ts=" << ts_in << std::endl;
                    }
                    if (hb_can_tx_pong(role, hb.direction)) {
                        long long ts_out = now_epoch_ms();
                        std::ostringstream oss;
                        // Keep payload consistent across HTTP and SSE: no server_elapsed/rtt hint.
                        oss << "HEARTBEAT=PONG seq=" << seqn << " ts=" << ts_out << "\n";
                        status = 200;
                        body = oss.str();
                        if (log_enable) {
                            std::cout << "[HB][TX] PONG role=server dir=" << hb_dir_str
                                      << " seq=" << seqn << " ts=" << ts_out
                                      << std::endl;
                        }
                    } else {
                        status = 403;
                        body = "Forbidden\n";
                    }
                } else {
                    status = 404;
                    body = "Not Found\n";
                }
            }


                            std::string resp = build_http_response(
                                http, keep, timeout_sec, max_req - (int)requests, status, body);

                            // TX payload (response)
                            if (log_enable && log_each_http) {
                                print_payload_visible_ascii("Server", "HTTP", "TX", resp);
                            }

                            if (!send_all_counted(fd, resp, bytes_out)) {
                                close_reason = "io-error";
                                break;
                            }

                            headers.clear();

                            if (!keep) {
                                close_reason = "server-close";
                                break;
                            }

                            if (requests >= max_req) {
                                close_reason = "max-requests";
                                break;
                            }
                        }

                        close(fd);

                        if (log_enable && log_lifecycle) {
                            auto now = Clock::now();
                            auto duration_ms =
                                std::chrono::duration_cast<std::chrono::milliseconds>(now - conn_start).count();
                            auto idle_ms =
                                std::chrono::duration_cast<std::chrono::milliseconds>(now - last_activity).count();

                            std::cout << "[Server] Conn closed remote=" << remote
                                      << " requests=" << requests
                                      << " duration=" << duration_ms << "ms"
                                      << " bytes-in=" << bytes_in
                                      << " bytes-out=" << bytes_out
                                      << " idle=" << idle_ms << "ms"
                                      << " reason=" << close_reason
                                      << std::endl;
                        }
                        return;
                    }

                    close(fd);

        };
        std::thread(std::move(session_worker)).detach();
} while (daemon);

    close(listen_fd);
    return 0;
}
