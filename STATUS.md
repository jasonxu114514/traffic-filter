# Traffic Filter — 當前狀態與問題分析

## 架構演進

### v1: eBPF/XDP (已棄用)
- C 語言內核程序 + Go 用戶空間控制平面
- XDP hook 在網卡驅動層攔截封包
- **問題**: clang 19 BPF backend 編譯 crash (loop unroll / branch range / memcpy builtin)

### v2: AF_PACKET (已棄用)  
- 純 Go，AF_PACKET raw socket 捕獲 + 注入 RST/DNS poison
- 通過 AF_PACKET 發送偽造 RST 封包
- **問題**: AF_PACKET 發送的封包走網卡 → 交換機，不會回到本機 TCP stack

### v3: AF_INET raw socket (當前，仍失敗)
- AF_PACKET 捕獲 + AF_INET SOCK_RAW IPPROTO_RAW 注入
- 用 `IP_HDRINCL` 自行構造 IP header 發送 RST/DNS poison
- **問題**: 同上 — raw socket 輸出封包不經本機 TCP stack 交付

## 核心技術問題

```
┌─────────────────────────────────────────────────────────┐
│                    本機 (我們的程式在此)                    │
│                                                         │
│  curl ──→ kernel TCP ──→ NIC(ens18) ──→ 外部網路         │
│             ↑                                          │
│        AF_PACKET 捕獲 ✓                                │
│                                                         │
│  我們的 RST 注入:                                        │
│    AF_INET raw socket ──→ kernel IP output ──→ NIC ──→ 外部
│                                                         │
│  ✗ RST 封包走「輸出」路徑，不會送到本機 TCP 輸入             │
│  ✗ 本機 TCP stack 永遠看不到我們偽造的 RST                 │
│  ✗ curl 的 socket 不會被 reset                          │
└─────────────────────────────────────────────────────────┘
```

**結論**: 任何在 userspace 發送偽造封包的方法（AF_PACKET / AF_INET raw socket），
都無法讓偽造封包被**本機 TCP stack** 接受。這是 Linux 網路棧設計的根本限制。

## 真正可行的方案

### 方案 A: 修復 eBPF/XDP（推薦）
使用 XDP 在 NIC 驅動層直接 DROP 封包，這是唯一能在本機生效且無需 tun/iptables 的方案。

修復 clang 19 編譯問題的具體做法：
1. 移除 `-Werror` 中導致 crash 的 flag: `-Wno-pass-failed=transform-warning`
2. 移除所有自訂 `mem_cpy`，改用 `__builtin_memcpy` (BPF backend 支援)
3. 將大的 `#pragma unroll` 迴圈拆分為多個小函數
4. 或降級 clang 到 v14-v17（這些版本的 BPF backend 較穩定）

### 方案 B: 中間網關
在一台獨立的 Linux 機器/VM 上運行，作為透明橋接/路由器：
```
Client ──→ [Filter Machine] ──→ Internet
```
- Filter 在橋接模式下捕獲所有流量
- AF_PACKET + RST 注入 → RST 送給 Client（跨機器，可以生效）
- 或直接用 XDP

### 方案 C: NFQUEUE + iptables（最簡單但用了 iptables）
```bash
iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0
iptables -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 0
iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0
```
Go 程式用 `github.com/florianl/go-nfqueue` 接收封包並決定 ACCEPT/DROP。
- 這是唯一能在 userspace **真正丟棄本機封包** 的方法
- 但依賴 iptables

## 當前代碼結構

```
traffic-filter/
├── main.go        # 入口，事件迴圈
├── config.go      # CLI 參數解析
├── capture.go     # AF_PACKET 捕獲 + AF_INET RST/DNS poison 注入
├── filter.go      # 封包解析 + 規則比對 (HTTP/TLS/DNS/IP)
├── go.mod
├── Makefile
└── build.sh
```

### 功能覆蓋

| 功能 | 代碼狀態 | 實際效果 |
|------|---------|---------|
| HTTP Host 檢測 | ✓ 實作 | ✗ 無法阻止 (RST 不生效) |
| TLS SNI 檢測 | ✓ 實作 | ✗ 無法阻止 (RST 不生效) |
| DNS 域名檢測 | ✓ 實作 | ✗ 無法阻止 (poison 不生效) |
| IP 全阻斷 | ✓ 實作 | ✗ 無法阻止 |
| IP:Port 阻斷 | ✓ 實作 | ✗ 無法阻止 |
| TCP RST 注入 | ✓ 實作 | ✗ 本機不收偽造 RST |
| DNS poison 注入 | ✓ 實作 | ✗ 本機不收偽造 DNS |
| 統計輸出 | ✓ 實作 | ✓ 正常 |
| CLI 參數 | ✓ 實作 | ✓ 正常 |

### 驗證: 程式確實偵測到目標流量

```
DEBU blocked TLS   tls_sni=example.com      ← 偵測成功
DEBU TCP RST injected  rst=sent              ← RST 已發送
DEBU blocked HTTP http_host=example.com      ← 偵測成功
DEBU TCP RST injected  rst=sent              ← RST 已發送
```

偵測和注入代碼都正常運作，問題純粹是注入的封包無法被本機 TCP stack 接受。

## 下一步建議

1. **直接修復 eBPF 編譯** — 只需調整編譯參數，核心邏輯不需改變
2. **或接受最小 iptables** — 只用一條 NFQUEUE 規則，其他邏輯全在 Go
3. **或部署到獨立機器** — 中間網關模式，RST 注入跨機器可生效
