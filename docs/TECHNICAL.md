# 技術文檔

## 架構設計

### 概覽
本項目實現了一個基於 eBPF/XDP 的三層流量過濾系統：
1. **HTTP 層**: 明文 HTTP Host 頭部檢測
2. **TLS 層**: TLS ClientHello SNI 擴展檢測
3. **DNS 層**: DNS 查詢檢測和污染

### 為什麼選擇 eBPF/XDP?

#### XDP (eXpress Data Path)
XDP 是 Linux 內核提供的高性能數據包處理框架，在以下位置執行：

```
網絡數據包流向:
NIC → 驅動 → XDP (←我們在這裡) → 網絡棧 → Socket
```

**優勢**:
- 在數據包進入內核網絡棧**之前**處理
- 零拷貝：數據包不需要從內核拷貝到用戶空間
- 低延遲：避免了大量內核處理
- 高性能：可以達到線速處理

#### eBPF (extended Berkeley Packet Filter)
eBPF 是一個在內核中運行沙箱程序的框架：
- 安全：eBPF 驗證器確保程序不會崩潰內核
- 高效：即時編譯為本地機器碼
- 靈活：可以動態加載和卸載

### 關鍵技術決策

#### 1. 不使用 TUN/TAP
**原因**: 
- TUN/TAP 需要在用戶空間重新注入數據包
- 性能開銷大
- 需要配置路由表

**XDP 方案**:
- 內核空間直接處理
- 無需用戶空間交互
- 性能開銷極小

#### 2. 不使用 iptables/nftables
**原因**:
- 這些工具在網絡棧較深的位置工作
- L7 過濾需要額外模塊且性能不佳
- 配置複雜

**XDP 方案**:
- 在驅動層直接過濾
- 自定義協議解析邏輯
- 單一程序統一管理

#### 3. SNI 檢測而非 MITM
**原因**:
- MITM 需要證書注入，用戶體驗差
- 性能開銷巨大（需要完整 TLS 解密）
- 實現複雜

**SNI 方案**:
- TLS ClientHello 中的 SNI 是明文
- 無需證書，無需解密
- 性能開銷極小
- 足夠用於域名過濾場景

## 數據結構

### eBPF Maps

#### 1. blocked_domains (HASH)
```c
key: char[128]    // 域名字符串（固定 128 字節）
value: uint32     // 標記（1 = 阻斷）
```

用途：存儲要阻斷的域名列表

#### 2. stats (ARRAY)
```c
key: uint32       // 統計類型索引
value: uint64     // 計數器
```

統計類型：
- 0: 總數據包數
- 1: 阻斷數據包數
- 2: HTTP 數據包數
- 3: TLS 數據包數
- 4: DNS 數據包數

#### 3. config_map (ARRAY)
```c
key: uint32       // 固定為 0
value: struct config {
    uint32 dns_mode;  // 0 = DROP, 1 = POISON
}
```

用途：存儲運行時配置

## 協議解析

### HTTP 解析

#### 數據包結構
```
Ethernet (14) | IP (20) | TCP (20+) | HTTP Payload
```

#### 解析步驟
1. 驗證 TCP 目標端口 80
2. 檢查 HTTP 方法（GET/POST/PUT/HEAD）
3. 在前 512 字節內搜索 "Host: " 字符串
4. 提取 Host 值直到 \r\n
5. 與阻斷列表比對

#### 限制
- 僅檢查前 512 字節（防止 eBPF 循環限制）
- 不支持分片的 HTTP 頭部

### TLS/SNI 解析

#### TLS ClientHello 結構
```
TLS Record Header (5 bytes)
├─ Content Type: 0x16 (Handshake)
├─ Version: 0x03 0x01/02/03
└─ Length: 2 bytes

Handshake Protocol (4+ bytes)
├─ Handshake Type: 0x01 (ClientHello)
├─ Length: 3 bytes
├─ Version: 2 bytes
├─ Random: 32 bytes
├─ Session ID: 1 + N bytes
├─ Cipher Suites: 2 + N bytes
├─ Compression Methods: 1 + N bytes
└─ Extensions: 2 + N bytes
    └─ SNI Extension (Type 0x0000)
        ├─ Extension Length: 2 bytes
        ├─ SNI List Length: 2 bytes
        ├─ Name Type: 1 byte (0x00)
        ├─ Name Length: 2 bytes
        └─ Server Name: N bytes  ← 提取這個
```

#### 解析步驟
1. 驗證 TCP 目標端口 443
2. 檢查 TLS Record Type (0x16) 和版本 (0x03 0x??)
3. 檢查 Handshake Type (0x01 = ClientHello)
4. 跳過固定字段到擴展部分
5. 遍歷擴展尋找 Type 0x0000 (SNI)
6. 提取 Server Name
7. 與阻斷列表比對

#### 限制
- 僅支持未壓縮的標準 ClientHello
- 不支持 ECH/ESNI (加密的 SNI)
- 最多檢查 20 個擴展（eBPF 循環限制）

### DNS 解析

#### DNS 數據包結構
```
Ethernet (14) | IP (20) | UDP (8) | DNS
```

#### DNS 頭部結構
```
DNS Header (12 bytes)
├─ Transaction ID: 2 bytes
├─ Flags: 2 bytes
│  ├─ QR (bit 15): 0 = Query, 1 = Response
│  ├─ Opcode (bit 11-14): 0 = Standard Query
│  ├─ AA (bit 10): Authoritative Answer
│  ├─ TC (bit 9): Truncated
│  ├─ RD (bit 8): Recursion Desired
│  ├─ RA (bit 7): Recursion Available
│  └─ RCODE (bit 0-3): Response Code
├─ Question Count: 2 bytes
├─ Answer Count: 2 bytes
├─ Authority Count: 2 bytes
└─ Additional Count: 2 bytes

Question Section
├─ QNAME: variable (標籤格式)
│  例: 3www6google3com0
│      → www.google.com
├─ QTYPE: 2 bytes
└─ QCLASS: 2 bytes
```

#### 解析步驟
1. 驗證 UDP 目標端口 53
2. 檢查 QR bit（必須為 0，即查詢）
3. 檢查 Question Count > 0
4. 解析 QNAME 標籤格式為域名字符串
5. 與阻斷列表比對
6. 根據模式執行 DROP 或 POISON

#### DNS 標籤格式解析
```
標籤格式: [長度][字符...][長度][字符...]...[0]

例子:
輸入: 07 65 78 61 6D 70 6C 65 03 63 6F 6D 00
      ↓  ↓           ↓        ↓  ↓     ↓  ↓
      7  example      3        com     0
結果: example.com
```

實現邏輯：
```c
while (length_byte != 0) {
    if (length > 63) return error;  // 標籤長度限制
    copy length bytes;
    add '.' separator;
}
```

#### DNS 污染實現

**POISON 模式**流程：
1. 檢測到匹配的查詢
2. 原地修改數據包：
   - 交換源/目標 MAC 地址
   - 交換源/目標 IP 地址
   - 交換源/目標 UDP 端口
   - 修改 DNS Flags：
     - QR = 1 (響應)
     - RCODE = 3 (NXDOMAIN)
   - 重新計算校驗和
3. 使用 XDP_TX 發回數據包

**優勢**:
- 客戶端立即收到 NXDOMAIN 響應
- 無需等待超時
- 用戶體驗更好

**DROP 模式**流程：
1. 檢測到匹配的查詢
2. 返回 XDP_DROP
3. 數據包直接丟棄

**劣勢**:
- 客戶端需要等待超時
- 用戶體驗較差

## XDP 動作類型

```c
XDP_DROP    // 丟棄數據包
XDP_PASS    // 繼續傳遞到網絡棧
XDP_TX      // 從接收接口發回數據包（用於 DNS 污染）
XDP_REDIRECT // 重定向到其他接口（未使用）
XDP_ABORTED  // 錯誤，丟棄數據包（未使用）
```

## XDP 模式

### Generic Mode (使用中)
```bash
link.XDPGenericMode
```
- 在內核網絡棧較晚階段執行
- 兼容性最好，支持所有網卡
- 性能中等

### Native Mode
```bash
link.XDPDriverMode
```
- 在網卡驅動層執行
- 需要網卡驅動支持
- 性能最高

### Offload Mode
```bash
link.XDPOffloadMode
```
- 在網卡硬件執行
- 需要智能網卡（SmartNIC）
- 性能極高但設備昂貴

## 性能考量

### eBPF 限制
1. **循環限制**: 
   - eBPF 驗證器限制循環次數
   - 使用 `#pragma unroll` 展開循環
   - 限制搜索範圍（如 512 字節、20 個擴展）

2. **棧空間限制**:
   - eBPF 棧空間有限（512 字節）
   - 使用固定大小的緩衝區
   - 避免深度遞歸

3. **指令數限制**:
   - 早期內核限制 4096 條指令
   - 現代內核放寬到 100 萬條
   - 保持程序簡潔

### 優化技巧
1. **早期退出**: 盡早檢查並返回
2. **邊界檢查**: 每次指針訪問前檢查 `data_end`
3. **內聯函數**: 使用 `static __always_inline`
4. **原子操作**: 統計計數使用 `__sync_fetch_and_add`

## 安全考量

### eBPF 安全性
- eBPF 驗證器確保程序安全
- 不能造成內核崩潰
- 不能訪問任意內存

### 繞過方法
用戶可能使用以下方法繞過：
1. **加密 SNI (ECH/ESNI)**: 未來 TLS 標準
2. **DoH/DoT**: 加密的 DNS 協議
3. **VPN/代理**: 隧道流量
4. **自定義端口**: 使用非標準端口
5. **IP 直連**: 不使用域名

### 緩解措施
- 結合多層防護
- 定期更新域名列表
- 監控異常流量模式
- 阻斷已知 DoH/VPN 服務器

## 調試技巧

### 1. 查看 eBPF 驗證器日誌
```bash
sudo bpftool prog load traffic_filter.o /sys/fs/bpf/filter
```

### 2. 追蹤 eBPF 程序
```bash
sudo bpftool prog tracelog
```

### 3. 查看 Map 內容
```bash
# 列出所有 Maps
sudo bpftool map list

# 查看 Map 內容
sudo bpftool map dump id <ID>
```

### 4. 抓包驗證
```bash
# 抓取接口流量
sudo tcpdump -i eth0 -nn -X port 443

# 抓取 DNS 流量
sudo tcpdump -i eth0 -nn port 53
```

### 5. 使用 debug 模式
```bash
sudo ./traffic-filter -iface eth0 -domains "example.com" -debug
```

## 常見問題

### Q: 為什麼 HTTPS 流量沒有被阻斷？
A: 可能原因：
1. 使用了 ECH/ESNI (加密 SNI)
2. 使用了 IP 直連
3. 域名不在阻斷列表中
4. XDP 程序未正確附加

驗證：使用 tcpdump 抓包查看 TLS ClientHello

### Q: DNS 污染沒有生效？
A: 可能原因：
1. 客戶端使用 DoH/DoT
2. DNS 查詢使用非 53 端口
3. 域名格式不匹配

驗證：使用 `dig` 直接查詢並抓包

### Q: 性能影響如何？
A: XDP Generic 模式下：
- CPU 使用率增加 < 5%
- 延遲增加 < 1ms
- 吞吐量影響可忽略

Native 模式性能更好。

### Q: 如何在生產環境部署？
A: 建議：
1. 先在測試環境驗證
2. 使用 systemd 服務管理
3. 設置自動重啟
4. 監控統計數據
5. 定期更新域名列表

## 未來改進

1. **IPv6 DNS 污染支持**
2. **動態域名列表更新 API**
3. **更多統計維度**（源 IP、時間分布等）
4. **日誌記錄到文件**
5. **支持正則表達式域名匹配**
6. **Web 管理界面**
7. **分布式部署支持**

## 參考資料

- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [Cilium eBPF Library](https://github.com/cilium/ebpf)
- [BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/)
- [RFC 6066 - TLS Extensions (SNI)](https://tools.ietf.org/html/rfc6066)
- [RFC 1035 - DNS Protocol](https://tools.ietf.org/html/rfc1035)
