# 流量過濾器 (Traffic Filter)

基於 eBPF/XDP 的高性能網絡流量檢測和阻斷工具，可在內核層面攔截包含特定域名的 HTTP、HTTPS 和 DNS 請求。

## 功能特性

- ✅ **內核層面攔截**: 使用 eBPF/XDP 在數據包到達網絡棧之前進行過濾
- ✅ **HTTP 流量檢測**: 解析 HTTP Host 頭部
- ✅ **HTTPS/TLS 流量檢測**: 解析 TLS ClientHello 的 SNI (Server Name Indication)
- ✅ **DNS 污染**: 支持 DNS 查詢攔截和污染（返回 NXDOMAIN）
- ✅ **零拷貝性能**: 數據包在內核空間直接處理，無需拷貝到用戶空間
- ✅ **實時統計**: 實時顯示總流量、阻斷流量、HTTP/TLS/DNS 流量統計
- ✅ **自定義域名列表**: 支持阻斷任意域名
- ✅ **靈活的 DNS 模式**: 可選擇直接丟棄或返回 NXDOMAIN 響應

## 技術架構

```
用戶空間 (Go)
├── 加載 eBPF 程序
├── 管理阻斷域名列表
├── 配置 DNS 處理模式
└── 監控統計信息
     ↕
內核空間 (eBPF/XDP)
├── XDP Hook (網絡驅動層)
├── 解析 Ethernet/IP/TCP/UDP 頭部
├── 檢測 HTTP Host 頭部
├── 檢測 TLS SNI 擴展
├── 解析 DNS 查詢並污染響應
└── DROP / POISON / PASS 決策
```

## 系統要求

- **操作系統**: Linux x86_64
- **內核版本**: >= 5.4 (支持 eBPF 和 XDP)
- **權限**: root
- **依賴**:
  - clang >= 10
  - llvm
  - libbpf-dev
  - linux-headers

## 安裝依賴

### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) golang-go
```

### RHEL/CentOS/Fedora
```bash
sudo dnf install -y clang llvm libbpf-devel kernel-devel golang
```

## 編譯

### 1. 編譯 eBPF 程序
```bash
cd bpf
clang -O2 -target bpf -c traffic_filter.c -o traffic_filter.o -I/usr/include
```

### 2. 生成 Go 綁定
```bash
go generate ./...
```

### 3. 編譯 Go 程序
```bash
go mod tidy
go build -o traffic-filter
```

## 使用方法

### 基本使用
```bash
# 在 eth0 接口上阻斷 pornhub.com，DNS 使用 DROP 模式
sudo ./traffic-filter -iface eth0 -domains "pornhub.com,www.pornhub.com"

# 使用 DNS 污染模式（返回 NXDOMAIN）
sudo ./traffic-filter -iface eth0 -domains "pornhub.com,www.pornhub.com" -dns-mode poison
```

### 參數說明
- `-iface`: 網絡接口名稱 (默認: eth0)
- `-domains`: 要阻斷的域名列表，逗號分隔
- `-dns-mode`: DNS 處理模式
  - `drop`: 直接丟棄 DNS 查詢包（默認）
  - `poison`: 返回 NXDOMAIN 響應（污染）
- `-debug`: 啟用調試日誌

### 查看網絡接口
```bash
ip link show
```

### 示例輸出
```
INFO[2026-06-22T10:30:00Z] 啟動流量過濾器  dns_mode=poison domains="[pornhub.com www.pornhub.com]" interface=eth0
INFO[2026-06-22T10:30:00Z] 已設置 DNS 模式  dns_mode="POISON (NXDOMAIN)"
INFO[2026-06-22T10:30:00Z] 已添加阻斷域名  domain=pornhub.com
INFO[2026-06-22T10:30:00Z] 已添加阻斷域名  domain=www.pornhub.com
INFO[2026-06-22T10:30:00Z] XDP 程序附加成功  interface=eth0
INFO[2026-06-22T10:30:00Z] 流量過濾器運行中... 按 Ctrl+C 停止
INFO[2026-06-22T10:30:05Z] 流量統計  blocked=15 blocked/s=3 dns=28 dns/s=5 http=45 http/s=9 tls=128 tls/s=25 total=5678 total/s=1135
```

## 工作原理

### HTTP 檢測
1. 檢測 TCP 目標端口 80
2. 解析 HTTP 請求行 (GET/POST/PUT/HEAD)
3. 查找 `Host:` 頭部
4. 提取域名並與阻斷列表比對
5. 匹配則 DROP，否則 PASS

### HTTPS/TLS 檢測
1. 檢測 TCP 目標端口 443
2. 解析 TLS 記錄頭部
3. 驗證是否為 ClientHello (握手第一個包)
4. 解析 TLS 擴展尋找 SNI (Server Name Indication)
5. 提取 SNI 域名並與阻斷列表比對
6. 匹配則 DROP，否則 PASS

### DNS 污染
1. 檢測 UDP 目標端口 53
2. 解析 DNS 頭部，驗證是查詢而非響應
3. 解析 DNS 查詢名稱（支持標籤格式）
4. 提取域名並與阻斷列表比對
5. 匹配則根據模式處理：
   - **DROP 模式**: 直接丟棄 DNS 查詢包
   - **POISON 模式**: 修改數據包為 NXDOMAIN 響應並發回

### 為什麼不需要 MITM?
我們使用 **SNI 檢測** 而非完整的 TLS 解密:
- TLS ClientHello 中的 SNI 是**明文**的
- 在 TLS 握手階段就能識別目標域名
- 無需證書注入或解密流量
- 性能高，延遲低

### DNS 污染 vs DROP
- **DROP 模式**: 客戶端等待超時，體驗較差但實現簡單
- **POISON 模式**: 立即返回 NXDOMAIN，客戶端認為域名不存在，體驗更好

## 性能優勢

與傳統方案對比:

| 方案 | 處理位置 | CPU 使用 | 延遲 | 需要用戶空間拷貝 | DNS 支持 |
|------|----------|----------|------|------------------|----------|
| iptables + L7 filter | 內核網絡棧 | 高 | 中 | 否 | 限制 |
| Squid Proxy | 用戶空間 | 非常高 | 高 | 是 | 需額外配置 |
| dnsmasq | 用戶空間 | 中 | 中 | 是 | 僅 DNS |
| **eBPF/XDP** | **網絡驅動層** | **極低** | **極低** | **否** | **原生支持** |

XDP 在數據包到達網絡棧**之前**就進行處理，避免了大量內核處理開銷。

## 限制與注意事項

1. **SNI 加密 (ECH/ESNI)**: 如果客戶端使用 Encrypted ClientHello，SNI 會被加密，無法檢測
2. **DoH/DoT**: 加密的 DNS 協議（DNS over HTTPS/TLS）無法檢測
3. **IP 直連**: 如果客戶端直接使用 IP 地址而非域名，無法阻斷
4. **端口變化**: 僅檢測 80/443/53 端口，自定義端口不會被檢測
5. **內核版本**: 需要較新的內核支持 eBPF
6. **XDP 模式**: 默認使用 Generic 模式，性能略低於 Native 模式但兼容性更好
7. **DNS 污染限制**: 僅支持 IPv4 DNS 污染，IPv6 DNS 查詢會被 DROP
8. **域名格式**: DNS 解析器不支持壓縮指針，僅支持標準標籤格式

## 故障排除

### 1. 權限錯誤
```
此程序需要 root 權限運行
```
**解決**: 使用 `sudo` 運行

### 2. 接口不存在
```
獲取接口索引失敗: 接口 eth0 不存在
```
**解決**: 使用 `ip link show` 查看正確的接口名稱

### 3. eBPF 驗證失敗
```
加載 eBPF 對象失敗
```
**解決**: 
- 檢查內核版本 `uname -r` (需要 >= 5.4)
- 檢查 BPF 是否啟用 `cat /proc/sys/kernel/unprivileged_bpf_disabled`
- 查看詳細錯誤使用 `-debug` 標誌

### 4. 編譯錯誤
```
fatal error: 'bpf/bpf_helpers.h' file not found
```
**解決**: 安裝 libbpf 開發包
```bash
sudo apt-get install libbpf-dev
```

## 安全考量

- 此工具需要 root 權限，請謹慎使用
- XDP 程序直接處理網絡流量，錯誤可能導致網絡中斷
- 建議先在測試環境驗證
- 阻斷列表應定期更新和審查

## 擴展

### 添加更多域名
修改啟動命令的 `-domains` 參數:
```bash
sudo ./traffic-filter -iface eth0 -domains "domain1.com,domain2.com,domain3.com"
```

### 支持更多端口
修改 `bpf/traffic_filter.c` 中的端口檢測邏輯，添加自定義端口的處理。

### 動態更新域名列表
可以擴展程序添加 HTTP API 或 Unix Socket，實現運行時動態添加/刪除域名。

### 改進 DNS 污染
當前 DNS 污染返回 NXDOMAIN，也可以修改為返回指定的假 IP 地址：
- 修改 `bpf/traffic_filter.c` 中的 `DNS_POISON_IP` 常量
- 調整 `poison_dns_response` 函數構造 A 記錄響應

### 日誌記錄
添加被阻斷連接的詳細日誌，包括源 IP、目標域名等信息。

## 許可證

GPL (因為 eBPF 程序需要)

## 作者

Created with Claude Code
