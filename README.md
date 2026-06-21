# Traffic Filter - eBPF/XDP Network Filter

基於 eBPF/XDP 的網路流量過濾器，可以阻斷本機的 HTTP/TLS/DNS 流量。

## 架構

- **bpf/traffic_filter.c** - eBPF/XDP C 程序 (596 行)，在內核網卡驅動層攔截封包
- **pkg/filter/filter.go** - Go BPF loader，使用 cilium/ebpf 載入 eBPF 程序
- **pkg/config/config.go** - 配置系統，支持域名、IP、IP:Port 阻斷規則
- **cmd/traffic-filter/main.go** - 主程序入口

## 功能特性

- **HTTP Host 阻斷**: 檢測 HTTP Host header
- **TLS SNI 阻斷**: 檢測 TLS ClientHello 中的 SNI
- **DNS 阻斷/Poison**: DROP 或返回 NXDOMAIN
- **IP 阻斷**: 支持 TCP/UDP/ICMP 協議獨立控制 (bitmask)
- **IP:Port 阻斷**: 精確到端口和協議
- **TCP RST 注入**: 通過 XDP_TX 發送 RST 封包
- **統計計數**: 8 個獨立計數器

## 系統需求

### Linux Kernel
- **最低版本**: 5.4+
- **推薦版本**: 5.10+ (更穩定的 BPF 支持)
- 檢查: `uname -r`

### BPF 支持
檢查內核是否啟用 BPF:
```bash
zgrep BPF /proc/config.gz | grep -E "CONFIG_BPF=|CONFIG_BPF_SYSCALL=|CONFIG_XDP_SOCKETS="
```

應該看到:
```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_XDP_SOCKETS=y
```

### 編譯依賴

Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install -y clang-14 llvm-14 libbpf-dev linux-headers-$(uname -r) golang-go
```

RHEL/CentOS:
```bash
sudo dnf install -y clang llvm libbpf-devel kernel-devel golang
```

Arch Linux:
```bash
sudo pacman -S clang llvm libbpf linux-headers go
```

## 編譯

```bash
# 1. 克隆或拉取代碼
git clone <repo> && cd traffic-filter
# 或
git pull

# 2. 檢查 clang 版本
which clang-14 || which clang-17 || which clang

# 3. 編譯
make build
```

編譯步驟:
1. 用 clang-14 編譯 `bpf/traffic_filter.c` → `bpf/traffic_filter.o`
2. 用 `bpf2go` 生成 Go bindings (pkg/filter/bpf_bpfel.go)
3. 編譯 Go 程序 → `traffic-filter` 可執行檔

## 使用

### 基本用法

```bash
# 阻斷特定域名 (HTTP/TLS/DNS)
sudo ./traffic-filter -iface eth0 -domains "example.com,blocked.test"

# 阻斷 IP
sudo ./traffic-filter -iface eth0 -block-ips "1.2.3.4,8.8.8.8"

# 阻斷 IP:Port
sudo ./traffic-filter -iface eth0 -block-ip-ports "1.2.3.4:80:tcp,1.2.3.4:443:tcp"

# DNS poison 模式 (返回 NXDOMAIN 而不是 DROP)
sudo ./traffic-filter -iface eth0 -domains "example.com" -dns-mode poison

# 組合使用
sudo ./traffic-filter \
    -iface eth0 \
    -domains "example.com,ads.com" \
    -block-ips "1.2.3.4" \
    -block-ip-ports "5.6.7.8:80:tcp" \
    -dns-mode poison \
    -ip-mode tcp,udp
```

### 參數說明

- `-iface <name>` - 網卡名稱 (必需)
- `-domains <list>` - 要阻斷的域名列表 (逗號分隔)
- `-block-ips <list>` - 要阻斷的 IP 列表 (逗號分隔)
- `-block-ip-ports <list>` - IP:Port:Protocol 列表，格式: `IP:Port:Proto`
  - Proto: `tcp`, `udp`, `icmp`
  - 範例: `1.2.3.4:80:tcp,1.2.3.4:443:tcp`
- `-dns-mode <mode>` - DNS 處理模式
  - `drop` (默認): 丟棄 DNS 查詢
  - `poison`: 返回 NXDOMAIN 響應
- `-ip-mode <protocols>` - IP 阻斷的協議 (逗號分隔)
  - `tcp`, `udp`, `icmp`
  - 默認: `tcp,udp,icmp` (全部)

### 停止

按 `Ctrl+C` 停止，會顯示統計信息。

## 驗證測試

### 1. 測試 HTTP 阻斷

```bash
# Terminal 1: 啟動 filter
sudo ./traffic-filter -iface eth0 -domains "example.com"

# Terminal 2: 測試
curl http://example.com
# 預期: Connection reset 或 timeout
```

### 2. 測試 TLS 阻斷

```bash
curl https://example.com
# 預期: Connection reset 或 SSL error
```

### 3. 測試 DNS 阻斷

```bash
# DROP 模式
sudo ./traffic-filter -iface eth0 -domains "example.com" -dns-mode drop
dig @8.8.8.8 example.com
# 預期: timeout

# POISON 模式
sudo ./traffic-filter -iface eth0 -domains "example.com" -dns-mode poison
dig @8.8.8.8 example.com
# 預期: NXDOMAIN
```

### 4. 測試 IP 阻斷

```bash
sudo ./traffic-filter -iface eth0 -block-ips "1.2.3.4"
ping 1.2.3.4
# 預期: 100% packet loss
```

### 5. 測試正常流量

```bash
curl http://allowed.com
# 預期: 正常響應
```

## 故障排除

### 編譯問題

#### 找不到 clang-14
```bash
# 檢查可用的 clang
which clang clang-14 clang-17

# 如果只有 clang-19，可能遇到 BPF backend 問題
# 建議安裝 clang-14:
sudo apt-get install clang-14 llvm-14
```

#### Header 檔案找不到
```bash
# 檢查是否安裝 libbpf-dev
dpkg -l | grep libbpf

# 檢查 kernel headers
ls /usr/include/linux/bpf.h
ls /usr/include/bpf/bpf_helpers.h
```

#### go generate 失敗
```bash
# 手動運行 generate
cd pkg/filter
go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 -cflags "-O2 -g -Wall" bpf ../../bpf/traffic_filter.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu
```

### 運行問題

#### Permission denied
需要 root 權限:
```bash
sudo ./traffic-filter -iface eth0 -domains "example.com"
```

#### 找不到網卡
```bash
# 列出所有網卡
ip link show

# 使用正確的網卡名稱
sudo ./traffic-filter -iface ens18 -domains "example.com"
```

#### XDP attach 失敗
```bash
# 檢查 kernel 是否支持 XDP
cat /proc/config.gz | gunzip | grep XDP

# 或者檢查當前運行的 kernel
grep XDP /boot/config-$(uname -r)

# 應該看到:
# CONFIG_XDP_SOCKETS=y
```

#### 沒有效果 (流量沒有被阻斷)

可能原因:
1. **網卡名稱錯誤** - 檢查 `-iface` 參數
2. **流量不經過該網卡** - 檢查路由表: `ip route`
3. **XDP Generic 模式** - 性能較差，可能有延遲
4. **規則沒有匹配** - 檢查日志輸出

### 調試

啟用詳細日志:
```bash
# 在代碼中設置 log level (pkg/filter/filter.go):
log.SetLevel(log.DebugLevel)

# 重新編譯
make build
```

## 性能

- **XDP 模式**: 在網卡驅動層處理，CPU 使用率極低 (< 5%)
- **零拷貝**: 封包在內核處理，不進入 userspace
- **統計開銷**: BPF map 查找和更新，O(1) 複雜度

## 與 AF_PACKET 方案的區別

| 特性 | eBPF/XDP | AF_PACKET |
|------|----------|-----------|
| 本機流量阻斷 | ✓ 有效 | ✗ 無效 |
| 性能 | 極高 (內核) | 中等 (userspace) |
| 依賴 | clang, kernel headers | 無 |
| 可移植性 | 僅 Linux 5.4+ | 任何 Linux |
| 編譯 | 需要 C 編譯器 | 純 Go |

**關鍵差異**: AF_PACKET/AF_INET raw socket 發送的偽造封包走網卡輸出路徑，不會回到本機 TCP stack。XDP 在封包進入 stack **之前**就 DROP 掉，因此能真正阻斷本機流量。

## 技術細節

### XDP Hook 點

```
NIC hardware → XDP hook (我們在這裡) → kernel network stack
```

XDP 程序在封包進入內核網路棧之前執行，可以:
- `XDP_DROP` - 丟棄封包
- `XDP_TX` - 發送封包回網卡 (用於 RST/DNS poison)
- `XDP_PASS` - 讓封包繼續進入網路棧

### BPF Maps

- `blocked_domains` (HASH, 128 entries) - 域名黑名單
- `blocked_ips` (HASH, 256 entries) - IP 黑名單
- `blocked_ip_ports` (HASH, 512 entries) - IP:Port 黑名單
- `config_map` (ARRAY, 1 entry) - 配置 (DNS mode, IP mode)
- `stats` (ARRAY, 8 entries) - 統計計數器

### 封包解析

1. **Ethernet** - 檢查是否為 IPv4
2. **IPv4** - 提取 src/dst IP, protocol
3. **TCP/UDP** - 提取 src/dst port
4. **應用層**:
   - HTTP: 解析 Host header
   - TLS: 解析 ClientHello SNI
   - DNS: 解析 query name

## License

待定

## 作者

Jason Xu
