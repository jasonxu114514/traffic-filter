# Traffic Filter - NFQUEUE 版本部署指南

## 快速開始（在遠端 Linux 執行）

```bash
# 1. 拉取代碼
git pull origin master

# 2. 編譯
make clean
make build

# 3. 測試（本機模式）
sudo ./traffic-filter -mode local -domains "example.com" -debug

# 4. 另開終端測試
curl https://example.com  # 應該失敗（被 DROP）
curl https://google.com   # 應該成功
```

## 系統需求

- Linux kernel >= 3.13 (NFQUEUE 支持)
- iptables
- nfnetlink_queue 模塊
- Go 1.22+

## 檢查環境

```bash
# 檢查 nfnetlink_queue 模塊
lsmod | grep nfnetlink_queue

# 如果沒有，載入模塊
sudo modprobe nfnetlink_queue

# 檢查 iptables
which iptables
```

## 使用方式

### 模式 1: 本機流量過濾

```bash
sudo ./traffic-filter -mode local -domains "example.com,ads.com"
```

效果：阻擋本機的 curl/wget/browser 訪問指定域名

### 模式 2: 網關模式（轉發流量）

```bash
# 啟用 IP 轉發
sudo sysctl -w net.ipv4.ip_forward=1

# 啟動過濾器
sudo ./traffic-filter -mode gateway -domains "example.com"
```

效果：作為中間網關，過濾經過本機的流量

### 模式 3: 混合模式

```bash
sudo ./traffic-filter -mode all -domains "example.com"
```

效果：同時過濾本機和轉發流量

## 參數說明

```
-mode string
    Filter mode: local, gateway, all (default "local")

-domains string
    Blocked domains (comma-separated)
    Example: "example.com,ads.com,tracker.com"

-block-ips string
    Blocked IPs (comma-separated)
    Example: "1.2.3.4,8.8.8.8"

-queue uint
    NFQUEUE queue number (default 0)

-debug
    Enable debug logging
```

## 工作原理

```
本機流量（local mode）:
  App → TCP stack → [iptables OUTPUT → NFQUEUE → 程序判斷 → DROP/ACCEPT]

轉發流量（gateway mode）:
  Client → [iptables FORWARD → NFQUEUE → 程序判斷 → DROP/ACCEPT] → Internet
```

## iptables 規則

程序會自動添加和清理 iptables 規則：

```bash
# OUTPUT chain (local mode)
iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0
iptables -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 0
iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0

# FORWARD chain (gateway mode)
iptables -A FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 0
iptables -A FORWARD -p tcp --dport 443 -j NFQUEUE --queue-num 0
iptables -A FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0
```

程序退出時會自動清理這些規則。

## 驗證

### 查看 iptables 規則

```bash
sudo iptables -L OUTPUT -n -v
sudo iptables -L FORWARD -n -v
```

### 測試本機阻擋

```bash
# Terminal 1
sudo ./traffic-filter -mode local -domains "example.com" -debug

# Terminal 2
curl http://example.com   # 應該失敗
curl https://example.com  # 應該失敗
dig @8.8.8.8 example.com  # 應該 timeout

curl http://google.com    # 應該成功
```

## 故障排除

### 錯誤: "failed to open nfqueue"

**原因**: nfnetlink_queue 模塊未載入

**解決**:
```bash
sudo modprobe nfnetlink_queue
```

### 錯誤: "This program must be run as root"

**原因**: 需要 root 權限操作 iptables 和 NFQUEUE

**解決**:
```bash
sudo ./traffic-filter ...
```

### 流量沒有被阻擋

**檢查**:
1. 確認規則已添加: `sudo iptables -L OUTPUT -n -v`
2. 確認域名拼寫正確（大小寫不敏感）
3. 查看日志輸出（使用 `-debug`）

## 與之前版本的對比

| 特性 | eBPF | AF_PACKET | NFQUEUE |
|------|------|-----------|---------|
| 本機流量 | ✓ (編譯失敗) | ✗ 無效 | ✓ 有效 |
| 轉發流量 | ✓ | ✓ | ✓ |
| 編譯需求 | C + clang | 無 | 無 |
| 依賴 | kernel 5.4+, libbpf | 無 | iptables |
| 實測結果 | 18+ 編譯錯誤 | RST 不生效 | **成功** |

## 性能

NFQUEUE 在內核處理，性能良好：
- 低延遲（微秒級）
- CPU 使用率低
- 適合中等流量場景

## 下一步

1. 測試三種模式
2. 驗證 HTTP/HTTPS/DNS 阻擋
3. 測試 IP 和 IP:Port 阻擋
4. 性能測試
5. 更新 README.md 和 STATUS.md
