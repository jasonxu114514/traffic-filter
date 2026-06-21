# 遠端 Linux 部署指南

本指南說明如何在遠端 Linux 機器上編譯和運行 eBPF traffic filter。

## 快速開始

```bash
# 1. 克隆或更新代碼
git pull

# 2. 安裝依賴 (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y clang-14 llvm-14 libbpf-dev linux-headers-$(uname -r) golang-go

# 3. 編譯
make clean
make build

# 4. 測試運行
sudo ./traffic-filter -iface eth0 -domains "example.com"

# 5. 另開終端測試
curl http://example.com  # 應該失敗
```

## 詳細步驟

### 步驟 1: 檢查系統環境

```bash
# 檢查 kernel 版本 (需要 5.4+)
uname -r

# 檢查 BPF 支持
zgrep CONFIG_BPF /proc/config.gz
zgrep CONFIG_XDP_SOCKETS /proc/config.gz

# 檢查網卡
ip link show
```

預期輸出:
- Kernel >= 5.4
- `CONFIG_BPF=y`
- `CONFIG_BPF_SYSCALL=y`  
- `CONFIG_XDP_SOCKETS=y`

### 步驟 2: 安裝依賴

#### Ubuntu 22.04 / Debian 12

```bash
sudo apt-get update
sudo apt-get install -y \
    clang-14 \
    llvm-14 \
    libbpf-dev \
    linux-headers-$(uname -r) \
    golang-go \
    build-essential
```

#### RHEL 9 / Rocky Linux 9

```bash
sudo dnf install -y \
    clang \
    llvm \
    libbpf-devel \
    kernel-devel \
    golang \
    make
```

#### Arch Linux

```bash
sudo pacman -S \
    clang \
    llvm \
    libbpf \
    linux-headers \
    go \
    make
```

驗證安裝:
```bash
clang-14 --version  # 或 clang-17, clang
go version
ls /usr/include/linux/bpf.h
ls /usr/include/bpf/bpf_helpers.h
```

### 步驟 3: 編譯

```bash
# 清理舊的構建產物
make clean

# 編譯 eBPF + Go
make build
```

編譯過程:
```
==> Compiling eBPF program with clang-14...
clang-14 -O2 -target bpf -c bpf/traffic_filter.c -o bpf/traffic_filter.o ...
==> Generating Go bindings + downloading dependencies...
cd pkg/filter && go generate ./...
go mod tidy
==> Building traffic-filter...
go build -o traffic-filter cmd/traffic-filter
```

成功後會生成:
- `bpf/traffic_filter.o` - eBPF 目標檔
- `pkg/filter/bpf_bpfel.go` - Go bindings
- `traffic-filter` - 可執行檔

### 步驟 4: 測試

#### 基本測試

```bash
# Terminal 1: 啟動 filter (阻斷 example.com)
sudo ./traffic-filter -iface eth0 -domains "example.com"
```

預期輸出:
```
INFO[0000] Traffic Filter — eBPF/XDP mode
INFO[0000] Loaded eBPF objects
INFO[0000] Added domain: example.com
INFO[0000] Attached XDP to eth0
INFO[0000] Filter active. Press Ctrl+C to stop.
```

```bash
# Terminal 2: 測試阻斷
curl http://example.com
# 預期: curl: (7) Failed to connect to example.com port 80: Connection refused
# 或: curl: (56) Recv failure: Connection reset by peer

curl http://google.com
# 預期: 正常返回 HTML
```

停止 filter (Terminal 1 按 Ctrl+C):
```
^C
INFO[0010] Shutting down...
INFO[0010] Statistics:
INFO[0010]   Total packets:   12345
INFO[0010]   Blocked packets: 42
INFO[0010]   HTTP packets:    15
INFO[0010]   TLS packets:     8
INFO[0010]   DNS packets:     7
INFO[0010]   IP blocked:      5
INFO[0010]   IP:Port blocked: 7
INFO[0010]   RST sent:        23
```

#### 功能測試矩陣

| 測試項目 | 命令 | 預期結果 |
|---------|------|---------|
| HTTP 阻斷 | `sudo ./traffic-filter -iface eth0 -domains "example.com"` → `curl http://example.com` | Connection reset |
| HTTPS 阻斷 | 同上 → `curl https://example.com` | SSL error |
| DNS 阻斷 (DROP) | `sudo ./traffic-filter -iface eth0 -domains "example.com" -dns-mode drop` → `dig @8.8.8.8 example.com` | timeout |
| DNS 阻斷 (POISON) | `sudo ./traffic-filter -iface eth0 -domains "example.com" -dns-mode poison` → `dig @8.8.8.8 example.com` | NXDOMAIN |
| IP 阻斷 | `sudo ./traffic-filter -iface eth0 -block-ips "1.1.1.1"` → `ping 1.1.1.1` | 100% loss |
| IP:Port 阻斷 | `sudo ./traffic-filter -iface eth0 -block-ip-ports "1.1.1.1:80:tcp"` → `curl http://1.1.1.1` | Connection refused |
| 正常流量 | 同上 → `curl http://google.com` | 正常返回 |

### 步驟 5: 安裝 (可選)

```bash
# 安裝到系統路徑
sudo make install

# 現在可以直接運行
sudo traffic-filter -iface eth0 -domains "example.com"
```

## 常見問題

### 編譯錯誤

#### 錯誤: `fatal error: 'linux/bpf.h' file not found`

**原因**: 缺少 kernel headers 或 libbpf-dev

**解決**:
```bash
sudo apt-get install linux-headers-$(uname -r) libbpf-dev
```

#### 錯誤: `fatal error: 'bpf/bpf_helpers.h' file not found`

**原因**: libbpf-dev 未安裝

**解決**:
```bash
sudo apt-get install libbpf-dev

# 驗證
ls /usr/include/bpf/bpf_helpers.h
```

#### 錯誤: `fatal error: 'asm/types.h' file not found`

**原因**: 缺少 arch-specific headers

**解決**: Makefile 已經包含 `-I/usr/include/x86_64-linux-gnu`，應該自動解決。如果仍有問題:
```bash
sudo apt-get install gcc-multilib
```

#### 錯誤: `clang-14: command not found`

**原因**: clang-14 未安裝，或不在 PATH

**解決**:
```bash
# 安裝 clang-14
sudo apt-get install clang-14

# 或使用其他版本
which clang-17  # 或 clang
```

Makefile 會自動檢測可用的 clang 版本 (clang-14 > clang-17 > clang)。

#### 錯誤: BPF backend crash (clang 19)

**症狀**: clang 編譯時 crash，錯誤訊息包含 "BPF backend"

**原因**: clang 19 的 BPF backend 有已知問題

**解決**: 安裝 clang-14 或 clang-17:
```bash
sudo apt-get install clang-14 llvm-14
```

### 運行錯誤

#### 錯誤: `operation not permitted`

**原因**: 沒有 root 權限

**解決**:
```bash
sudo ./traffic-filter -iface eth0 -domains "example.com"
```

#### 錯誤: `link attach: ENODEV`

**原因**: 網卡名稱錯誤

**解決**:
```bash
# 列出所有網卡
ip link show

# 使用正確的網卡名稱 (常見: eth0, ens18, ens33, enp0s3)
sudo ./traffic-filter -iface ens18 -domains "example.com"
```

#### 錯誤: `XDP not supported`

**原因**: kernel 不支持 XDP，或 kernel 版本太舊

**檢查**:
```bash
uname -r  # 需要 >= 5.4

# 檢查 XDP 配置
zgrep XDP /proc/config.gz
```

**解決**: 升級 kernel 或使用支持 XDP 的 Linux 發行版。

#### 問題: 流量沒有被阻斷

**檢查清單**:

1. **網卡是否正確**:
   ```bash
   ip route  # 檢查流量走哪個網卡
   sudo ./traffic-filter -iface <正確的網卡> ...
   ```

2. **域名/IP 是否匹配**:
   ```bash
   # 檢查實際請求的域名
   curl -v http://example.com 2>&1 | grep Host
   # 確保 -domains 參數包含該域名
   ```

3. **XDP 是否成功 attach**:
   啟動時應該看到:
   ```
   INFO[0000] Attached XDP to eth0
   ```

4. **是否有統計輸出**:
   Ctrl+C 停止時應該看到非零的 Total packets。如果 Total packets = 0，說明沒有捕獲到流量。

### 性能問題

#### CPU 使用率過高

**預期**: eBPF/XDP 模式下，CPU 使用率應該 < 5%

**檢查**:
```bash
top -p $(pgrep traffic-filter)
```

**可能原因**:
- XDP Generic 模式 (較慢，但兼容性好)
- 流量過大
- 統計更新頻繁

**優化**: 修改代碼減少統計更新頻率。

## 生產部署建議

### 1. Systemd Service

創建 `/etc/systemd/system/traffic-filter.service`:

```ini
[Unit]
Description=Traffic Filter eBPF/XDP
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/traffic-filter -iface eth0 -domains "ads.com,tracker.com" -dns-mode poison
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

啟用:
```bash
sudo systemctl daemon-reload
sudo systemctl enable traffic-filter
sudo systemctl start traffic-filter
sudo systemctl status traffic-filter
```

### 2. 日志

添加 `-log-level debug` 或修改代碼設置 log level。

### 3. 監控

定期檢查統計:
```bash
# 發送 SIGINT 會輸出統計並退出
sudo killall -INT traffic-filter
```

或修改代碼添加 HTTP metrics endpoint。

### 4. 安全

- 只允許 root 運行
- 限制可執行檔權限: `sudo chmod 700 /usr/local/bin/traffic-filter`
- 使用 AppArmor/SELinux 限制權限

## 故障排查流程

1. **檢查環境**:
   ```bash
   uname -r  # >= 5.4
   zgrep BPF /proc/config.gz
   ip link show
   ```

2. **檢查依賴**:
   ```bash
   which clang-14
   ls /usr/include/linux/bpf.h
   ls /usr/include/bpf/bpf_helpers.h
   ```

3. **嘗試編譯**:
   ```bash
   make clean
   make build 2>&1 | tee build.log
   ```

4. **嘗試運行**:
   ```bash
   sudo ./traffic-filter -iface eth0 -domains "example.com"
   ```

5. **測試功能**:
   ```bash
   curl http://example.com  # 應該失敗
   curl http://google.com   # 應該成功
   ```

6. **檢查日志**:
   啟動時的 INFO 訊息，停止時的統計輸出。

## 與開發機器同步

```bash
# 在開發機器 (Windows Git Bash)
git add -A
git commit -m "Restore eBPF architecture"
git push

# 在遠端 Linux 機器
git pull
make clean
make build
sudo ./traffic-filter -iface eth0 -domains "example.com"
```

## 下一步

- 根據實際需求調整阻斷規則
- 添加更多域名/IP 到黑名單
- 調整 DNS mode (drop vs poison)
- 調整 IP mode (tcp,udp,icmp)
- 設置開機自啟 (systemd service)
- 監控統計數據

## 支持

遇到問題請提供:
- `uname -r` 輸出
- `make build` 完整錯誤訊息
- `sudo ./traffic-filter ...` 運行日志
- 系統發行版: `cat /etc/os-release`
