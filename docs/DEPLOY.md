# 部署指南

## 系統要求

- Linux x86_64
- 內核版本 >= 5.4
- root 權限
- 至少 512MB 可用內存
- 至少 100MB 磁盤空間

## 安裝步驟

### 1. 安裝依賴

**Ubuntu/Debian 20.04+**
```bash
sudo apt-get update
sudo apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    golang-go \
    make \
    git
```

**RHEL/CentOS 8+**
```bash
sudo dnf install -y \
    clang \
    llvm \
    libbpf-devel \
    kernel-devel \
    golang \
    make \
    git
```

**Arch Linux**
```bash
sudo pacman -S \
    clang \
    llvm \
    libbpf \
    linux-headers \
    go \
    make \
    git
```

### 2. 下載源碼

```bash
git clone https://github.com/your-repo/traffic-filter.git
cd traffic-filter
```

### 3. 編譯

**使用 Make**
```bash
make build
```

**或使用 build 腳本**
```bash
chmod +x build.sh
./build.sh
```

### 4. 測試運行

```bash
# 查看網絡接口
ip link show

# 測試運行（替換 eth0 為你的接口名稱）
sudo ./traffic-filter -iface eth0 \
    -domains "example.com" \
    -dns-mode poison \
    -debug
```

按 Ctrl+C 停止。

### 5. 安裝到系統

```bash
# 創建安裝目錄
sudo mkdir -p /opt/traffic-filter

# 複製程序
sudo cp traffic-filter /opt/traffic-filter/
sudo chmod +x /opt/traffic-filter/traffic-filter

# 複製文檔
sudo cp README.md TECHNICAL.md /opt/traffic-filter/

# 創建配置文件（可選）
sudo tee /opt/traffic-filter/domains.txt <<EOF
pornhub.com
www.pornhub.com
xvideos.com
www.xvideos.com
xnxx.com
www.xnxx.com
EOF
```

### 6. 配置 systemd 服務

```bash
# 編輯服務文件，修改接口名稱和域名列表
sudo nano traffic-filter.service

# 複製服務文件
sudo cp traffic-filter.service /etc/systemd/system/

# 重新加載 systemd
sudo systemctl daemon-reload

# 啟用服務（開機自啟）
sudo systemctl enable traffic-filter

# 啟動服務
sudo systemctl start traffic-filter

# 查看狀態
sudo systemctl status traffic-filter

# 查看日誌
sudo journalctl -u traffic-filter -f
```

## 配置

### 基本配置

編輯 `/etc/systemd/system/traffic-filter.service`:

```ini
ExecStart=/opt/traffic-filter/traffic-filter \
    -iface <你的網絡接口> \
    -domains "<域名列表，逗號分隔>" \
    -dns-mode <drop|poison>
```

### 高級配置

#### 使用域名文件

修改程序以支持從文件讀取域名列表（需要擴展代碼）：

```bash
# 創建域名文件
sudo tee /opt/traffic-filter/blocked-domains.txt <<EOF
pornhub.com
www.pornhub.com
EOF

# 修改服務使用文件
ExecStart=/opt/traffic-filter/traffic-filter \
    -iface eth0 \
    -domain-file /opt/traffic-filter/blocked-domains.txt \
    -dns-mode poison
```

#### 多接口部署

為每個接口創建單獨的服務：

```bash
# 複製服務文件
sudo cp /etc/systemd/system/traffic-filter.service \
        /etc/systemd/system/traffic-filter@.service

# 編輯為模板服務
[Service]
ExecStart=/opt/traffic-filter/traffic-filter \
    -iface %i \
    -domains "..." \
    -dns-mode poison

# 啟動多個實例
sudo systemctl enable traffic-filter@eth0
sudo systemctl enable traffic-filter@eth1
sudo systemctl start traffic-filter@eth0
sudo systemctl start traffic-filter@eth1
```

## 監控和維護

### 查看實時日誌

```bash
sudo journalctl -u traffic-filter -f
```

### 查看統計信息

統計信息每 5 秒輸出一次：

```
INFO[...] 流量統計  
    total=123456 
    blocked=234 
    http=1234 
    tls=5678 
    dns=890 
    total/s=1000 
    blocked/s=5
```

### 性能監控

```bash
# CPU 使用率
top -p $(pgrep traffic-filter)

# 內存使用
ps aux | grep traffic-filter

# 網絡統計
sudo bpftool prog show
```

### 日誌輪轉

使用 systemd 內置的日誌限制：

```bash
sudo mkdir -p /etc/systemd/journald.conf.d/
sudo tee /etc/systemd/journald.conf.d/traffic-filter.conf <<EOF
[Journal]
SystemMaxUse=100M
SystemMaxFileSize=10M
EOF

sudo systemctl restart systemd-journald
```

### 更新域名列表

```bash
# 停止服務
sudo systemctl stop traffic-filter

# 修改服務文件中的域名列表
sudo nano /etc/systemd/system/traffic-filter.service

# 重新加載配置
sudo systemctl daemon-reload

# 啟動服務
sudo systemctl start traffic-filter
```

### 故障排查

#### 1. 服務無法啟動

```bash
# 查看詳細錯誤
sudo journalctl -u traffic-filter -n 50 --no-pager

# 手動運行測試
sudo /opt/traffic-filter/traffic-filter -iface eth0 -domains "test.com" -debug
```

#### 2. 沒有攔截效果

```bash
# 檢查 XDP 程序是否附加
sudo ip link show eth0 | grep xdp

# 查看 eBPF 程序
sudo bpftool prog list

# 查看統計
# 應該看到 total 和相關計數器在增長
```

#### 3. 性能問題

```bash
# 嘗試 Native XDP 模式（需要網卡支持）
# 修改代碼中的 link.XDPGenericMode 為 link.XDPDriverMode

# 減少域名列表大小

# 升級內核版本
```

## 安全加固

### 1. 限制服務權限

編輯 `/etc/systemd/system/traffic-filter.service`:

```ini
[Service]
# 禁止創建新特權
NoNewPrivileges=true

# 使用私有臨時目錄
PrivateTmp=true

# 只讀根目錄（如果程序不需要寫入）
ReadOnlyPaths=/

# 設置資源限制
LimitNOFILE=1024
LimitNPROC=1

# 禁用網絡（除了 XDP）
RestrictAddressFamilies=AF_UNIX AF_PACKET AF_NETLINK
```

### 2. SELinux/AppArmor

**SELinux (RHEL/CentOS)**
```bash
# 創建策略（需要專業知識）
# 或臨時設置為 permissive
sudo setenforce 0
```

**AppArmor (Ubuntu)**
```bash
# 創建配置文件
sudo tee /etc/apparmor.d/opt.traffic-filter <<EOF
#include <tunables/global>

/opt/traffic-filter/traffic-filter {
  #include <abstractions/base>
  
  capability net_admin,
  capability sys_resource,
  
  /opt/traffic-filter/traffic-filter mr,
  /sys/class/net/** r,
  /proc/sys/kernel/unprivileged_bpf_disabled r,
}
EOF

sudo apparmor_parser -r /etc/apparmor.d/opt.traffic-filter
```

## 備份和恢復

### 備份

```bash
# 備份程序和配置
sudo tar czf traffic-filter-backup.tar.gz \
    /opt/traffic-filter \
    /etc/systemd/system/traffic-filter.service
```

### 恢復

```bash
# 恢復文件
sudo tar xzf traffic-filter-backup.tar.gz -C /

# 重新加載服務
sudo systemctl daemon-reload
sudo systemctl restart traffic-filter
```

## 卸載

```bash
# 停止服務
sudo systemctl stop traffic-filter
sudo systemctl disable traffic-filter

# 刪除服務文件
sudo rm /etc/systemd/system/traffic-filter.service

# 刪除程序
sudo rm -rf /opt/traffic-filter

# 重新加載 systemd
sudo systemctl daemon-reload
```

## 生產環境最佳實踐

1. **測試環境驗證**: 先在測試環境完整測試
2. **逐步推出**: 先在單個節點部署，再擴展到集群
3. **監控告警**: 集成到監控系統（Prometheus, Grafana）
4. **日誌集中**: 使用 ELK/Loki 集中收集日誌
5. **自動化部署**: 使用 Ansible/Terraform
6. **高可用**: 多節點部署，避免單點故障
7. **定期更新**: 定期更新域名列表和程序
8. **性能測試**: 進行壓力測試驗證性能
9. **災難恢復**: 準備回滾方案

## 集成其他系統

### Prometheus 監控

擴展程序添加 metrics 端點：

```go
// 添加 HTTP 服務器暴露 metrics
import "github.com/prometheus/client_golang/prometheus/promhttp"

http.Handle("/metrics", promhttp.Handler())
go http.ListenAndServe(":9090", nil)
```

### 配置管理

**Ansible Playbook 示例**:

```yaml
---
- name: Deploy Traffic Filter
  hosts: gateways
  become: yes
  tasks:
    - name: Install dependencies
      apt:
        name:
          - clang
          - llvm
          - libbpf-dev
        state: present

    - name: Copy binary
      copy:
        src: traffic-filter
        dest: /opt/traffic-filter/traffic-filter
        mode: '0755'

    - name: Copy systemd service
      template:
        src: traffic-filter.service.j2
        dest: /etc/systemd/system/traffic-filter.service

    - name: Enable and start service
      systemd:
        name: traffic-filter
        state: started
        enabled: yes
        daemon_reload: yes
```

## 支持

如有問題，請：
1. 查看 [README.md](README.md)
2. 查看 [TECHNICAL.md](TECHNICAL.md)
3. 檢查 GitHub Issues
4. 提交新 Issue

## 許可證

GPL - 因為 eBPF 程序需要
