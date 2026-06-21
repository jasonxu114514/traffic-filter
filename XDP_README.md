# Traffic Filter - XDP/eBPF 版本

## 簡介

使用 XDP (eXpress Data Path) + eBPF 在內核網卡驅動層直接 DROP 封包。

- **純 Go** + 嵌入的預編譯 eBPF 字節碼
- **極簡的 eBPF C 代碼** - 避免 clang 19 的 memcpy 錯誤
- **真正有效** - 在封包進入 TCP stack 之前就阻擋

## 快速開始

```bash
cd ~/traffic-filter
git pull

# 編譯（eBPF 已編譯好並嵌入）
make clean
make build

# 運行（阻擋端口 80, 443, 53）
sudo ./traffic-filter -iface ens18

# 測試
curl http://example.com  # 應該失敗（被 XDP DROP）
curl https://example.com # 應該失敗
```

## 工作原理

```
NIC → XDP hook (我們的 eBPF 程序) → 檢查端口 → DROP/PASS
      ↑ 在這裡就阻擋了，不會進入 TCP stack
```

## 當前功能

**V1 版本（極簡）**:
- ✅ 阻擋指定端口（80, 443, 53）
- ✅ 統計：total/blocked/passed
- ✅ 純端口過濾，不解析協議

**未來版本**:
- ⏳ HTTP/TLS/DNS 域名過濾（需要更複雜的 eBPF 代碼）
- ⏳ IP 黑名單
- ⏳ 動態規則更新

## 優勢

vs NFQUEUE:
- ✅ 不需要 nfnetlink_queue 模塊（您的系統沒有）
- ✅ 性能更高（XDP 在 NIC 驅動層）

vs AF_PACKET:
- ✅ 真正能阻擋本機流量
- ✅ 不需要注入 RST 封包

vs 完整 eBPF:
- ✅ 極簡 C 代碼，避免 memcpy 錯誤
- ✅ 成功編譯

## 限制

- 只過濾端口，不解析域名（需要更複雜的 eBPF 實現）
- 需要 root 權限
- 需要 kernel 支持 XDP (5.4+)

## 參數

```
-iface string    網卡名稱（必需）
-debug           調試模式
```

## 編譯 eBPF

如果修改了 `bpf/filter.bpf.c`：

```bash
make bpf        # 重新編譯 eBPF
make build      # 重新構建（嵌入新的 eBPF 字節碼）
```

需要：
- clang
- vmlinux.h（已包含在 bpf/ 目錄）
