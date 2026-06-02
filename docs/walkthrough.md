# 模擬流程 walkthrough（真實終端輸出）

> 🎬 影片版：**[docs/video/sensel-walkthrough-1080.mp4](video/sensel-walkthrough-1080.mp4)**（1080p，同樣的真實輸出 + 流程圖；製作方式見 [docs/video/README.md](video/README.md)）。

下面三段是 `first-principles-redesign` 分支**實際跑出來**的輸出（非示意）。全部離線、不需 Docker/網路，你可在任何裝了 Python+scapy 的機器照著重跑。這就是「錄下模擬流程」的可重現版本——比影片更能被你親自驗證。

> 真實感測器要在 Linux/Pi + 鏡像埠上跑（`make up-attack-lab` 等），那一段需要 Docker，無法在純 Windows 開發機重現；要產出 MP4 影片，建議在 Linux lab 機上對 `make up-attack-lab → make attack-all → make verify-attacks` 錄製。

---

## A. 沒有 baseline 也能用：從工程 SCD 自動推導

```console
$ python3 scripts/scd-to-baseline.py lab/61850/sample.scd --site-id lab --stdout
# (stderr) derived baseline: 2 assets, 1 GOOSE publishers, 1 MMS IEDs
```
推導出的關鍵內容（節錄）：
```json
{
  "assets": ["ied-01", "hmi-01"],
  "goose_publishers": [
    { "asset_id": "ied-01", "publisher_mac": "", "appid": 1000,
      "gocb_ref": "", "production": true, "max_silence_sec": 8.0 }
  ],
  "mms_ieds": [
    { "asset_id": "ied-01", "ied_ip": "192.168.10.50",
      "allowed_mms_clients": ["192.168.10.10"] }
  ]
}
```
**重點**：GOOSE 以 **APPID（1000）** 為權威 key（SCL 的 MAC 是目的多播、非來源 MAC，故 `publisher_mac` 留空）；`max_silence_sec` 由 GSE `MaxTime` 推導。

---

## B. 還沒有 SCD：先 learning（安靜學習）→ 匯出候選 baseline

```console
$ # detection.mode=learning, state_db=...  跑一段代表性「正常」流量後關閉
alerts raised during learning : (none)
candidate goose_publishers   : [{"asset_id":"","publisher_mac":"00:11:22:33:44:55","appid":1000,"gocb_ref":"","production":true,"max_silence_sec":0.0}]
candidate mms_ieds           : [{"asset_id":"","ied_ip":"192.168.10.50","allowed_mms_clients":["192.168.10.10"]}]
```
**重點**：學習期間**完全不告警**（`(none)`），但把觀測到的 GOOSE（來源 MAC + APPID）與 MMS（IED + client）學進持久化狀態，匯出成**和 SCD 同一 schema** 的候選 baseline 供審核。對應指令：
```bash
python3 scripts/observed-to-baseline.py data/assets/learned-state.db --site-id lab --stdout
```

---

## C. 偵測真的有效：OT-001 ~ OT-018 全數觸發

```console
$ python3 scripts/attacks-selftest.py
  OT-001: PASS    OT-007: PASS    OT-013: PASS
  OT-002: PASS    OT-008: PASS    OT-014: PASS
  OT-003: PASS    OT-009: PASS    OT-015: PASS
  OT-004: PASS    OT-010: PASS    OT-016: PASS
  OT-005: PASS    OT-011: PASS    OT-017: PASS
  OT-006: PASS    OT-012: PASS    OT-018: PASS
OK — all 18 implemented rules fired
```
（真實流量版：`make up-attack-lab` 後 `make attack-all` / `attack-arp`，見 [`lab/attack/README.md`](../lab/attack/README.md)。）

---

## 一句話總結三段

| 情境 | 指令 | 結果 |
|------|------|------|
| 有工程檔 | `scd-to-baseline.py …` | 從 SCD 自動得到權威 baseline |
| 還沒 baseline | `mode: learning` → `observed-to-baseline.py …` | 安靜學習、零告警 → 候選 baseline |
| 驗證偵測 | `attacks-selftest.py` | OT-001~018 全綠 |
