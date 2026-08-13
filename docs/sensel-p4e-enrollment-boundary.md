# SenseL P4-E Edge Enrollment Boundary

## 🔒 Site 行為

Site 只接受 secure aggregation 為 `none` 的 `FedXgbBagging` round。若 Control Plane 宣告尚未落地的 secure aggregation protocol，Site 會 fail closed。

受 managed enrollment 約束時，每個 signed update 都包含 `enrollment_id` 與 `key_generation`，並沿用同一份 signed round 中的 enrollment snapshot、device identity、trust domain 與 rate policy。

> [!WARNING]
> Edge 不自行把新 key 視為可信。Key rotation 必須先經 Control Plane enrollment API 與外部 PKI/IAM 程序核准；舊 round snapshot 不會自動接受新 generation。

---

## 🧪 驗證規則

| 規則 | 拒絕條件 |
|---|---|
| Secure aggregation | protocol 不是 `none`，或錯誤宣告 production ready |
| Enrollment | ID 格式、generation 或 snapshot digest 缺失 |
| Site identity | device identity、trust domain 或 rate policy 缺失 |
| Privacy | RDP/noise policy 不一致 |

本切片不改變 Edge 本地 deterministic detection，也不授權 candidate release 或 model activation。
