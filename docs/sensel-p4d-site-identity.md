# SenseL P4-D Site Identity Binding

## 🔒 Edge/Site 責任

Site 只接受 Control Plane 簽署的 RDP、probe rotation 與 identity/rate policy。送出 update 時，manifest 會簽入 `site_identity_id`、`trust_domain_id` 與 `rate_policy_id`；Control Plane 再與鎖定的 registry digest、Site signing key 與 rolling-window policy交叉驗證。

> [!WARNING]
> 現有 leaf perturbation 不是完整 XGBoost DP。Site 會拒絕缺少 `rdp_gaussian_v1`、adjacency、RDP orders 或一致 noise multiplier 的 privacy policy。

---

## 🧪 驗收邊界

| 項目 | Site 行為 |
|---|---|
| Signed identity policy | 缺少 device/trust-domain identity 時拒絕建立 update |
| RDP policy | noise multiplier 與 Gaussian leaf mechanism 不一致時拒絕 |
| Rate limit | 由 Control Plane transactionally enforcement；Site 只簽署 policy identity |
| Probe | Site 不持有 server probe catalog，避免針對 probe 調參 |
| Activation | 此切片不新增自動 release 或 activation |
