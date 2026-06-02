# 教學模擬影片

**[▶ sensel-walkthrough-1080.mp4](sensel-walkthrough-1080.mp4)** — 1920×1080 · H.264 · 30fps · ~52s · 動態 motion graphics

`hardening-v1` 偵測強化動態導覽。流程圖**會動**（封包沿被動側連線流動、連線自我繪製、規則徽章逐一彈出、修好的階段發綠光、18 條攻擊格逐一打勾）。聚焦**修好 main 的偵測並用真實攻擊驗證**：OT-003 ARP、MMS 真 BER 解析、OT-013 wrap-safe、OT-015/017 補實作、tailer 輪替、可落盤 pcap 證據。

## 怎麼做的 / 如何重新產生

用 [HeyGen HyperFrames](https://github.com/heygen-com/hyperframes)（HTML → 影片，agent-native，**直接輸出 MP4**，非先 webm 再轉）。需要 Node 22+ 與 ffmpeg。`composition.html` 是純向量重建（場景以 `data-start`/`data-duration` 計時，GSAP 做連線繪製、封包沿線移動、stagger、計數），只外連 GSAP CDN，不依賴 PNG。

```bash
npx hyperframes init sensel-video && cd sensel-video
cp /path/to/repo/docs/video/composition.html index.html
npm run check
npx hyperframes render -q high -f 30 -o sensel-walkthrough-1080.mp4
```

中文以 Windows 系統字型（Microsoft JhengHei）渲染；本機渲染即可。渲染後請抽幀自我檢查（含在同一動畫場景抽相鄰時間點，確認封包/連線位置不同＝真的有動）。
