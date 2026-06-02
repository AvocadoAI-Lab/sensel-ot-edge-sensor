# 教學模擬影片

**[▶ sensel-walkthrough-1080.mp4](sensel-walkthrough-1080.mp4)** — 1920×1080 · H.264 · 30fps · ~49s

一支把「為什麼有 `first-principles-redesign` 分支、跟誰不同、優勢」走一遍的教學影片，內含**真實終端輸出**與流程圖：

1. 標題 → 雙路徑架構圖
2. 問題（為什麼要重做）
3. ① 有工程檔：`scd-to-baseline` 真實輸出
4. ② 還沒 baseline：learning 模式（零告警）→ 候選 baseline
5. ③ 偵測有效：OT-001 ~ OT-018 全數觸發
6. 兩源匯流（baseline 生命週期圖）→ 結尾

> 內容對應 [`docs/walkthrough.md`](../walkthrough.md)（同樣的真實輸出，文字版）。

## 怎麼做的 / 如何重新產生

用 [HeyGen HyperFrames](https://github.com/heygen-com/hyperframes)（HTML → 影片，agent-native，**直接輸出 MP4**，非先 webm 再轉）。需要 Node 22+ 與 ffmpeg。

```bash
# 1. 建一個 hyperframes 專案（在 repo 外，避免 node_modules 進版控）
npx hyperframes init sensel-video && cd sensel-video

# 2. 用本資料夾的 composition.html 取代 index.html，並放入流程圖
cp /path/to/repo/docs/video/composition.html index.html
cp /path/to/repo/docs/diagrams/architecture.png .
cp /path/to/repo/docs/diagrams/baseline-lifecycle.png .
#   （composition.html 內的 ../diagrams/*.png 改成同層檔名，或調整路徑）

# 3. 驗證 + 直接渲染高畫質 MP4
npm run check
npx hyperframes render -q high -f 30 -o sensel-walkthrough-1080.mp4
```

- `composition.html`：影片的 HTML 來源（場景以 `data-start`/`data-duration`/`data-track-index` 計時，GSAP 做進場與 Ken-Burns）。
- 中文以 Windows 系統字型（Microsoft JhengHei）渲染；本機渲染即可，毋需 Google Fonts。
- 渲染後請抽幀自我檢查（如 `ffmpeg -ss 15 -i out.mp4 -frames:v 1 f.png`）。
