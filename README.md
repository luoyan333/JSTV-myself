# JSTV-myself

个人 JSTV 统一订阅。以用户指定的 [fangkuia/XPTV · dist](https://github.com/fangkuia/XPTV/tree/main/dist) 为基础，整合已修复的红果短剧源。

## 订阅地址

在 JSTV「订阅 → ＋ → 添加订阅」中添加：

```text
https://raw.githubusercontent.com/luoyan333/JSTV-myself/main/index.js.md5
```

名称可填写 `JSTV-myself`。所有入口归于这一个订阅；不需要另外添加红果地址。设备当前网络需要能够访问 GitHub 原始文件服务。

## 本版内容

版本：**1.1.0**，2026-10-27。

- 保留指定上游的 20 个入口，包含其成人类站点、短剧、直播配置入口。
- 加入「红果短剧·独立版」，总计 **21 个入口**，其中 19 个为内容来源，2 个为直播/配置入口。
- 未混入此前误选的 xiaobaitulele 订阅。
- 所需运行代码均内置于 `index.js`，适配 JSTV 只下载入口脚本和配置文件的导入方式。

## 本次修复

- **Avdb**：适配新的 `PLAYER_CONFIG` 视频字段，保留嵌入页 Referer/Origin，避免空地址导致 `Invalid URL`。
- **HLS 请求**：中转读取清单时保留站点提供的请求头。
- **Avdb / Pornhub**：使用带必要请求头的直接 HLS 播放，避免原自动中转引起的播放失败。
- **Pornhub**：详情保存页面引用，在每次播放时重新获取媒体地址，减少临时地址失效的问题。
- **红果**：保留匿名设备注册、媒体处理、分段读取及进度跳转功能。
- 默认开启上游 HTTPS 证书校验；本机服务只监听回环地址。

## 验证范围

2026-10-27，在本机独立空配置环境检查目录、详情、播放接口及视频解码。没有读取 JSTV 现有账号或个人配置，没有上传账号凭据、运行数据库、浏览记录、测试视频或临时媒体地址。

以下是抽样结果，不代表站内全部影片、全部线路或所有设备均可播放：

| 来源 | 当前结果 |
| --- | --- |
| 红果短剧·独立版 | 整合后视频解码回归通过；此前在 macOS JSTV 1.17 中实际播放，进度跳转和切集经使用者实测通过 |
| KanAV、Taiav、肉视频、麻豆社、PPPHub、XXXFollow、XVideos、黄豆短剧、黄果短剧 | 整合后样本视频解码通过 |
| Avdb | 修复后样本视频解码通过 |
| Pornhub | 使用播放时刷新地址及直接 HLS；最终两个样本中一例解码通过、一例仍返回 410；仅记为兼容性调整，未认定稳定修复 |
| Kbjfan | 当前网络下 TLS 连接失败，未完成播放验收 |
| Jable、51吃瓜 | 当前网络下连接中断，未完成播放验收 |
| Hanime、SpankBang | 当前请求被拒绝或返回 403，未完成播放验收 |
| MissAV | 目录可读取，详情请求出现 HTTP 解析异常，未完成播放验收 |
| pandatv | 目录可读取，取流请求返回 400，未完成播放验收 |
| 直播源、配置页面 | 配置入口；未导入用户直播列表，因此不作直播可播结论 |

待验证来源仍保留在订阅中。当前环境中的网络/站点限制不作为永久失效结论，也未将这些来源标记为已修好。未配置网站验证信息，不代用户完成网站验证。

本次整合版尚未替换 Mac 正在使用的订阅，也未在其他设备实机验收。此前红果独立版的实机结果仅适用于其未变更的功能。

## 配置与维护

- 网站自己的配置页沿用上游；如需账号或网站验证，由使用者在自己的设备上操作，勿提交到 GitHub。
- 红果不需要账号登录。新建的匿名设备身份和临时播放信息仅保留在运行内存中。
- 上游配置管理功能可能在设备本地保存使用者自行设置的内容；仓库中的默认配置不包含个人登录信息。
- `src/hongguo.js` 为红果模块，`src/entry.js` 为统一入口，`src/upstream-patches.json` 记录对本次上游版本的精确修改。
- `vendor/fangkuia-jstv.js` 保留本次下载的上游原文件；构建时核对修改位置，避免静默改错版本。

修改后构建：

```sh
python3 scripts/build.py
```

构建会刷新根目录脚本及对应 `.md5`。`redguo-1.0.0` 标签保留整合前的红果独立版，作为定向回退入口。

## 来源与许可

非官方适配，与 JSTV 及内容平台无关联；仓库不托管视频内容。

整合上游为 [fangkuia/XPTV](https://github.com/fangkuia/XPTV)。红果签名算法参考 [sunnysky123/hongguo-web](https://github.com/sunnysky123/hongguo-web)，其注释标明上游为 jackotom/hongguo-drama、woshishiq1/drpys；匿名注册参考 [HongguoTV-Phone-TV-NoAds](https://github.com/qq294716498/HongguoTV-Phone-TV-NoAds)；红果视频采样索引适配参考 [Yswag/xptv-extensions](https://github.com/Yswag/xptv-extensions/tree/jstv)。

本项目自有适配及相关 GPL 组件按 GPL-3.0-or-later 提供，见 `LICENSE`；保留参考实现的 MIT 声明，见 `LICENSE.upstream-MIT`。上游文件中的各项版权与许可声明继续有效，不据此变更其原有授权。
