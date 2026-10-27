# JSTV-myself · 红果短剧独立源

本订阅仅保留「红果短剧·独立版」。适用于支持 CatPawOpen Node.js 订阅源的 JSTV，提供真人短剧、漫剧、AI 剧的分类、搜索、分集与播放。

## 添加订阅

在 JSTV 的「订阅」→「＋」→「添加订阅」中填写：

```text
https://raw.githubusercontent.com/luoyan333/JSTV-myself/main/index.js.md5
```

名称可填写「红果短剧独立源」。添加后选择该订阅，再进入「红果短剧·独立版」。

订阅只托管脚本，视频由设备向内容平台请求。无需另外部署服务器，也无需红果账号登录。GitHub 原始文件需要在设备当前网络中可访问。

## 功能

- 真人短剧、漫剧、AI 剧分类与筛选。
- 官方 App 搜索，首屏失败时回退官网网页搜索。
- 分集列表；自动选择最高可用画质，以及最高 720P、480P 两档。
- 视频分段读取、拖动进度与切集。
- 片源不提供兼容的所选画质时明确报错，不以高画质冒充低画质。

## 已验证范围

2026-10-27，在 macOS 的 JSTV 1.17（30）中完成导入、搜索、1080P HEVC 硬件解码与实际播放验证；进度跳转和切集经使用者实测通过。另对三部剧各一集完成完整音视频解码测试。

其他设备尚未实际验收；是否支持取决于设备的 JSTV 版本、Node.js 运行环境及解码能力。未对全部剧集作可播保证。

## 运行方式

脚本为当前运行会话新建匿名设备身份，用于内容接口请求；身份和临时播放信息仅保留在内存中。关闭源后清除，不读取现有账号凭据，不写入本机配置。

本机视频服务只监听回环地址，随 JSTV 运行，不对局域网或公网提供服务。平台接口、视频编码或网页结构变化可能导致失效。

## 文件

- `index.js`：独立源及所需算法，内置依赖，无需额外安装 npm 包。
- `index.config.js`：空默认配置。
- 两个 `.md5` 文件：对应脚本内容校验码。

更新源文件时，需要同步更新对应的 MD5 校验码。

## 来源与许可

本项目为非官方适配，与 JSTV、红果平台无关联。仓库仅包含适配代码，不托管视频内容。

签名算法参考 [sunnysky123/hongguo-web](https://github.com/sunnysky123/hongguo-web)，其注释标明上游为 jackotom/hongguo-drama、woshishiq1/drpys；匿名设备注册参考 [HongguoTV-Phone-TV-NoAds](https://github.com/qq294716498/HongguoTV-Phone-TV-NoAds)；视频采样索引适配参考 [Yswag/xptv-extensions](https://github.com/Yswag/xptv-extensions/tree/jstv)。

适配源代码按 GPL-3.0-or-later 提供，见 `LICENSE`。同时保留参考实现的 MIT 声明，见 `LICENSE.upstream-MIT`；各部分原有权利声明继续有效。
