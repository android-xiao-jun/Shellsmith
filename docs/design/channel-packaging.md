# 渠道包写入设计

## 目标

给已加固并签名的 APK 批量写入 Walle 兼容渠道号，产出 `原文件名_渠道名.apk`。实现位于 `crates/shield-core/src/channel.rs`，不依赖 JDK、walle-cli 或按平台分发的 JDK，CLI 与 GUI 共用同一套逻辑。

## 数据格式

渠道号存放在 APK Signing Block 的 ID-value 对中：

```text
APK Signing Block
  size(8)                     块总长度减 8
  pair: len(8) + id(4) + value
    id = 0x71777777           Walle 渠道 ID
    value = {"channel":"..."} UTF-8
  pair: ...                   其他 V2/V3 签名、source stamp 等条目
  size(8)                     与首部长度一致
  magic(16)                   "APK Sig Block 42"
```

读取时兼容 `{"channel":"..."}` 与纯 UTF-8 渠道字符串。写入时只替换渠道 pair，删除旧 verity padding 后按 4096 字节对齐重新生成，其余 pair 保持原顺序和原始字节。

## 写入流程

1. 从文件尾部回扫最多 `22 + 65535` 字节定位 EOCD，校验签名与注释长度；ZIP64 或超过 4GB 时拒绝。
2. 从 Central Directory 起点向前读取 24 字节 footer，校验签名块魔数与头尾长度一致。
3. 解析 ID-value 对，过滤旧渠道与 verity padding，追加新的渠道 pair。
4. 重建签名块，写入临时文件：先复制签名块之前的原始内容，再写新签名块，最后复制 Central Directory 与 EOCD。
5. 仅修改 EOCD 中 Central Directory 偏移字段，保留 ZIP 注释；完成后原子替换目标文件。
6. 回读产物渠道号做自检。

V2/V3 签名覆盖 APK 内容、Central Directory 和去掉 CD 偏移字段后的 EOCD，不覆盖 Signing Block 本身，因此在签名后追加渠道 pair 不会破坏签名。

## 约束与边界

- 输入 APK 必须有 APK Signing Block（V2/V3 签名）；V1-only 或未签名 APK 直接失败。
- 必须先签名再写渠道。写渠道后 APK 字节发生变化，不能再修改内容、重新签名或再次 zipalign。
- 启用 V4 时，原 `.idsig` 与新的 APK 不匹配，需要重新生成；默认关闭 V4。
- ZIP64 与超过 4GB 的 APK 不在当前支持范围。
- 渠道名非空、最多 256 个字符，禁止控制字符、双引号和反斜杠；重复渠道在写入前拒绝。
- 文件名中的 `\ / : * ? " < > |` 与控制字符替换为 `_`，规避 Windows 保留名和尾随点/空格；渠道过长时截断并附加摘要后缀。
- 批量写入串行执行；每个渠道包都是一份完整 APK 副本，需预留 `渠道数 × APK 大小` 的磁盘空间。
- 输出已存在时默认报错，`--force` 才会覆盖；输入与输出不能是同一文件。
- 取消只清理当前临时文件，已完成的渠道包保留。

## 入口

CLI：

```bash
shield channel get <APK>
shield channel batch --input <APK> --channels-file <FILE> [--output-dir <DIR>] [--force] [--json]
```

GUI：独立“渠道包”页面，支持选择 APK、读取当前渠道、导入 `channels.txt`、选择输出目录、覆盖开关、进度与取消。

#### Android 端接入

运行时读取渠道号需要引入 Walle library。若同时使用 Walle Gradle 插件生成渠道包，再配置 plugin；Shellsmith 已经负责写渠道，业务工程只需要 library 即可读取。

根目录 `build.gradle`：

```gradle
buildscript {
    dependencies {
        classpath 'com.meituan.android.walle:plugin:1.1.7'
    }
}
```

App 模块 `build.gradle`：

```gradle
apply plugin: 'walle'

dependencies {
    implementation 'com.meituan.android.walle:library:1.1.7'
}
```

读取渠道：

```java
String channel = WalleChannelReader.getChannel(Utils.getApp(), "default");
```

`com.meituan.android.walle:plugin:1.1.7` 及 `apply plugin: 'walle'` 仅在使用 Walle Gradle 插件生成渠道包时需要；Shellsmith 写入的渠道包不需要该插件，但读取仍需要 library。Walle 从 APK Signing Block 读取渠道，因此 APK 必须保持 V2/V3 签名。

## 验证

- `crates/shield-core/src/channel.rs` 单元测试覆盖读取、替换、保留其他签名块条目、ZIP 注释、无签名块拒绝、非法/重复渠道、文件名安全化、覆盖策略与取消。
- `tests/scripts/run-protect-e2e.sh` 在真实签名 APK 上生成两个渠道包，并用 `apksigner verify`、`shield channel get`、`unzip -t` 校验，同时确认源 APK 未被修改。
- GUI 前端测试覆盖渠道文本解析规则。
