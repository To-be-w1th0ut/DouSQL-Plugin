# DouSQL V3.0.3 (U-Sec Team)

DouSQL 是一个功能强大的 Burp Suite SQL 注入自动化检测插件，支持多种检测技术和 FUZZ 功能。

## 作者

l1ch & w1th0ut

## 团队

**无界安全 (U-Sec)**

## 功能特性

### 多工具监听
- Proxy (代理)
- Repeater (重放器)
- Scanner (扫描器)
- Intruder (入侵者)
- 右键菜单手动发送 ("Send to DouSQL")

### SQL 注入检测技术
- **报错注入**：检测 SQL 错误信息（MySQL、Oracle、PostgreSQL、SQL Server 等）
- **布尔盲注**：通过 `AND 1=1`、`AND 1=2` 测试
- **时间盲注**：通过 `SLEEP()`、`exp(999)` 等延迟函数测试
- **数字型注入**：对数字参数进行 `-1`、`-0` 测试

### 参数类型支持
- URL 参数 (`?id=1`)
- Body 参数 (POST 表单)
- JSON 参数 (复杂嵌套结构)
- Cookie 参数
- XML 参数
- Multipart 参数

### FUZZ 功能
- **参数 FUZZ**：自动测试常见参数（order、sort、id、uid、key 等）
- **JSON 内部 FUZZ**：对 JSON 参数内部字段进行注入测试
- **参数追加 FUZZ**：向请求中追加新参数进行测试

## 配置文件

所有配置保存在 `dousql` 目录下：

| 文件名 | 功能 |
|--------|------|
| `xia_SQL_diy_payload.ini` | 自定义 Payload |
| `xia_SQL_diy_error.ini` | 自定义报错关键字 |
| `xia_SQL_whitelist.ini` | 参数白名单 |
| `xia_SQL_blacklist.ini` | 参数黑名单 |
| `xia_SQL_blacklist_urls.ini` | URL 黑名单 |
| `xia_SQL_fuzz_params.ini` | FUZZ 参数列表 |
| `xia_SQL_response_time_threshold.ini` | 响应时间阈值 |
| `xia_SQL_length_diff_threshold.ini` | 长度差异阈值 |
| `xia_SQL_param_filter_mode.ini` | 参数过滤模式 |

## 使用方法

### 安装插件

1. 下载 [DouSQL-Plugin.jar (v3.0.4)](https://github.com/To-be-w1th0ut/DouSQL-Plugin/releases/download/v3.0.4/DouSQL-Plugin.jar)
2. 在 Burp Suite 中：**Extender** → **Extensions** → **Add**
3. 选择 `DouSQL-Plugin.jar` 文件
4. 点击 **Next** 安装插件
5. ✅ **无需勾选 "Java file" 选项**（v3.0.4 已修复）

> 💡 **提示**: 如果 v3.0.3 加载失败，请使用 v3.0.4 版本

### 配置插件

1. 配置白名单/黑名单（可选）
2. 配置自定义 Payload（可选）
3. 启用要监控的工具（Proxy/Repeater）
4. 开始检测 SQL 注入漏洞

### 下载链接

- [最新版本 v3.0.4 ⭐推荐](https://github.com/To-be-w1th0ut/DouSQL-Plugin/releases/download/v3.0.4/DouSQL-Plugin.jar)
- [v3.0.3 (旧版本)](https://github.com/To-be-w1th0ut/DouSQL-Plugin/releases/download/v3.0.3/DouSQL-Plugin.jar)
- [所有版本](https://github.com/To-be-w1th0ut/DouSQL-Plugin/releases)

## 检测流程

```
HTTP 请求接收
    ↓
方法过滤 (仅 GET/POST)
    ↓
白名单过滤
    ↓
黑名单 URL 过滤
    ↓
静态文件过滤 (jpg、css、js 等)
    ↓
构建 MD5 指纹并去重
    ↓
参数黑白名单过滤
    ↓
遍历参数进行测试
    ↓
发送 Payload 并分析响应
    ↓
记录结果并判断漏洞
```

## 响应判断标准

1. **时间阈值**：响应时间 > 2000ms（可配置）
2. **长度差异**：响应长度差异 > 100 字节（可配置）
3. **报错信息**：匹配自定义错误关键字

## 注意事项

⚠️ **重要提醒**：
- 插件会发送大量请求，建议在测试环境中使用
- 响应时间测试可能会导致服务器负载增加
- 某些 WAF 可能会检测到测试行为并拦截
- 建议配置好白名单和黑名单，减少误报和漏报

## 版本历史

- **V3.0.3 Pro**：修复了 JSON Fuzz Payload 循环问题

## 编译说明

详细的编译方法请参考 [BUILD.md](https://github.com/To-be-w1th0ut/DouSQL-Plugin/blob/master/BUILD.md)

### 快速打包

```bash
# 使用提供的打包脚本
./package.sh

# JAR 文件会生成在 output/DouSQL-Plugin.jar
```

## 许可证

请遵守相关法律法规，仅用于合法的安全测试。

