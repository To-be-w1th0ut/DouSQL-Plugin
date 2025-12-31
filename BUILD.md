# DouSQL Plugin 编译说明

## 方式一：在 Burp Suite 中直接使用（推荐）

Burp Suite 会自动编译 Java 源码，这是最简单的方式：

1. 启动 Burp Suite
2. 进入 **Extender** → **Extensions** → **Add**
3. 选择 **DouSqlPluginComplete.java** 文件（`src/main/java/dousql/` 目录）
4. 勾选 **"Java file"** 选项
5. Burp Suite 会自动编译并加载插件

## 方式二：使用已发布的 JAR 包（最简单）

直接从 GitHub Releases 下载已编译好的 JAR 包：

1. 下载 [DouSQL-Plugin.jar](https://github.com/To-be-w1th0ut/DouSQL-Plugin/releases/latest)
2. 在 Burp Suite 中：**Extender** → **Extensions** → **Add**
3. 选择 `DouSQL-Plugin.jar` 文件
4. 点击 **Next** 完成安装

## 方式三：手动打包（高级）

使用提供的打包脚本重新创建 JAR：

```bash
# 运行打包脚本
./package.sh

# JAR 文件会生成在 releases/DouSQL-Plugin.jar
```

### 打包脚本说明

`package.sh` 会自动：
1. 创建输出目录结构
2. 生成 SPI 服务文件 (`META-INF/services/burp.api.montoya.BurpExtension`)
3. 生成 MANIFEST.MF 文件
4. 复制源代码和文档
5. 打包成 JAR 文件

### JAR 包结构

```
DouSQL-Plugin.jar
├── META-INF/
│   ├── MANIFEST.MF
│   └── services/
│       └── burp.api.montoya.BurpExtension  ← SPI 服务注册文件
├── dousql/
│   └── DouSqlPluginComplete.java
├── README.md
└── BUILD.md
```

## 文件说明

- `src/main/java/dousql/DouSqlPluginComplete.java` - 插件源代码
- `releases/DouSQL-Plugin.jar` - 已发布的 JAR 包
- `package.sh` - 打包脚本
- `README.md` - 项目说明文档
- `BUILD.md` - 本编译说明
- `.gitignore` - Git 忽略配置

## 技术栈

- **Java**: 11+
- **Burp API**: Montoya API 2024.x
- **依赖**: 无（Burp Suite 自带 API）

## 开发者

- **团队**: U-Sec (无界安全)
- **作者**: l1ch & w1th0ut
- **版本**: V3.0.4

## 许可证

请遵守相关法律法规，仅用于合法的安全测试。

