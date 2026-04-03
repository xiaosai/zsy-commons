# zsy-commons

个人 Java 工具库，沉淀日常开发中的常用代码。

## 模块说明

| 模块 | 说明 |
|------|------|
| `zsy-commons-core` | 核心工具：字符串、集合、日期、随机数等 |
| `zsy-commons-crypto` | 加密脱敏：日志脱敏、哈希、加解密等 |
| `zsy-commons-web` | Web 工具：请求处理、响应封装等 |
| `zsy-commons-json` | JSON 工具：Jackson 配置、序列化增强等 |

## 快速开始

### Maven 引入

```xml
<dependency>
    <groupId>io.github.zsy</groupId>
    <artifactId>zsy-commons-core</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Gradle 引入

```groovy
implementation 'io.github.zsy:zsy-commons-core:1.0.0'
```

## 环境要求

- Java 17+
- Maven 3.6+

## 构建

```bash
mvn clean install
```

## License

[Apache License 2.0](LICENSE)
