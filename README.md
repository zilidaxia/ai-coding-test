# ai-coding-test

基于 Golang 实现的 Ollama 网站测绘 CLI。

该工具用于输入 `IP` 或 `CIDR 网段` 与 `端口范围`，扫描目标范围内可识别为 Ollama 服务的网站资产，并输出结构化结果。

## 项目目标

本项目聚焦两个核心点：

1. 做网站资产测绘，而不是只判断端口是否开放
2. 做 Ollama 服务识别，而不是只靠单个关键字或默认端口误判

因此扫描结果不仅包含 `ip`、`port`，还会尽量输出页面、请求协议、响应头、响应体、域名线索等资产信息。

## 已实现能力

- 支持输入单个 IP，例如 `127.0.0.1`
- 支持输入 CIDR 网段，例如 `192.168.1.0/24`
- 支持输入单个端口、逗号分隔端口、端口区间
- 支持并发扫描
- 支持 HTTP 和 HTTPS 双协议探测
- 支持识别响应协议版本：
  - `HTTP/1.0`
  - `HTTP/1.1`
  - `HTTP/2.0`
- 支持首页探测，提取：
  - `header`
  - `body`
  - `title`
  - `status_code`
- 支持 Ollama API 探测：
  - `/api/tags`
  - `/api/version`
- 支持 Ollama 指纹联合识别，避免只靠端口或单关键字误报
- 支持输出 `host` 与 `domain` 字段
- 支持从以下来源提取域名线索：
  - 反向 DNS
  - TLS 证书 SAN / CN
  - HTTP `Location`
  - 页面中的绝对 URL
- 支持 JSONL 输出
- 项目内附带 `HTTP/1.0` 和 `HTTP/2.0` 的 Ollama 样例数据集

## 当前识别策略

当前 Ollama 识别不是“端口是 `11434` 就判定为 Ollama”，而是综合以下信号：

- 首页正文是否出现 `Ollama` 关键词
- `/api/tags` 是否返回符合 Ollama 结构的 JSON
- `/api/version` 是否返回合法版本结构

当前的置信度分级为：

- `high`
  - `/api/tags` 命中
  - `/api/version` 命中
- `medium`
  - `/api/tags` 命中
  - 或首页出现明显 Ollama 特征

## 命令行用法

### 直接运行

```bash
go run . scan \
  --cidr 192.168.1.0/24 \
  --ports 80,443,8080,11434-11440 \
  --concurrency 128 \
  --timeout 3s \
  --body-limit 16384 \
  --insecure \
  --output result.jsonl
```

### 构建后运行

```bash
go build -o ollama-map .

./ollama-map scan \
  --cidr 192.168.1.0/24 \
  --ports 80,443,11434
```

## 参数说明

- `--cidr`
  - 必填
  - 支持单个 IP 或多个逗号分隔的 IP/CIDR
- `--ports`
  - 必填
  - 例如 `80,443,11434-11436`
- `--concurrency`
  - 并发 worker 数，默认 `64`
- `--timeout`
  - 单次请求超时时间，默认 `3s`
- `--body-limit`
  - 响应体保留字节数上限，默认 `16384`
- `--insecure`
  - 跳过 TLS 证书校验，适合自签证书环境
- `--output`
  - 输出文件路径，不传时输出到标准输出

## 输出字段

每条结果是一行 JSON，当前主要字段如下：

- `ip`
  - 实际连接的目标 IP
- `port`
  - 实际连接的目标端口
- `scheme`
  - 实际命中的协议方案，例如 `http` 或 `https`
- `url`
  - 本次探测命中的 URL
- `host`
  - 本次请求使用的 Host 值，默认是 `ip:port`
- `domain`
  - 从反向 DNS、证书、跳转、页面 URL 中提取出的域名列表
- `status_code`
  - 首页 HTTP 状态码
- `protocol`
  - 实际响应协议版本，例如 `HTTP/1.0` 或 `HTTP/2.0`
- `header`
  - 首页响应头
- `body`
  - 首页响应体摘要
- `title`
  - 页面标题
- `fingerprint`
  - 命中的 Ollama 指纹列表
- `confidence`
  - 指纹识别置信度
- `tls`
  - 是否为 TLS 连接

## 输出样例

```json
{"ip":"127.0.0.1","port":11434,"scheme":"https","url":"https://127.0.0.1:11434/","host":"127.0.0.1:11434","domain":["ollama.local"],"status_code":200,"protocol":"HTTP/2.0","header":{"Content-Type":["text/html"]},"body":"<html>...</html>","title":"Ollama","fingerprint":["api_tags_json","api_version_ok","homepage_keyword:ollama"],"confidence":"high","tls":true}
```

## 示例数据集

项目内附带示例数据集文件：

- `testdata/dataset/expected-assets.jsonl`

该文件包含两类 Ollama 服务样本：

- `HTTP/1.0`
- `HTTP/2.0`

这份数据集主要用于说明输出结构与协议识别结果，不代表真实生产环境资产。

## 测试与验证

### 运行全部测试

```bash
go test ./...
```

### 只验证扫描器集成能力

```bash
go test ./internal/scanner -run TestScanTargetsFindsOllamaFixtures -v
```

该集成测试会验证：

- 本地 `HTTP/1.0` Ollama 夹具可被识别
- 本地 `HTTP/2.0` Ollama 夹具可被识别
- 非 Ollama 页面不会误报

### 验证项目可编译

```bash
go build ./...
```

## 代码结构

项目主要结构如下：

```text
.
├── main.go
├── go.mod
├── README.md
├── docs/
│   └── superpowers/
│       ├── plans/
│       └── specs/
├── internal/
│   ├── config/
│   ├── fingerprint/
│   ├── model/
│   ├── output/
│   ├── probe/
│   └── scanner/
└── testdata/
    └── dataset/
```

### 各模块职责

- `main.go`
  - CLI 入口
  - 解析参数
  - 调用扫描器
  - 输出 JSONL

- `internal/config`
  - 解析命令行参数
  - 解析 CIDR、IP、端口范围
  - 控制输入边界

- `internal/probe`
  - 发起 HTTP 请求
  - 提取响应协议版本
  - 提取响应头、响应体、页面标题
  - 提取 TLS 证书中的域名线索

- `internal/fingerprint`
  - 根据首页和 API 响应做 Ollama 指纹识别
  - 输出指纹列表与置信度

- `internal/scanner`
  - 并发调度扫描任务
  - 先做 TCP 预探测
  - 根据端口选择优先协议顺序
  - 组合首页探测、API 探测、域名提取和指纹识别

- `internal/output`
  - 负责 JSONL 序列化输出

- `internal/model`
  - 定义统一资产结果结构

- `testdata/dataset`
  - 保存样例数据集输出

## 当前实现上的注意点

- 为避免超大网段导致长时间阻塞，当前对可展开 CIDR 范围做了限制
- 扫描器会先做 TCP 连接过滤未开放端口
- 对常见 HTTPS 端口会优先尝试 `https`
- 页面探测与 API 探测是分开的：
  - 页面探测用于资产输出
  - API 探测用于提高 Ollama 识别准确率

## 后续建议优化点

当前版本已经可用，但还有一些明确可优化的地方：

### 1. 协议探测策略可继续优化

当前实现只是“基于常见端口调整优先顺序”，对非常规 HTTPS 端口仍可能先打一轮 HTTP。

建议后续优化为：

- `http/https` 并发竞速
- 先做 TLS 特征预探测再决定协议
- 对同类目标做 scheme 缓存

### 2. Ollama 指纹还可以更严格

当前主要依赖首页关键词、`/api/tags`、`/api/version`。

后续可以继续加入：

- 更严格的 JSON 结构校验
- 更多 API 路径验证
- 反向代理场景下的特征补强
- favicon hash 或更稳定的页面特征

### 3. 输出格式可继续扩展

当前默认是 JSONL。

后续可以增加：

- CSV
- 表格输出
- 分页输出
- 结果去重策略配置

### 4. 扫描性能可继续提升

后续可以考虑：

- worker 池优化
- 连接复用优化
- 批量 DNS 解析
- 更细粒度的超时与重试策略

### 5. Host 头策略可继续增强

当前 `host` 默认使用 `ip:port`。

后续可以增加：

- 自定义 Host 头
- 域名字典探测
- 基于证书域名自动回探

## 设计文档

项目中还保留了设计与实现计划文档，便于继续扩展：

- `docs/superpowers/specs/2026-03-31-ollama-cli-design.md`
- `docs/superpowers/plans/2026-03-31-ollama-cli.md`

## 说明

本项目适合用于授权范围内的资产测绘、功能验证与本地实验。  
请勿在未授权场景下使用。
