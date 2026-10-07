# http1-audit — 离线 HTTP/1.1 请求消息裁决网关

对一条抓包得到的原始 HTTP/1.1 请求做**离线、确定性**裁决，判定其唯一消息边界，
阻止前后端因正文长度理解不一致而产生的请求走私。零第三方依赖，仅使用
Python 3.11 标准库。

## 接口

`POST /api/http1/audit`

```json
{ "captureBase64": "<base64 编码的完整 HTTP/1.1 请求报文>" }
```

解码后的报文不得超过 **256 KiB**。

### 成功响应（HTTP 200）

```json
{
  "ok": true,
  "method": "POST",
  "target": "/api/http1/audit?id=1",
  "host": "example.com:8443",
  "framing": "content-length | chunked | none",
  "bodyLength": 11,
  "bodySha256": "b94d27b9…（小写 hex）",
  "trailers": [{ "name": "X-Checksum", "value": "deadbeef" }]
}
```

`trailers` 按字段到达顺序返回。

### 失败响应（HTTP 400 信封错误 / 422 报文裁决错误）

```json
{ "ok": false, "error": "<稳定错误码>", "offset": 58 }
```

`offset` 是首个错误字节的偏移；截断类错误指向 `len(data)`，无具体字节可指时为
`null`。

## 裁决策略

| 类别 | 规则 |
|---|---|
| 行结束 | 必须严格 CRLF；裸 CR/LF 按 `bad_line_ending` 拒绝；禁止 obsolete 折行 |
| 请求行 | `方法 SP origin-form SP HTTP/1.1`；方法为合法 token；target 为 ASCII origin-form（`absolute-path [ "?" query ]`，RFC 3986 pchar/百分号编码）；拒绝 absolute-form |
| Host | 有且仅有一个（大小写不敏感），值为合法 uri-host[":"port]（含 IPv6 字面量） |
| Content-Length | 零或一个；值为**规范十进制**（纯 DIGIT、无前置零/空白/符号） |
| Transfer-Encoding | 仅允许单独的 `chunked`（无其它编码、无重复、无参数）；与 Content-Length 同时出现一律 `conflicting_framing` |
| 定长正文 | 正文必须与 Content-Length **完全等长**，短了 `content_length_mismatch`，多了 `trailing_bytes` |
| 分块正文 | 合法十六进制块长、完整块数据、块后必须 CRLF、必须有终止块；不接受块扩展（`;…`） |
| 尾部字段 | 必须由 `Trailer` 预先逐项声明；不得是分帧/路由相关字段（Host、Content-Length、Transfer-Encoding、Connection、Upgrade、TE、Trailer、Keep-Alive、Proxy-*） |
| 消息结束 | 终止空行之后不得再有任何字节 |

典型错误码：`malformed_request_line`、`invalid_method`、`invalid_request_target`、
`invalid_http_version`、`missing_host`、`duplicate_host`、`invalid_host`、
`duplicate_content_length`、`invalid_content_length`、`conflicting_framing`、
`invalid_transfer_encoding`、`incomplete_chunk`、`invalid_chunk_size`、
`chunk_extension_not_allowed`、`bad_chunk_terminator`、`undeclared_trailer`、
`forbidden_trailer`、`invalid_trailer_declaration`、`trailing_bytes`、
`bad_line_ending`、`obsolete_line_folding`、`payload_too_large`。

## 目录结构

```
app/parser.py      纯函数裁决器（无 I/O）
app/server.py      stdlib ThreadingHTTPServer，POST /api/http1/audit + GET /healthz
tests/test_audit.py 53 个单元测试
smoke/verify.py    一次性验证作业：单测 + 构建检查 + 定长/分块/走私拦截冒烟
Dockerfile         python:3.11-slim，内置 HEALTHCHECK
docker-compose.yml api（可配置宿主端口）+ verify（一次性服务）
```

## 运行

```bash
# 构建并启动 API（宿主端口可用 API_PORT 覆盖）
API_PORT=9090 docker compose up -d api

# 一次性验证：等待 api 健康后运行全部检查，以退出码报告结果
docker compose up verify; docker compose inspect verify --format '{{.State.ExitCode}}'
# 或查看日志
docker compose logs verify
```

无 Docker 时可直接本地运行：

```bash
python -m unittest discover -s tests          # 单元测试
PORT=8080 python -m app.server                 # 启动 API
API_URL=http://127.0.0.1:8080 python smoke/verify.py
```

## 调用示例

```bash
printf 'POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello' \
  | base64 | jq -Rs '{captureBase64: .}' \
  | curl -sS -H 'Content-Type: application/json' --data @- \
      http://localhost:8080/api/http1/audit
```
