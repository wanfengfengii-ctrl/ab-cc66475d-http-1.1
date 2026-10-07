# http1-audit — HTTP/1.1 消息边界裁决网关

工业接入网关的离线裁决服务：对一条 HTTP/1.1 原始请求判定**唯一消息边界**，
凡前后端可能产生长度理解分歧的报文一律拒绝，避免请求走私数据被放行。

纯 Python 标准库实现，无第三方依赖。

## 裁决规则

- 解码后报文 ≤ 256 KiB；全程使用 CRLF；方法为合法 token；目标为 ASCII
  origin-form；有且仅有一个 Host；消息结束后不得有多余字节。
- 无 Transfer-Encoding 时：允许零个或一个**规范十进制** Content-Length
  （无前导零、无符号、纯数字），正文必须与其完全等长。
- Transfer-Encoding 仅可为单独的 `chunked`（大小写不敏感），且不得与
  Content-Length 同时出现。
- 分块正文：合法十六进制块长、完整块数据、终止块；**不接受块扩展**。
- 尾部字段必须由 Trailer 头**逐项预先声明**，且不得包含消息分帧或路由
  相关字段（Content-Length、Transfer-Encoding、Trailer、TE、Host、
  Connection、Keep-Alive、Upgrade）。

## API

### `POST /api/http1/audit`

请求：`{"captureBase64": "<base64 编码的原始 HTTP/1.1 请求>"}`

成功（200）：

```json
{
  "ok": true,
  "method": "POST",
  "target": "/api/x?y=1",
  "host": "example.com",
  "framing": "content-length",
  "bodyLength": 5,
  "bodySha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
  "trailers": [{"name": "X-Checksum", "value": "..."}]
}
```

- `framing`：`none` / `content-length` / `chunked`
- `bodySha256`：解码正文的小写 SHA-256
- `trailers`：按到达顺序排列的尾部字段

失败（422 裁决失败 / 400 请求错误 / 413 超限）：

```json
{"ok": false, "error": "TRAILING_BYTES", "offset": 47, "detail": "..."}
```

`offset` 为解码后报文中**首个错误字节**的 0 基偏移。

### 稳定错误码

| 错误码 | 含义 | offset 指向 |
|---|---|---|
| `EMPTY_MESSAGE` | 空报文 | 0 |
| `MESSAGE_TOO_LARGE` | 解码后超过 256 KiB | 262144（首个超限字节） |
| `INVALID_BASE64` | captureBase64 非法 | 0 |
| `BAD_API_REQUEST` | 请求信封格式错误 | 0 |
| `BAD_CRLF` | 头部区出现裸 LF | 该 LF 字节 |
| `INCOMPLETE_MESSAGE` | 头部行未以 CRLF 结束 | 报文末尾 |
| `BAD_REQUEST_LINE` | 请求行格式错误 | 0 |
| `BAD_METHOD` | 方法不是合法 token | 0 |
| `BAD_TARGET` | 目标非 ASCII origin-form | 首个非法字节 |
| `BAD_VERSION` | 非 HTTP/1.1 | 版本起始 |
| `BAD_HEADER` | 头部字段畸形（含 obs-fold） | 行首或非法字节 |
| `MISSING_HOST` | 缺少 Host | 头部区末尾 |
| `DUPLICATE_HOST` | Host 重复 | 第二个 Host 行首 |
| `AMBIGUOUS_FRAMING` | 歧义分帧：CL+TE 并存、CL/TE 重复、TE 非单独 chunked | 冲突头部行首 |
| `BAD_CONTENT_LENGTH` | CL 非规范十进制 | CL 行首 |
| `TRUNCATED_BODY` | 正文短于 CL | 报文末尾 |
| `BAD_CHUNK` | 坏块：非法块长/块扩展/块数据残缺/缺终止块 | 首个非法字节 |
| `ILLEGAL_TRAILER` | 非法尾部：未声明/禁用了分帧路由字段/畸形 | 尾部行首 |
| `TRAILING_BYTES` | 消息结束后有多余字节 | 首个多余字节 |

### `GET /healthz`

健康检查，返回 `{"status": "ok"}`。

## 运行

```bash
# 启动 API（宿主机端口可通过 HTTP1_AUDIT_PORT 配置，默认 8080）
HTTP1_AUDIT_PORT=9000 docker compose up --build api

# 一次性验证：API 健康后依次执行代码测试、构建检查、定长与分块冒烟，
# 随后自行退出，退出码即结果（0 通过 / 1 失败）
docker compose up --build --exit-code-from verify
```

本地（无 Docker）：

```bash
python -m unittest discover -s tests -t .   # 单元测试
python -m app.server                        # 启动 API（PORT 环境变量可改端口）
API_BASE=http://127.0.0.1:8080 python -m verify.verify   # 完整验证
```

## 项目结构

```
app/parser.py    消息边界裁决器（纯函数，bytes -> 裁决结果 / AuditError）
app/server.py    HTTP API（/api/http1/audit, /healthz）
tests/           单元测试
verify/          一次性验证服务（代码测试 + 构建检查 + 冒烟）
Dockerfile       API 镜像（含 HEALTHCHECK）
docker-compose.yml  api 服务（宿主机端口可配置）+ verify 一次性服务
```
