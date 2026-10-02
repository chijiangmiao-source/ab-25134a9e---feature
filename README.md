# Seafloor Signed Checkpoint Log

岸基值班员核验海底观测站签名树根（signed tree head）的服务：首个有效检查点冻结
Ed25519 公钥，更大的树必须携带 RFC 9162 一致性证明确认旧树是新树前缀，同尺寸的
已验签分叉将封存首个证据且永不改写已发布历史。

纯 Python 3.11 标准库实现（自带 RFC 8032 Ed25519 与 RFC 9162 Merkle 算法），
镜像无任何第三方 pip 依赖，数据持久化在 SQLite（WAL + 原子事务）中。

## 快速开始

```bash
# 在可配置宿主端口启动 API（默认 0.0.0.0:18080）
docker compose up --build -d api

# 运行容器内验收服务（HTTP 冒烟 + 算法测试 + 镜像构建检查），退出码即结论
docker compose run --rm verify

# 或一条命令：构建、启动、验收、按验收码退出
docker compose up --build --abort-on-container-exit --exit-code-from verify verify
```

可配置发布地址与端口：

```bash
API_PUBLISH_HOST=0.0.0.0 API_PUBLISH_PORT=9090 docker compose up --build -d api
```

健康检查：`GET /healthz` → `200 {"status":"ok"}`（容器内置 HEALTHCHECK）。

## HTTP API

### `POST /logs/{logId}/checkpoints`

请求体（JSON，字段均为小写 hex 字符串；`consistency` 为 hex 数组）：

```json
{
  "public_key":   "<32 字节 Ed25519 公钥，hex>",
  "tree_size":    7,
  "timestamp_ms": 1790000000000,
  "root_hash":    "<32 字节 SHA-256 根，hex>",
  "signature":    "<64 字节 Ed25519 签名，hex>",
  "consistency":  ["<32 字节证明节点，hex>", "..."]
}
```

**签名覆盖的是规定的原始二进制消息，不是 JSON 转写结果。** 二进制布局
（大端序）：

```
MAGIC(16B, "SEAFLOOR-LOGCPT1") || u16 log_id 长度 || log_id(ASCII)
|| public_key(32B) || u64 tree_size || u64 timestamp_ms || root_hash(32B)
```

`logId` 为非空、≤256 字节的可打印 ASCII（0x20–0x7E）。

裁决规则：

| 情形 | 状态码 | `error.code` / `result` |
|---|---|---|
| 首个有效提交（`consistency` 必须为空） | 201 | `result=frozen`，密钥冻结 |
| 有效更大树且证明旧树为新树前缀 | 200 | `result=trusted, applied=true` |
| 相同扩展的并发/串行重传 | 200 | 一次 `trusted`，其余 `already_trusted` |
| 同尺寸但根/时间/密钥/签名不同（已验签） | 409 | `fork_evidence_sealed`，封存首个分叉证据，原记录不变 |
| 封存分叉后的任何推进 | 409 | `log_sealed` |
| 更小的树大小 | 409 | `stale_tree_size` |
| 扩展换用未冻结密钥 | 409 | `public_key_frozen` |
| 空/截断/伪造证明、错误哈希 | 400 | `invalid_consistency_proof` |
| 签名不覆盖规范二进制消息 | 400 | `invalid_signature` |
| 字段缺失/长度错误/hex 非法 | 400 | `missing_fields` / `invalid_field`（details 带字段定位） |

所有校验在任何持久化写入之前完成；拒绝不留半成品。错误体形如：

```json
{"error": {"code": "invalid_consistency_proof",
           "message": "consistency proof failed: ...",
           "details": {"trusted_tree_size": 6, "proof_nodes": 2}}}
```

### `GET /logs/{logId}`

返回可信树大小、根哈希、时间戳、冻结公钥、状态（`active` /
`fork_sealed`）及首个分叉证据（`fork` 字段，含可信头与分叉头的完整快照与签名）。

另有 `GET /healthz` 与 `GET /logs`。

## 持久化与并发

* 命名卷 `checkpoint-data` 上的 SQLite，`PRAGMA synchronous=FULL`、WAL 日志；
  状态推进在单条 `BEGIN IMMEDIATE` 事务中完成（更新 `logs` + 插入
  `checkpoints`），重启后可信检查点与分叉记录均可查询。
* 进程内可重入锁串行化"读取-裁决-写入"区间；并发相同扩展恰好一次落库，所有
  调用方拿到同一裁决。
* `forks` 表对 `(log_id, rival_sig)` 去重并只保留首个证据。

## 验收服务 `verify`

`docker compose run --rm verify` 在同一镜像内执行（退出码 0=通过）：

1. 等待 `/healthz` 健康；
2. Ed25519 RFC 8032 测试向量与"签名必须覆盖二进制而非 JSON"检查；
3. RFC 9162 一致性证明穷举测试（尺寸 1..32 全部前缀对、截断、伪造、空证明）；
4. HTTP 冒烟：首次冻结 → 合法扩展 → 篡改旧前缀叶的伪造扩展 → 截断证明 →
   过期大小 → 密钥轮换 → 相同扩展并发重传（断言恰好一次推进）→ 重放；
5. 镜像构建检查（构建时烘焙的 `/app/IMAGE_BUILD` 标记、无第三方依赖、
   CPython 版本；挂载 `/var/run/docker.sock` 时还会核对 api/verify 同源镜像）；
6. 同尺寸分叉冒烟：不同根/密钥的已验签对手头封存证据、第二个对手头不覆盖首证、
   封存后拒绝推进、伪造签名不留证据；
7. 直接只读核验 SQLite 持久化记录；挂载 Docker socket 时重启 `api` 容器后
   重新查询可信检查点与分叉记录。

## 本地开发（无 Docker）

```bash
python3 -m unittest discover -s tests -v
API_PORT=18080 DB_PATH=/tmp/cp.db python3 -m app.server
API_BASE=http://127.0.0.1:18080 DB_PATH=/tmp/cp.db \
  IMAGE_BUILD_MARKER=./IMAGE_BUILD.placeholder python3 acceptance/harness.py
```

## 目录

```
app/canonical.py   规范二进制消息
app/ed25519.py     RFC 8032 纯标准库实现
app/merkle.py      RFC 9162 树哈希/一致性/包含证明
app/storage.py     SQLite 事务存储
app/server.py      HTTP API 与裁决逻辑
acceptance/harness.py  verify 服务验收程序
tests/             算法与服务规则单元测试
Dockerfile, docker-compose.yml
```
