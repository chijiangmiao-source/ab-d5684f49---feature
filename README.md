# 诊断类载入前校验器（JVM `()V` 静态方法类型状态验证）

飞控地面工具的载入闸门：审查员在网页粘贴单个 Base64 编码的 JVM class 文件
（≤ 64 KiB），页面经真实 API 对目标静态 `()V` 方法执行类型状态验证，给出

- **逐偏移入栈状态**：每条指令偏移处的局部变量 / 操作数栈类型；
- **处理器入口状态**：每个异常表项 handler 入口的局部变量与操作数栈；
- **通过**或**首个拒绝证据**：稳定定位到字节偏移（`offset` + `kind` + 消息）。

核心目标：确认异常跳转**不会把半初始化对象或错误操作数栈带入处理器**，
否则看似可载入的补丁会在故障路径崩溃。

## 验证规则

- 自行解析 class 常量池与 `Code` 属性（`app/classfile.py`），不依赖任何外部库；
- 按 JVM 验证的工作队列算法（`app/verifier.py`）沿**正常边与异常边**传播类型状态，
  汇合点按类型格合并；
- 未初始化对象只以产生它的 `new` 指令偏移为身份追踪（`uninit(new@<pc> <class>)`）：
  - 构造成功前**不得进入处理器路径**（异常边上局部变量含未初始化对象 → 拒绝）；
  - **不得与已初始化引用合并**（汇合冲突 → 拒绝）；
  - `invokespecial <init>` 成功后，同一 `new` 身份的所有副本（局部变量 + 栈）一并初始化；
- 控制流汇合时槽位数量与类型必须兼容（栈高不一致 / 类型不兼容 → 拒绝）；
- 稳定定位字节偏移的结构性拒绝：截断属性 / 截断指令、跳入指令中部、
  无效处理器范围（越界、空区间、未对齐指令边界）、栈高不一致、无法收敛
  （分析步数保险丝，默认 200000 步）；
- 服务无状态，每次提交独立验证；页面在重新提交或修改输入时**清除旧结论**。

## 范围

- 目标方法：静态 `()V`（多个时需用 `method` 字段指定）；无字段访问；
- 指令集：常量（`iconst`/`bipush`/`sipush`/`ldc`）、`iload/aload/istore/astore` 系列、
  `iinc`、int 运算、`pop/dup`、分支（`if*`/`goto`/`goto_w`）、`new`、
  `invokespecial <init>`、`athrow`、`return`、异常表；
- 越出范围的指令 / 常量按 `unknown-opcode` / `unsupported-*` 拒绝并定位偏移。

## API

| 请求 | 响应 |
| --- | --- |
| `GET /` | 复核页 |
| `GET /health` | `{"status":"ok"}` |
| `POST /api/verify` `{"class_b64": "...", "method": "可选"}` | 见下 |

```json
{
  "ok": true,
  "class": "Smoke", "method": "run", "descriptor": "()V",
  "max_stack": 2, "max_locals": 1,
  "states":   [{"offset": 0, "insn": "new com/acme/Diag", "reachable": true,
                "locals": ["top"], "stack": []}],
  "handlers": [{"start_pc": 0, "end_pc": 9, "handler_pc": 9,
                "catch": "java/lang/Throwable", "table_offset": 147,
                "reachable": true, "locals": ["top"],
                "stack": ["ref java/lang/Throwable"]}],
  "error": null
}
```

拒绝时 `ok=false` 且 `error={"offset": 4, "kind": "uninitialized-escapes-to-handler",
"message": "..."}`（`states`/`handlers` 为已计算的部分证据）。请求级错误
（非法 Base64、超过 64 KiB、缺字段）返回 4xx。主要 `kind`：
`truncated` / `truncated-attribute` / `truncated-instruction`、
`bad-branch-target`、`bad-handler-range`、`stack-height-mismatch`、
`incompatible-types`、`uninitialized-escapes-to-handler`、
`uninitialized-object-used`、`already-initialized`、`stack-underflow` /
`stack-overflow`、`local-index-out-of-range`、`fall-off-end`、
`unknown-opcode`、`non-converging`、`no-target-method` / `ambiguous-method`。

## 运行（Docker Compose）

```bash
# 构建镜像并运行一次性 verify 服务（单元测试 + API/HTTP 冒烟），
# verify 完成即退出，退出码即结果：
docker compose up --build --exit-code-from verify --abort-on-container-exit

# 仅启动复核页（宿主端口可配置，默认 8080）：
HOST_PORT=9090 docker compose up app
# 复核页:  http://localhost:9090/     健康:  http://localhost:9090/health
```

`verify` 服务等待 `app` 健康检查后执行
`python -m unittest discover -s tests -v && python verify/smoke.py`，
全部通过以状态码 0 退出，否则非 0。

## 本地开发（无 Docker）

```bash
python3 -m unittest discover -s tests -v     # 47 个单元/API 测试
PORT=8080 python3 -m app.server &            # 启动服务
APP_URL=http://127.0.0.1:8080 python3 verify/smoke.py   # 冒烟
```

## 布局

```
app/classfile.py   class 解析（常量池 / Code / 异常表，截断定位）
app/verifier.py    类型状态工作队列验证器（正常边 + 异常边）
app/server.py      HTTP 服务（stdlib，无第三方依赖）
app/web/index.html 复核页
tests/             class 构造器 + 单元测试 + API 测试
verify/smoke.py    Compose verify 服务的一次性冒烟脚本
Dockerfile / docker-compose.yml
```
