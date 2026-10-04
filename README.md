# 诊断类载入前校验器（JVM `()V` 静态方法类型状态验证）

飞控地面工具的载入闸门：审查员在网页粘贴单个 Base64 编码的 JVM class 文件
（≤ 64 KiB），页面经真实 API 对目标静态 `()V` 方法执行类型状态验证，给出

- **逐偏移入栈状态**：每条指令偏移处的局部变量 / 操作数栈类型；
- **处理器入口状态**：每个异常表项 handler 入口的局部变量与操作数栈；
- **通过**或**首个拒绝证据**：稳定定位到字节偏移（`offset` + `kind` + 消息）。

核心目标：确认异常跳转**不会把半初始化对象或错误操作数栈带入处理器**，
否则看似可载入的补丁会在故障路径崩溃。

复核页另有“**核对声明帧**”开关：开启后，除工作队列推导外，还会解析 Code
属性中的 **StackMapTable**，确认供应商写入的声明帧未以压缩帧掩盖错误控制流
（见下“声明帧核对”）。

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

## 声明帧核对（StackMapTable）

复核页“核对声明帧”开关（API 字段 `check_stackmap`）开启后，在既有分析
**通过的前提下**追加核对供应商写入的声明帧：

- 解析 Code 属性中的 StackMapTable，支持 `same`、
  `same_locals_1_stack_item`（含 extended）、`chop`、`append`、`full`
  五种帧形式，以及 `Top`/`Integer`/`Float`/`Null`/`Object`/`Uninitialized`
  验证类型（`Long`/`Double`/`UninitializedThis` 越出范围，按
  `unsupported-verification-type` 拒绝）；
- 偏移增量按 JVM 规则展开为绝对指令边界：首帧偏移 = `offset_delta`，
  后续帧 = 上一帧偏移 + `offset_delta` + 1；展开基准是静态 `()V` 方法的
  隐式初始帧（无局部变量、空操作数栈）；
- 逐帧与**可达推导状态**比较，比较遵守现有合并语义
  （`merge_types` 不可合并即拒绝）与构造完成后的身份替换语义
  （声明 `Uninitialized(offset)` 必须对应 `new` 指令，且推导状态在该槽位
  仍持有同一 `new@offset` 身份；构造完成后只能声明初始化后的引用）；
- 声明帧省略的局部变量槽位在推导状态中必须是 `top`（压缩帧不得掩盖
  存活槽位）；操作数栈高度必须与推导状态一致；
- 拒绝均定位到首个稳定字节偏移（帧或验证类型项在 class 文件中的位置）：
  跳入指令中部 / 越出代码（`bad-stackmap-target`）、压缩序列截断
  （`truncated-attribute`）、无效常量池项（`bad-constant-index`）、
  未初始化偏移不对应 `new`（`bad-stackmap-uninitialized`）、chop 下溢
  （`bad-stackmap-chop`）、保留帧标签（`unknown-stackmap-frame`）、
  未知验证类型标签（`unknown-verification-type`）、与推导状态槽位不一致
  （`stackmap-mismatch`）。

关闭开关时既有验证结论与响应保持兼容（不解析 StackMapTable，响应无
`stackmaps` 字段）；开启且通过时，响应与结果页给出每个声明帧的原始位置
（`table_offset`）、帧形式、展开偏移、展开状态及对应推导状态。

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
| `POST /api/verify` `{"class_b64": "...", "method": "可选", "check_stackmap": false}` | 见下 |

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

`check_stackmap: true` 时响应额外携带 `stackmaps`（未开启则无此字段）：

```json
"stackmaps": [{"table_offset": 183, "frame_type": 252, "kind": "append",
               "offset_delta": 11, "offset": 11,
               "locals": ["uninit(new@0 com/acme/Diag)"], "stack": [],
               "derived_locals": ["uninit(new@0 com/acme/Diag)"],
               "derived_stack": []}]
```

拒绝时 `ok=false` 且 `error={"offset": 4, "kind": "uninitialized-escapes-to-handler",
"message": "..."}`（`states`/`handlers` 为已计算的部分证据；声明帧核对失败时
`stackmaps` 为已成功核对的帧）。请求级错误
（非法 Base64、超过 64 KiB、缺字段）返回 4xx。主要 `kind`：
`truncated` / `truncated-attribute` / `truncated-instruction`、
`bad-branch-target`、`bad-handler-range`、`stack-height-mismatch`、
`incompatible-types`、`uninitialized-escapes-to-handler`、
`uninitialized-object-used`、`already-initialized`、`stack-underflow` /
`stack-overflow`、`local-index-out-of-range`、`fall-off-end`、
`unknown-opcode`、`non-converging`、`no-target-method` / `ambiguous-method`、
`bad-stackmap-target`、`bad-stackmap-uninitialized`、`bad-stackmap-chop`、
`stackmap-mismatch`、`unknown-stackmap-frame`、`unknown-verification-type` /
`unsupported-verification-type`。

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
python3 -m unittest discover -s tests -v     # 77 个单元/API 测试
PORT=8080 python3 -m app.server &            # 启动服务
APP_URL=http://127.0.0.1:8080 python3 verify/smoke.py   # 冒烟
```

## 布局

```
app/classfile.py   class 解析（常量池 / Code / 异常表 / StackMapTable，截断定位）
app/verifier.py    类型状态工作队列验证器（正常边 + 异常边 + 声明帧核对）
app/server.py      HTTP 服务（stdlib，无第三方依赖）
app/web/index.html 复核页
tests/             class 构造器 + 单元测试 + API 测试
verify/smoke.py    Compose verify 服务的一次性冒烟脚本
Dockerfile / docker-compose.yml
```
