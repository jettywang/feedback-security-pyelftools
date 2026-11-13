# pyelftools CFI 离线崩溃展开：函数边界返回地址的规则选择

## 结论先行

pyelftools 的 CFI **解析层没有 bug**。`FDE.get_decoded()` 产出的每一行只记录区间
**起点 PC**（`Line['pc']`），行的有效范围是 `[本行 pc, 下一行 pc)`；FDE 的整体覆盖是
header 里的半开区间 `[initial_location, initial_location + address_range)`。

选错规则的根因在**上层地址解释**：把"当前 PC"和"返回地址"两种语义混为一谈，并用
`addr - 1` 统一处理。这两个输入对应不同的权威行：

| 输入 | 语义 | 正确的选行方式 |
|------|------|----------------|
| 当前 PC（活的、被中断的指令地址） | 该 PC 此刻所在的规则 | 选 `[start,end)` 包含该 PC 的 FDE，再取最后一个 `pc <= PC` 的行 |
| 返回地址（call 压栈的、call 之后那条指令） | 调用点的规则 | 取严格小于返回地址的最后一行；恰好在函数边界时，归属**前一个** FDE 的末行 |

对当前 PC 盲目减一，会把它挪进上一个函数，选到一个从未对该 PC 生效的 CFA 规则。
减一"碰巧正确"只发生在返回地址且地址不在边界上的情形——那是结果对、理由错，不能推广。

## 复现产物

- `build_ehframe_elf.py`：纯 Python 手工编码一个 x86-64 ET_REL，内含确定性 `.eh_frame`，
  不依赖编译器。覆盖 remember/restore_state、CFA 寄存器 rsp↔rbp 切换、FDE 间覆盖空洞、
  以及两个首尾相接的函数。
- `unwind.py`：基于 pyelftools 解码表的行选择器 + 单帧展开器，显式区分两种语义。
- `reproduce.py`：打印规则状态表、边界选行对比、统一减一的失败案例、单帧演算、
  未覆盖地址与缺失证据的停止行为。
- `test_cfi_unwind.py`：9 条 pytest 断言固化上述结论。
- `sample_x86_64.ehframe.o`：生成的最小 ELF。

运行：

```
python3 build_ehframe_elf.py
python3 reproduce.py
python3 -m pytest test_cfi_unwind.py -q
```

## 手工布局的 FDE 覆盖

```
FDE A (funcA) [0x1000,0x1040)
FDE B (funcB) [0x1040,0x1060)   # 与 A 首尾相接，边界 = 0x1040
(空洞)          [0x1060,0x1080)   # 无任何 FDE
FDE C (funcC) [0x1080,0x1090)
>= 0x1090                        # 无覆盖
```

## 规则状态表（funcA，由 pyelftools 实际解码）

| 行 PC | CFA | 保存的寄存器 | 关键指令 |
|-------|-----|--------------|----------|
| 0x1000 | rsp+8 | rbx@[cfa-8] r15@[cfa-16] r14@[cfa-24] rip@[cfa] | def_cfa + offsets，remember |
| 0x1008 | rsp+16 | 同上 | def_cfa_offset 16 |
| 0x1010 | rsp+16 | 同上 | remember |
| 0x1018 | **rbp+16** | 同上 | **def_cfa_register rbp（CFA 寄存器切换）** |
| 0x1020 | rsp+16 | 同上 | restore_state（回到 0x1010 状态） |
| 0x1028 | **rsp+8** | 同上 | restore_state（回到 0x1000 状态） |
| 0x1030 | rsp+8 | 上述 + rbp@[cfa-32] | 新增 rbp 保存规则 |

funcB 只有一行 `0x1040: CFA=rbp+128, rbx@[cfa-128]`，与 funcA 的规则刻意不同，
让边界选错时产生可观察的差异。

## 边界 0x1040 的两种裁决（同一数值，不同答案）

- 作为**当前 PC**：归属 funcB，选 `row 0x1040 CFA=rbp+128`。
- 作为**返回地址**：调用点在 funcA，选 funcA 末行 `row 0x1030 CFA=rsp+8`。

固定快照 `rsp=0x7000, rbp=0x5000` 下：
- 返回地址语义得到 `CFA=0x7008`，从 `[0x7008]` 取回调用者 PC `0x2000`，rbx/rbp 等
  按 funcA 的槽位正确还原。
- 若误用 funcB 规则，会算出 `CFA=rbp+128=0x5080`，去读完全不同的栈地址；这些槽位在
  给定内存中不存在，展开器据此报告 `incomplete` 而不是编造值。

## 给调用方的建议

1. 保留输入的来源标签：每个地址明确标注是 `CURRENT_PC` 还是 `RETURN_ADDR`，在选行
   之前不要做任何 `-1` 归一化。
2. 当前 PC：用 FDE 半开区间判覆盖，再取最后一个 `pc <= PC` 的行。
3. 返回地址：取严格小于该地址的最后一行（同一 FDE 内）；当地址恰好等于某 FDE 的
   `end` 时，调用者规则在前一个 FDE 的末行，而非下一个 FDE 的首行。
4. 地址不在任何 FDE 区间、或处于覆盖空洞、或不是任何 FDE 的精确边界：**停止推断**，
   报告"无规则行"，不要向相邻函数外推。
5. CFA 基址寄存器缺失、所需栈槽不在内存快照、或遇到不支持的规则类型（表达式等）：
   只返回已能确证的部分并标注 `incomplete`；拿不到返回地址就不要输出该层栈帧，
   绝不编造完整调用栈。
6. 单帧演算只在证据齐全时成立；多层展开应逐层重复上述校验，任一层失败即终止。

## 错误归属

- 解析（pyelftools `callframe.py`）：正确，行表与 FDE 覆盖均符合 DWARF 语义。
- 行选择（本目录 `unwind.py` 的职责）：必须区分半开区间与"严格小于"两种比较，
  这是容易出错但可正确实现的一层。
- 上层地址解释：**实际 bug 所在**——对返回地址与当前 PC 统一减一，导致函数边界上
  选到相邻函数的规则。
