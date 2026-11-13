# pyelftools 无节头 ELF 动态链接信息恢复审查

- 审查对象：本仓库 pyelftools `0.33`（`elftools/`）
- 焦点：`e_shoff=0 / e_shnum=0`（super-stripped，无节头）时，仅靠 `PT_LOAD` + `PT_DYNAMIC` 能恢复哪些动态链接信息，以及符号表长度是否来自**推测**
- 入口类：`elftools.elf.dynamic.DynamicSegment`（`elftools/elf/dynamic.py`）
- 复跑方式：
  - `python3 audit_sectionless_elf/run_experiments.py`（17 个损坏/对照场景，机器可读结果在 `results/experiment_results.json`）
  - `python3 audit_sectionless_elf/demo_inflation.py`（导入清单被夸大的最小复现，输出存 `results/demo_inflation.txt`）
- 样本：`samples/` 下每个场景一个 ELF（`*.elf`），由 `elfbuild.py`（ELF64）/`elfbuild32.py`（ELF32）确定性生成，无外部工具链依赖

---

## 1. 无节头时能恢复的信息与可信度

无节头 ELF 仍保留程序头与 `PT_DYNAMIC`。pyelftools 不依赖节头即可恢复：

| 信息 | 来源 | 是否依赖推测的符号表长度 |
|---|---|---|
| `DT_NEEDED` / `DT_RUNPATH` / `DT_SONAME` 等字符串标签 | 动态标签 + `DT_STRTAB`（`dynamic.py:161` `_get_stringtable`） | 否 |
| 动态标签全集（含 `DT_JMPREL`、`DT_RELA*`、版本标签等） | `PT_DYNAMIC` 内联数组，以 `DT_NULL` 终止（`dynamic.py:186` `_iter_tags`） | 否（但依赖 `DT_NULL`，见 §4） |
| 重定位表（REL/RELA/RELR/JMPREL） | 显式 `DT_*SZ` 大小 + 标签指针（`dynamic.py:234` `get_relocation_tables`） | 否，大小是文件显式声明 |
| 动态符号**数量** | 三条恢复路径，见 §2 | **是，除 SYSV `nchains` 外均为边界推测** |
| 动态符号条目与名字 | `DT_SYMTAB` + 上面的数量 + `DT_STRTAB`（`dynamic.py:368` `get_symbol`） | **是**，数量决定读到哪里为止 |
| 哈希查找（按名取符号） | `DT_HASH` / `DT_GNU_HASH`（`hash.py`） | 否，按桶/链索引定位，但链本身可能损坏 |

结论：**依赖库清单（NEEDED）与重定位信息不依赖符号表长度推测**；真正受推测长度影响的是“动态符号/导入函数清单”。后端若只要样本依赖了哪些 `.so`，可信度高；若要列全导入函数名，必须带上 §5 的完整性标记。

---

## 2. 符号表长度的三条恢复路径（按代码优先级）

`DynamicSegment._num_symbols`（`elftools/elf/dynamic.py:314-366`），`@cached_property`，只计算一次：

1. **DT_GNU_HASH 优先**（`dynamic.py:318-321`）→ `GNUHashTable.get_number_of_symbols`（`hash.py:150-171`）
   - 取桶数组中最大符号索引 `max_idx = max(buckets)`（`hash.py:155`）
   - 从该索引对应的链项开始，逐项读 4 字节链 word，直到最低位（end-of-chain）置 1（`hash.py:166-171`）
   - 返回 `max_idx + 1`；若最大桶索引 < `symoffset` 则返回 `symoffset`（`hash.py:156-157`）
   - **这是边界推导，不是显式长度**：长度 = 最高桶起点 + 其链长。
2. **其次 DT_HASH（SYSV）**（`dynamic.py:324-328`）→ `ELFHashTable.get_number_of_symbols`（`hash.py:67-70`）
   - 直接返回哈希头里的 `nchains` 字段。**这是文件显式声明的长度**，但字段可被任意伪造，pyelftools 不校验它是否与实际符号/链一致。
3. **相邻动态指针回退**（无任何哈希时，`dynamic.py:332-366`）
   - 先在所有标签里找满足 `d_ptr > DT_SYMTAB` 的最小值（“最近上界”，`dynamic.py:337-354`），用 `(nearest - symtab) / sizeof(Elf_Sym)` 得数量；
   - 找不到则回退到**包含 `DT_SYMTAB` 的那个 `PT_LOAD` 的 `p_vaddr + p_filesz`** 作为末端（`dynamic.py:357-364`）。
   - 这是纯粹的布局推测：假定符号表后面紧邻的下一个对象就是其边界。

地址翻译统一走 `ELFFile.address_offsets`（`elffile.py:264-275`），只在 `p_vaddr .. p_vaddr+p_filesz`（文件支撑范围）内映射，**不使用 `p_memsz`**。

---

## 3. 三类结果的划分原则

按证据强度把每个产出归入：

- **明确声明（DECLARED）**：值由文件中的显式长度/大小字段给出。
  - SYSV `nchains`（`hash.py:70`）、`DT_RELASZ/DT_RELSZ/DT_PLTRELSZ/DT_STRSZ`、`DT_SYMENT`。
  - 注意“显式”只表示有字段背书，**不表示该字段未被伪造**；§4 显示 `nchains` 可被直接夸大/缩小。
- **可由边界推导（DERIVED）**：无显式长度，但从文件内可验证的结构边界算出。
  - GNU 哈希链走终止位、相邻指针上界、`PT_LOAD` 的 `p_filesz` 末端。
  - 前提是底层结构（桶、链终止位、标签布局）本身完好；一旦损坏，推导值不可信。
- **信息不足（INSUFFICIENT）**：没有可验证边界，或读取落入零填充/EOF/相邻对象。
  - 此时要么抛异常（良好情形，见 §4），要么静默把任意字节包装成 `Symbol`（危险情形）。**绝不能把这些字节计入导入清单。**

判据补充：`get_symbol`（`dynamic.py:368-383`）对每个索引都 `struct_parse(Elf_Sym)` 再用 `st_name` 去 strtab 取名，**不校验 `st_name` 是否落在 `DT_STRSZ` 范围内、不校验 `st_info/st_shndx` 合理性**。因此越界读出的垃圾也能产生一个“有名字”的 `Symbol`（demo 中 ELF32 越界项的 `st_name` 恰好落进 strtab，凭空造出 `libc.so.6` 导入）。

---

## 4. 损坏形式如何截断或夸大导入清单（带源码位置与实证）

样本 ID 对应 `samples/<id>.elf` 与 `results/experiment_results.json`。真实符号数均为 4（含下标 0 的 null 符号）。

| 样本 ID | 损坏形式 | 路径 | pyelftools 实测行为 | 对导入清单的影响 | 关键源码 |
|---|---|---|---|---|---|
| `base_gnu` / `base_sysv` / `base_fallback` | 完好无节头对照 | 三条 | 均返回 4，名字正确 | 无（基线） | `dynamic.py:314` |
| `gnu_no_terminator` | GNU 链末项缺终止位 | GNU | 真 EOF：`ELFParseError`；其后有可读字节：**静默返回 11（真实 4）** | 有相邻数据时**夸大**，越界字节被当符号 | `hash.py:166-171` |
| `gnu_sparse_bucket` | 最高桶起点超出真实链 | GNU | 同上：EOF 报错 / 有数据时**静默 11** | **夸大**（稀疏桶把链起点推到表外） | `hash.py:155,160-161` |
| `gnu_chain_bss` | 链需走进零填充(BSS)才到终止位 | GNU | `ELFParseError`（BSS 无文件支撑，读不到终止位） | 信息不足，无法出清单 | `elffile.py:272-275` + `hash.py:167` |
| `gnu_zero_buckets` | `nbuckets` 被置 0 | GNU | **裸 `ValueError: max() empty`**（非 ELFError 体系） | 分析中断 | `hash.py:155` |
| `sysv_inflate` | `nchains` 调大 3 | SYSV | 正常返回 **7（真实 4）**，后 3 项为空名符号 | **夸大**，完全跟随伪造字段 | `hash.py:70` |
| `sysv_deflate` | `nchains` 调小 2 | SYSV | 正常返回 **2** | **截断**，真实导入丢失且无告警 | `hash.py:70` |
| `sysv_inflate_eof` | `nchains` 调大到越过 EOF | SYSV | `ELFParseError`（读符号越界） | 信息不足 | `dynamic.py:375-378` |
| `fallback_dup_strtab` | 注入更低的重复 `DT_STRTAB` 指针 | 回退 | 正常返回 **1（只剩 null）** | **静默截断**：伪造上界把表末端拉到表前 | `dynamic.py:349-354` |
| `fallback_dup_symtab` | 注入更低的重复 `DT_SYMTAB` | 回退 | 返回 4（不受影响） | 无：`get_table_offset` 只取首个匹配，且该指针在表前不构成上界 | `dynamic.py:144-159` |
| `fallback_truncated` | 文件在推导边界前被截断 | 回退 | `ELFParseError`（短读） | 信息不足 | `dynamic.py:375` |
| `gnu_symtab_bss` | `DT_SYMTAB` 指向零填充区 | GNU | `ELFError: Segment does not contain DT_SYMTAB` | 信息不足（地址无法翻译） | `dynamic.py:333-334` + `elffile.py:272` |
| `fallback_strtab_bss` | `DT_STRTAB` 指向零填充区 | 回退 | **裸 `AssertionError`**（非 ELFError 体系） | 分析中断；上层若只捕 `ELFError` 会漏 | `dynamic.py:182-183` |
| `fallback_bss_boundary` | 末端边界落在零填充 | 回退 | 返回 4，正确 | 无：回退用 `p_filesz` 而非 `p_memsz`，BSS 被排除 | `dynamic.py:357-364` |
| `gnu_drop_null` | 删除 `DT_NULL` | GNU | `num_symbols` 正常（GNU 路径不扫标签）；但 `iter_tags()`/`num_tags()`/回退路径均 `ELFParseError` | 符号数可用，标签遍历不可用 | `dynamic.py:191-196,226-230` |

两类**非 ELFError 异常**需要后端特别兜底：
- `ValueError`（`hash.py:155`，空桶数组上 `max()`）
- `AssertionError`（`dynamic.py:183`，无节头且 `DT_STRTAB` 不可翻译时，`.dynstr` 节回退也失败）

只 `except ELFError` 的调用方会让这两类异常逃逸成未处理崩溃（拒绝服务面）。

### 关键机制说明

- **夸大来自“无终止 + 有相邻数据”**：GNU 链走循环（`hash.py:166`）没有最大步数/边界检查，只用裸 `stream.read`（`hash.py:167`）。读到 EOF 时短读抛 `ELFParseError`；但若符号表后面还有被映射的数据（同一 `PT_LOAD` 内的下一张表、填充、或加载器拼入的相邻内容），循环会持续把这些 word 当链项，直到偶发遇到最低位为 1 的字，再据 `max_idx+1` 让 `iter_symbols` 把对应字节解析成符号。
- **截断来自“被污染的上界”**：回退路径对**所有**标签的 `d_ptr` 取最近上界（`dynamic.py:337-354`），不区分该指针是否真的是符号表后继。重复或被改小的 `DT_STRTAB` 即可制造一个落在符号表内部的“边界”。
- **零填充默认安全，但前提是翻译被拒**：`address_offsets` 用 `p_filesz` 而非 `p_memsz`（`elffile.py:274`），BSS 地址返回空迭代器，因此落入 BSS 的表指针会走到报错而不是读到全 0 符号。这是当前实现里正确的一面；风险在于 GNU 链走不经过 `address_offsets` 的逐符号边界检查，而是直接按文件偏移 `stream.read`。
- **SYSV 字段无交叉校验**：`nchains` 被直接信任（`hash.py:70`），不与桶/链内容或 `DT_SYMTAB..下一边界` 的跨度比对，故 `sysv_inflate/deflate` 都静默生效。

---

## 5. 上层何时必须标记“分析不完整”

建议后端在生成依赖证据时按下列规则打标，不要只凭“是否抛异常”判断：

1. 路径为 GNU 哈希且发生下列任一情况 → 标记不完整，导入函数清单不得作为完整证据：
   - `num_symbols` 抛出任何异常（含 `ValueError`）；
   - 最高桶索引对应链的终止位落在 `PT_LOAD` 文件支撑范围之外（可能走进 BSS/EOF/相邻对象）；
   - 无法证明“最高链末端 + 1”仍在 `DT_SYMTAB` 所在 `PT_LOAD` 的 `p_filesz` 内。
2. 路径为 SYSV 哈希 → 因 `nchains` 可伪造且无校验，将数量标记为“文件声明、未独立验证”；当 `nchains * sizeof(Elf_Sym)` 超出符号表到下一可验证边界的跨度时，标记不完整。
3. 路径为相邻指针/`PT_LOAD` 回退 → 一律标记“长度为推测值”；存在重复动态标签、或边界指针落在符号表内部时，标记不完整（截断风险）。
4. 兜底捕获面至少覆盖 `ELFError`、`ELFParseError`、`ValueError`、`AssertionError`，避免 §4 的两个裸异常造成任务崩溃。
5. 可信证据与推测证据分离输出：
   - **高可信**：`DT_NEEDED` 等字符串标签、带显式 `*SZ` 的重定位表——不依赖符号表长度。
   - **需带标记**：导入函数符号清单——其完整性取决于上述长度来源是否可验证。
6. 完整性自检（建议在后端实现，pyelftools 当前不提供）：
   - 校验每个 `Symbol` 的 `st_name < DT_STRSZ`；
   - 校验符号索引范围不越过 `DT_SYMTAB` 所在 `PT_LOAD` 的 `p_filesz`；
   - GNU 哈希对链走设置上界（不超过该 LOAD 文件支撑字节），SYSV 对 `nchains` 做跨度交叉校验；
   - 检测重复/矛盾的动态标签指针与缺失的 `DT_NULL`。

---

## 6. 文件与复现清单

- `elfbuild.py`：ELF64 无节头 ET_DYN 生成器与全部损坏开关（`Knobs`）
- `elfbuild32.py`：ELF32 对应实现（验证 32/64 位行为一致，越界名可跨表污染）
- `run_experiments.py`：17 场景驱动 + 三分类标注，输出 `results/experiment_results.{json,txt}`
- `demo_inflation.py`：夸大导入的最小复现，输出 `results/demo_inflation.txt`
- `samples/`：每个场景的可加载 ELF 对照样本（含 `sanity*` 完好基线与 `sanity32_*`）
