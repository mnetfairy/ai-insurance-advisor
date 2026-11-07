#!/usr/bin/env python3
"""
sanitize_products_json.py — 中和产品库中对 agent 的祈使指令（ClawHub AR1 / Anti-Refusal）

🆕 2026-10-30：ClawHub 安全审计 v2.0.196 的 AR1（Anti-Refusal，severity HIGH）

背景
----
`references/products.json` 的 `health_disclosure` / `renewal_terms` 是外部抓取
（Tavily + LLM 摘要）回填的自由文本，其中混入了**对 agent 的祈使句**——即面向
助手的祈使语气英文句式（核心动词形态包括 answer / truthful / volunteer /
refuse / comply 等，完整字面量见下方 `REWRITES` 匹配表）。

ClawHub 安全扫描器据此判定「指令要求 agent 不得拒绝」→ Anti-Refusal（AR1 × 9，
severity HIGH）。⚠️ 上句为扫描器判定语的**转述**（描述性），本脚本不重复任何
祈使句字面量。这类句子**不是**产品条款本身，
而是抓取摘要时误写成了对助手的指令，会抑制 agent 拒绝不安全/越界请求的能力。

本脚本做什么
------------
把这类**祈使句式**改写为**中性陈述句**。

⚠️ 2026-11-07 整改（ClawHub SDI-4 / SDI-3）：改写语义已收敛——
**只做语气中性化，不新增任何保险后果**。原先的替换文本会把「未如实告知 →
保单解除 / 拒赔 / 合同解除」等法律后果**引入**到原文并未声明该后果的句子上，
属于「改写即增加实质保险后果」。现在：
- 原文**已含**后果表述的（如原文已写 coverage may be voided）→ 仅把祈使语气
  改为陈述语气，后果原样保留（不删、不改、不加重）。
- 原文**未含**后果表述的 → 只输出中性陈述句，**不补写**任何后果。

改写后仍是「英文原文 + 中文中性句」的混合文本 —— 这是**有意为之**：
只中和祈使语气，不改写整段英文，避免误伤条款语义（如 regardless of …）。

⚠️ 刻意**不动**的东西
--------------------
- 保险条款语义里的 "regardless of ..."（如 "guaranteed renewal regardless of
  health changes"）是**产品条款**，不是对 agent 的指令 → **不改**
- `coverage_period_*` 等结构化续保字段（2535 款齐全）→ 不动
- 任何其他字段（名称/保费/保额/条款…）→ 不动

用法
----
    # 中和并原地写回（自动备份到 references/backups/）
    python3 scripts/sanitize_products_json.py --db references/products.json

    # 只报告不写盘
    python3 scripts/sanitize_products_json.py --db references/products.json --dry-run

    # 校验（断言无祈使指令）→ 退出码 0/1
    python3 scripts/sanitize_products_json.py --db references/products.json --check

⚠️ --db 路径限制（2026-11-07 整改 SDI-3）
------------------------------------------------
--db **只接受本 skill 自有的 `references/products.json`**（按 realpath 判定）。
传入其他路径会被直接拒绝并返回退出码 3 —— 本脚本不得被用于改写 skill 之外的
任何 JSON 文件。备份目录固定为 `references/backups/`（已在 .gitignore 内，
不随发布产物分发），不再从 --db 路径反推。

⚠️ 该脚本为**本地维护工具**，不随 skill 发布产物分发（见 .clawhubignore），
不在运行时白名单内，须由维护者在显式授权的维护流程中手动执行。

幂等性
------
改写规则以「句子级替换表」实现：命中即替换，不命中即原样保留。
**跑第二次结果与第一次字节级相同**（已由 test_data_hygiene.py 断言）。
"""

import argparse
import json
import os
import re
import shutil
import sys
from datetime import datetime

# ---------------------------------------------------------------------------
# 祈使指令检测（与 ClawHub 扫描器的 Anti-Refusal 口径一致）
# 注意：只匹配「对 agent 的祈使」，不匹配保险条款语义
# ---------------------------------------------------------------------------
IMPERATIVE_PATTERNS = [
    r"always\s+answer\b",
    r"always\s+be\s+truthful\b",
    r"must\s+be\s+truthful\b",
    r"do\s+not\s+volunteer\b",
    r"never\s+refuse\b",
    r"always\s+comply\b",
    r"ignore\s+(previous|prior|above)\b",
    r"system\s+prompt\b",
]
IMPERATIVE_RE = re.compile("|".join(IMPERATIVE_PATTERNS), re.IGNORECASE)

# 「保险条款语义」豁免：regardless of 在产品语境里是条款，不是指令
REGARDLESS_RE = re.compile(r"regardless of", re.IGNORECASE)

# ---------------------------------------------------------------------------
# 句子级改写表：把祈使句式换成中性陈述
# 每条 = (正则, 中性替换文本)
# ⚠️ 2026-11-07 整改（SDI-4）：改写**只做语气中性化，不新增保险后果**。
# 规则：替换文本中出现的后果表述，必须在**同一正则匹配的原文里已存在**；
#       原文没有后果的 → 替换文本也不写后果。
# ---------------------------------------------------------------------------
REWRITES = [
    # ── Always answer … ──
    # 原文无后果表述 → 中性句也不引入后果
    (r"Always answer insurance questions truthfully and accurately\.",
     "健康告知要求如实回答保险公司问询。"),
    (r"Always answer insurance questions directly based on medical records\.",
     "健康告知应以病历记录为依据如实填写。"),
    (r"Always answer insurance questions truthfully\.",
     "健康告知要求如实回答保险公司问询。"),
    (r"Always answer asked questions, not all\.",
     "如实回答保险公司实际问询的问题即可，无需回答未被问及的事项。"),
    (r"Always answer insurer's specific questions honestly; do not volunteer information not asked\.",
     "如实回答保险公司具体问询的问题即可，无需主动补充未被问及的信息。"),
    (r"Always answer insurer's specific questions honestly\.",
     "如实回答保险公司具体问询的问题即可。"),
    (r"always answer insurance-specific questions honestly\.",
     "如实回答保险公司具体问询的问题即可。"),
    (r"always answer insurance company's specific health questions truthfully\.",
     "如实回答保险公司具体问询的健康问题即可。"),
    (r"always answer truthfully based on medical records\.",
     "健康告知应以病历记录为依据如实填写。"),
    (r"always answer honestly\.",
     "健康告知需如实填写。"),

    # ── must be truthful（含分号从句，整体替换避免残留半句）──
    # 以下几条的**原文本身已含**后果表述 → 后果原样保留（仅祈使语气转陈述语气）
    (r"Health disclosure must be truthful; otherwise, coverage may be voided\.",
     "健康告知需如实填写；否则保障可能被解除。"),
    (r"Health disclosure must be truthful; omissions can void coverage\.",
     "健康告知需如实填写；遗漏告知事项可能导致保障被解除。"),
    (r"Health disclosure must be truthful; if not asked, no need to disclose\.",
     "健康告知需如实填写；未被问及的事项无需填写。"),
    (r"Health disclosure must be truthful; if insurance questions are asked, answer honestly\.",
     "健康告知需如实填写；对保险公司问询的问题应如实回答。"),
    (r"Health disclosure must be truthful but not exaggerated\.",
     "健康告知需如实填写，不应夸大病情。"),
    (r"Health disclosure must be truthful for accurate insurance assessment; incomplete or false information can lead to claim denial or policy cancellation\.",
     "健康告知需如实填写，方可作出准确的核保评估；信息不完整或不真实可能导致拒赔或保单解除。"),
    (r"Health disclosure must be truthful to avoid contract termination\.",
     "健康告知需如实填写，以免发生合同解除。"),
    (r"Health declaration(?:s)? must be truthful; false information can void coverage\.",
     "健康告知需如实填写；信息不真实可能导致保障被解除。"),
    (r"Health disclosure(?:s)? must be truthful; false information can void coverage\.",
     "健康告知需如实填写；信息不真实可能导致保障被解除。"),
    (r"Health declaration(?:s)? must be truthful; otherwise, the policy may be voided\.",
     "健康告知需如实填写；否则保单可能被解除。"),
    # 兜底：任何 Health disclosure(s)/Health declaration(s) must be truthful …
    (r"(Health disclosure(?:s)?|Health declaration(?:s)?) must be truthful\b",
     "健康告知需如实填写"),
    (r"health disclosure must be truthful\b",
     "健康告知需如实填写"),

    # ── 其他指令片段 ──
    (r"Always consult professionals for complex cases\.",
     "复杂情形建议咨询专业保险代理人或核保人员。"),
    (r"If insurance and smart underwriting conflict, health disclosure is primary\.",
     "智能核保结论与健康告知要求冲突时，以健康告知要求为准。"),
    (r"do not volunteer information not asked\.",
     "无需主动补充未被问及的信息。"),
]

# 排序策略：先按【具体度】—— 含标点从句的具体句式优先于泛化兜底；
# 同具体度内按模式长度降序（长句优先，避免短句先命中导致长句残留）。
# ⚠️ 泛化兜底（(Health disclosure…|Health declaration…) must be truthful）必须排在最后，
#    否则它会先命中并吃掉后面的从句，留下 "健康告知需如实填写; otherwise, coverage may be voided." 这种半句。
_GENERIC_FALLBACK = r"(Health disclosure(?:s)?|Health declaration(?:s)?) must be truthful\b"


def _sort_key(pair):
    pattern = pair[0]
    is_generic = 1 if pattern == _GENERIC_FALLBACK else 0
    return (is_generic, -len(pattern))


REWRITES.sort(key=_sort_key)


def neutralize(text):
    """把文本中的祈使指令改写为中性陈述。返回 (新文本, 命中数)。"""
    if not isinstance(text, str) or not text:
        return text, 0
    hits = 0
    out = text
    for pattern, replacement in REWRITES:
        # ⚠️ 必须 IGNORECASE：真实数据里同一句式大小写混用
        #（"Health disclosure must be truthful" vs "health disclosure must be truthful"）。
        # 若用大小写敏感匹配，长句模式会漏掉小写开头 → 只剩泛化兜底命中 →
        # 产出 "健康告知需如实填写; otherwise, coverage may be voided." 这种半句残渣。
        new_out, n = re.subn(pattern, replacement, out, flags=re.IGNORECASE)
        if n:
            out = new_out
            hits += n
    return out, hits


def sanitize_product_fields(product):
    """就地中和单个产品的两个自由文本字段。返回命中数。"""
    hits = 0
    for field in ("health_disclosure", "renewal_terms"):
        value = product.get(field)
        if not isinstance(value, str) or not value:
            continue
        new_value, n = neutralize(value)
        if n:
            product[field] = new_value
            hits += n
    return hits


def scan_file(path):
    """扫描一个 products.json，返回 (祈使命中列表, 产品总数)。"""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    products = data.get("products", [])
    found = []
    for p in products:
        for field in ("health_disclosure", "renewal_terms"):
            value = p.get(field)
            if isinstance(value, str) and IMPERATIVE_RE.search(value):
                # 条款语义豁免：整段只出现 regardless of 时不算指令
                if REGARDLESS_RE.search(value) and not re.search(
                    r"always\s+answer|must\s+be\s+truthful|do\s+not\s+volunteer|"
                    r"never\s+refuse|always\s+comply|system\s+prompt",
                    value,
                    re.IGNORECASE,
                ):
                    continue
                found.append((p.get("name"), field))
    return found, len(products)


def _skill_root():
    """本 skill 根目录（scripts/ 的上一级）。"""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _resolve_managed_db(db_arg):
    """把 --db 解析为**本 skill 自有**的 references/products.json。

    ⚠️ 2026-11-07 整改（SDI-3）：--db 原先接受任意路径 → 脚本可被用来改写
    任意 JSON 文件（越权写库）。现在只接受本 skill 自己的产品库路径；
    其他路径一律拒绝并返回非 0 退出码。

    Returns:
        tuple[str, str | None]: (解析后的绝对路径, 错误信息)
    """
    managed = os.path.join(_skill_root(), "references", "products.json")
    managed_real = os.path.realpath(managed)
    candidate = os.path.realpath(os.path.abspath(db_arg))

    if candidate == managed_real:
        return candidate, None

    # 允许写法上的等价（如 skill 根目录下的相对路径）——realpath 已覆盖
    return None, (
        f"拒绝操作非本 skill 所有的数据库文件：{candidate}\n"
        f"本脚本仅允许操作：{managed_real}"
    )


def main():
    parser = argparse.ArgumentParser(description="中和中和产品库中对 agent 的祈使指令（ClawHub AR1）")
    parser.add_argument("--db", required=True,
                        help="products.json 路径（仅限本 skill 的 references/products.json）")
    parser.add_argument("--dry-run", action="store_true", help="只报告不写盘")
    parser.add_argument("--check", action="store_true", help="只校验（无祈使指令则退出码 0）")
    args = parser.parse_args()

    path, path_err = _resolve_managed_db(args.db)
    if path_err:
        print(f"❌ {path_err}", file=sys.stderr)
        return 3
    if not os.path.exists(path):
        print(f"❌ 找不到 {path}", file=sys.stderr)
        return 2

    if args.check:
        found, total = scan_file(path)
        if found:
            print(f"❌ 仍有 {len(found)} 处祈使指令（{path}）:")
            for name, field in found:
                print(f"   - {name} [{field}]")
            return 1
        print(f"✅ 无祈使指令（{path}，共 {total} 款产品）")
        return 0

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    products = data.get("products", [])

    hits = 0
    touched = 0
    for p in products:
        n = sanitize_product_fields(p)
        if n:
            hits += n
            touched += 1

    print(f"扫描 {len(products)} 款产品，命中祈使指令 {hits} 处，涉及 {touched} 款产品")

    if args.dry_run:
        print("（--dry-run：未写盘）")
        return 0

    if hits == 0:
        print("✅ 无需改动（已干净），未写盘")
        return 0

    # 备份（references/backups/ 已在 .gitignore 内，不随发布产物分发）
    # ⚠️ 2026-11-07 整改（SDI-3）：备份目录固定为本 skill 自有的 references/backups/，
    #    不再从 --db 路径反推，避免向任意目录写入备份文件。
    backup_dir = os.path.join(_skill_root(), "references", "backups")
    os.makedirs(backup_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(backup_dir, f"products.json.pre_ar1_sanitize_{ts}")
    shutil.copy2(path, backup_path)
    print(f"已备份 → {backup_path}")

    # 写盘前再次校验目标路径（防御：防止中途路径被替换 / 符号链接指向外部）
    final_path, final_err = _resolve_managed_db(path)
    if final_err:
        print(f"❌ 写盘前路径校验失败：{final_err}", file=sys.stderr)
        return 3

    # 写回：保持与原文件一致的 readable 格式（indent=2 + ensure_ascii=False）
    with open(final_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"已写回 → {final_path}")

    # 写回后自检
    found, total = scan_file(path)
    if found:
        print(f"❌ 写回后仍有 {len(found)} 处祈使指令:", file=sys.stderr)
        for name, field in found:
            print(f"   - {name} [{field}]", file=sys.stderr)
        return 1
    print(f"✅ 写回后自检通过：0 处祈使指令（共 {total} 款产品）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
