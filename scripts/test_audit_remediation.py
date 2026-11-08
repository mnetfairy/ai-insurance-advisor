#!/usr/bin/env python3
"""
test_audit_remediation.py — ClawHub 安全审计整改回归测试（2026-11-07）

被审报告：ClawHub 安全审计 · scanner 2.12.0 · 33 findings / score 100 / CRITICAL
被审版本：v2.3.4 → 整改后 v2.3.5

覆盖 3 个根因的回归守卫（本文件只测**本次整改引入的行为**，不重复既有测试）：

1. **R3 · LP3（未声明工具范围）**
   - SKILL.md 正文不得再出现独立 `---` 分隔线（只保留 frontmatter 的首尾两行），
     否则 ClawHub 注册表侧的 `normalized.indexOf("\n---", 3)` 会命中正文分隔线，
     切出含正文的 YAML → 解析失败 → `permissions` 不被识别 → 判 LP3。
   - 用 ClawHub 同款解析逻辑实测能解析出 `permissions` 与 `allowed-tools`。

2. **R4 · SDI-4（医疗险续保条款造假）**
   - 医疗险 `coverage_period` / `key_benefits` 展示字段**必须**与选中产品的
     真实续保字段一致，不得无条件宣称「保证续保20年」。
   - 覆盖 3 类用例：①有 20 年保证续保产品 ②只有较短保证续保（兜底）
     ③完全无保证续保 —— 后两类必须**如实报告限制**，不得谎称 20 年。

3. **R5 · SDI-4（重复产品未排除）**
   - `load_products()` 返回的报价池中不得出现 `is_duplicate is True` 的产品。
   - `stats.eligible_products` 必须等于 `len(load_products())`（两处口径不再漂移）。

4. **R4 · 保额超产品可售上限（官方 ClawScan 唯一 concern 点名的第一条）**
   - 三套方案各险种的 `coverage` 不得超过该产品在产品库的 `max_coverage`
     （可售保额上限，单位万元→元）。
   - 触顶时必须在 `budget_adjustments` 记 `coverage_capped`（留痕可审计）。
   - `_coverage_cap()` 语义：无 `max_coverage` → 不设上限（不得假装有上限）。

用法：
    python3 scripts/test_audit_remediation.py
退出码 0 = 全部通过。
"""

import importlib.util
import json
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(SCRIPT_DIR)
SKILL_MD = os.path.join(SKILL_DIR, "SKILL.md")
PRODUCTS_JSON = os.path.join(SKILL_DIR, "references", "products.json")

_results = []


def check(name, condition, detail=""):
    _results.append((name, bool(condition), detail))
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))
    return bool(condition)


def _load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(SCRIPT_DIR, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _clawhub_frontmatter_parse(text):
    """复刻 ClawHub 注册表侧 `extractSkillFrontmatterDescription()` 的解析逻辑。

    源码（clawhub/src/lib/skillFrontmatter.ts）：
        const normalized = content.replace(/\\r\\n/g, '\\n');
        const endIndex = normalized.indexOf('\\n---', 3);
    切片出的 YAML 再交给 yaml.safe_load。
    """
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    end = normalized.find("\n---", 3)
    if end == -1:
        return None, -1
    yaml_slice = normalized[normalized.find("---") + 4:end + 1]
    try:
        import yaml
        return yaml.safe_load(yaml_slice), normalized[:end].count("\n") + 1
    except Exception:
        return None, normalized[:end].count("\n") + 1


# ---------------------------------------------------------------------------
# R3 — LP3 根因回归
# ---------------------------------------------------------------------------
def test_r3_frontmatter_delimiters():
    print("\n[R3] LP3 — frontmatter 分隔符与工具范围声明")
    raw = open(SKILL_MD, encoding="utf-8").read()
    lines = raw.replace("\r\n", "\n").split("\n")

    sep_lines = [i + 1 for i, l in enumerate(lines) if l.strip() == "---"]
    check("R3.1 SKILL.md 恰好只有 2 个独立 '---' 行",
          len(sep_lines) == 2, f"实际行号 {sep_lines}")
    check("R3.2 第 1 行是 '---'（frontmatter 起始）",
          len(sep_lines) >= 1 and sep_lines[0] == 1)
    check("R3.3 第 2 个 '---' 位于 frontmatter 结束位置（第 38 行）",
          len(sep_lines) >= 2 and sep_lines[1] == 38, f"实际 {sep_lines[1] if len(sep_lines)>1 else 'N/A'}")

    normalized = raw.replace("\r\n", "\n").replace("\r", "\n")
    end = normalized.find("\n---", 3)
    # indexOf 返回的是 '\n' 的偏移量 → 该换行符位于第 37 行，其后的 '---' 即第 38 行
    hit_line = normalized[:end].count("\n") + 2
    check("R3.4 indexOf('\\n---', 3) 命中 frontmatter 结束符（不是正文分隔线）",
          hit_line == 38 and normalized[end:].startswith("\n---"),
          f"命中 '---' 所在行第 {hit_line} 行，上一行内容 {normalized[end - 3:end + 5]!r}")

    data, _ = _clawhub_frontmatter_parse(raw)
    check("R3.5 ClawHub 同款解析逻辑能成功解析 frontmatter",
          isinstance(data, dict), f"解析结果类型 {type(data).__name__}")
    check("R3.6 解析结果含 permissions", isinstance(data, dict) and "permissions" in data)
    check("R3.7 解析结果含 allowed-tools",
          isinstance(data, dict) and "allowed-tools" in data)
    if isinstance(data, dict):
        check("R3.8 allowed-tools == ['read', 'exec']",
              data.get("allowed-tools") == ["read", "exec"], repr(data.get("allowed-tools")))
        perms = data.get("permissions") or {}
        allow = (((perms.get("exec") or {}).get("allow")) or [])
        check("R3.9 permissions.exec.allow 仅含 3 个运行时脚本",
              len(allow) == 3 and all("test_" not in a and "sanitize" not in a for a in allow),
              repr(allow))
        write = ((perms.get("filesystem") or {}).get("write"))
        check("R3.10 permissions.filesystem.write 为空（运行时零写入）",
              write == [], repr(write))


# ---------------------------------------------------------------------------
# R4 — SDI-4 医疗险续保条款回归
# ---------------------------------------------------------------------------
def test_r4_medical_renewal(pd):
    print("\n[R4] SDI-4 — 医疗险续保条款与展示字段一致性")
    products = pd.load_products()
    medical = [p for p in products if p.get("type") == "医疗险"]

    # --- 4.1 真实数据：选中产品的展示字段必须与真实字段一致 ---
    check("R4.1 产品池中存在医疗险", len(medical) > 0, f"{len(medical)} 款")

    mismatches = []
    for p in medical:
        derived = pd.derive_medical_coverage_period(p)
        guaranteed = p.get("coverage_period_guaranteed_renewable") is True
        if guaranteed:
            years = pd._renewal_duration_years(p)
            if years is not None and f"{years}年" not in derived:
                mismatches.append((p["name"], derived, years))
        else:
            # 非保证续保的产品不得出现「保证续保N年」措辞
            if "保证续保" in derived and "长期保证续保" not in derived:
                mismatches.append((p["name"], derived, "非保证续保却宣称保证续保"))
    check("R4.2 全部医疗险的派生 coverage_period 与真实字段一致",
          not mismatches, f"不一致 {len(mismatches)} 款：{mismatches[:3]}")

    # --- 4.3 选品：无「保证续保20年」产品时不得谎称 ---
    fake_short = [
        {"id": "t1", "name": "测试A", "type": "医疗险",
         "coverage_period": "1年（可续保）",
         "coverage_period_guaranteed_renewable": False,
         "coverage_period_duration_value": 1,
         "coverage_period_duration_unit": "year"},
        {"id": "t2", "name": "测试B", "type": "医疗险",
         "coverage_period": "6年保证续保",
         "coverage_period_guaranteed_renewable": True,
         "coverage_period_duration_value": 6,
         "coverage_period_duration_unit": "year",
         "coverage_period_parse_notes": ["guaranteed_renewable_6年"]},
    ]
    sel, limitation = pd.select_medical_product(fake_short, min_guaranteed_years=20)
    check("R4.3 无 20 年保证续保产品时返回限制说明",
          limitation is not None and "reason" in limitation,
          json.dumps(limitation, ensure_ascii=False) if limitation else "None")
    check("R4.4 限制说明中不得声称满足 20 年要求",
          limitation is not None and "20年" in limitation.get("requirement", ""),
          limitation.get("requirement") if limitation else "None")
    check("R4.5 兜底选品的派生字段如实反映真实年限（6 年 → 6年保证续保）",
          sel is not None and pd.derive_medical_coverage_period(sel) == "6年保证续保",
          pd.derive_medical_coverage_period(sel) if sel else "None")
    check("R4.6 兜底选品不得宣称「保证续保20年」",
          sel is not None and "20年" not in pd.derive_medical_coverage_period(sel),
          pd.derive_medical_coverage_period(sel) if sel else "None")

    # --- 4.7 完全没有保证续保产品 ---
    fake_none = [fake_short[0]]
    sel2, limitation2 = pd.select_medical_product(fake_none, min_guaranteed_years=20)
    check("R4.7 无任何保证续保产品时如实报告限制",
          limitation2 is not None and "无任何标明保证续保" in limitation2["reason"],
          limitation2["reason"] if limitation2 else "None")
    check("R4.8 无保证续保产品的派生字段不含「保证续保」措辞",
          sel2 is not None and "保证续保" not in pd.derive_medical_coverage_period(sel2),
          pd.derive_medical_coverage_period(sel2) if sel2 else "None")
    check("R4.9 无保证续保产品的 key_benefits 声明「续保条件以产品条款为准」",
          sel2 is not None and "续保条件以产品条款为准" in pd.derive_medical_key_benefits(sel2, "X"),
          pd.derive_medical_key_benefits(sel2, "X") if sel2 else "None")

    # --- 4.10 有 20 年保证续保产品时必须选中它 ---
    fake_20 = fake_short + [
        {"id": "t3", "name": "测试C", "type": "医疗险",
         "coverage_period": "20年保证续保",
         "coverage_period_guaranteed_renewable": True,
         "coverage_period_duration_value": 20,
         "coverage_period_duration_unit": "year",
         "coverage_period_parse_notes": ["guaranteed_renewable_20年"]},
    ]
    sel3, limitation3 = pd.select_medical_product(fake_20, min_guaranteed_years=20)
    check("R4.10 有 20 年保证续保产品时选中它且无限制说明",
          sel3 is not None and sel3["name"] == "测试C" and limitation3 is None,
          f"{sel3['name'] if sel3 else None} / limitation={limitation3}")

    # --- 4.11 真实数据：标准版方案的医疗险展示字段与产品真实字段一致 ---
    plan = pd.design_standard_plan(35, "男", 500000, 50000,
                                   {"death": 2000000, "critical_illness": 1500000,
                                    "hospital": 4000000}, products)
    mi_entries = [e for e in plan["products"] if e["type"] == "医疗险"]
    check("R4.11 标准版方案含医疗险", len(mi_entries) == 1, f"{len(mi_entries)} 个")
    if mi_entries:
        entry = mi_entries[0]
        real = next((p for p in products if p.get("name") == entry["product_name"]), None)
        check("R4.12 方案中医疗险 coverage_period 等于产品真实字段派生值",
              real is not None and entry["coverage_period"] == pd.derive_medical_coverage_period(real),
              f"{entry['coverage_period']} vs "
              f"{pd.derive_medical_coverage_period(real) if real else 'N/A'}")
        check("R4.13 方案中医疗险 coverage_period 不含硬编码「保证续保20年」以外的编造",
              "保证续保20年" in entry["coverage_period"]
              or real is not None and real.get("coverage_period_guaranteed_renewable") is True,
              entry["coverage_period"])
        check("R4.14 方案 features 中的医疗险描述与选中产品一致",
              any(entry["coverage_period"] in f for f in plan.get("features", [])),
              str([f for f in plan.get("features", []) if "医疗" in f]))

    # --- 4.15 源码级断言：不再存在无条件写死「保证续保20年」的展示字段 ---
    src = open(os.path.join(SCRIPT_DIR, "plan_designer.py"), encoding="utf-8").read()
    # 只检查**实际代码行**（排除以 # 开头的注释行 —— 注释里描述的是旧 bug）
    code_lines = [l for l in src.split("\n") if not l.strip().startswith("#")]
    code_src = "\n".join(code_lines)
    hardcoded = re.findall(r'"coverage_period"\s*:\s*"保证续保20年"', code_src)
    check("R4.15 代码行中不再有写死的 \"coverage_period\": \"保证续保20年\"",
          not hardcoded, f"命中 {len(hardcoded)} 处")
    hardcoded_kb = re.findall(r'"key_benefits"\s*:\s*"长期医疗保障，20年续保稳定"', code_src)
    check("R4.16 代码行中不再有写死的 key_benefits「长期医疗保障，20年续保稳定」",
          not hardcoded_kb, f"命中 {len(hardcoded_kb)} 处")


# ---------------------------------------------------------------------------
# R5 — SDI-4 重复产品排除回归
# ---------------------------------------------------------------------------
def test_r5_duplicate_filter(pc):
    print("\n[R5] SDI-4 — 重复产品排除与口径统一")
    pool = pc.load_products()
    stats = pc.load_product_stats()

    dups = [p for p in pool if p.get("is_duplicate") is True]
    check("R5.1 报价池中无 is_duplicate=True 的产品",
          not dups, f"发现 {len(dups)} 个：{[p.get('name') for p in dups[:3]]}")

    check("R5.2 eligible_products == len(load_products())",
          stats["eligible_products"] == len(pool),
          f"{stats['eligible_products']} vs {len(pool)}")

    check("R5.3 load_products() 与 load_product_stats() 共用同一资格谓词",
          hasattr(pc, "is_eligible_for_pool"), "is_eligible_for_pool 存在")
    if hasattr(pc, "is_eligible_for_pool"):
        mismatched = [
            p.get("name") for p in pool
            if not pc.is_eligible_for_pool(p, filter_garbage=True, include_discontinued=False)
        ]
        check("R5.4 报价池内每个产品都通过资格谓词", not mismatched, str(mismatched[:3]))

    # 包含停售产品时的口径同样一致
    pool_inc = pc.load_products(include_discontinued=True)
    stats_inc = pc.load_product_stats(include_discontinued=True)
    check("R5.5 include_discontinued=True 时两处口径仍一致",
          stats_inc["eligible_products"] == len(pool_inc),
          f"{stats_inc['eligible_products']} vs {len(pool_inc)}")
    check("R5.6 include_discontinued=True 时仍排除重复品",
          not [p for p in pool_inc if p.get("is_duplicate") is True],
          f"{len([p for p in pool_inc if p.get('is_duplicate') is True])} 个")

    # 源码级断言：load_products 使用了共用谓词
    src = open(os.path.join(SCRIPT_DIR, "premium_calculator.py"), encoding="utf-8").read()
    check("R5.7 load_products() 调用 is_eligible_for_pool()",
          "is_eligible_for_pool" in src.split("def load_product_stats")[0])


# ---------------------------------------------------------------------------
# R6 — SDI-3/SDI-4 清洗脚本收敛回归
# ---------------------------------------------------------------------------
def test_r6_sanitizer(san):
    print("\n[R6] SDI-3/SDI-4 — 清洗脚本收敛")
    # 改写只做语气中性化，不新增保险后果
    consequence_re = re.compile(
        r"解除|拒赔|拒绝|终止|失效|作废|void|denial|cancell|termination|terminate", re.IGNORECASE)
    cases = [
        ("Always answer insurance questions truthfully and accurately.", False),
        ("Always answer insurance questions directly based on medical records.", False),
        ("Always answer insurance questions truthfully.", False),
        ("Always answer asked questions, not all.", False),
        ("Always answer insurer's specific questions honestly; do not volunteer information not asked.", False),
        ("Always answer insurer's specific questions honestly.", False),
        ("always answer insurance-specific questions honestly.", False),
        ("always answer insurance company's specific health questions truthfully.", False),
        ("always answer truthfully based on medical records.", False),
        ("always answer honestly.", False),
        ("Health disclosure must be truthful; otherwise, coverage may be voided.", True),
        ("Health disclosure must be truthful; omissions can void coverage.", True),
        ("Health disclosure must be truthful; if not asked, no need to disclose.", False),
        ("Health disclosure must be truthful; if insurance questions are asked, answer honestly.", False),
        ("Health disclosure must be truthful but not exaggerated.", False),
        ("Health disclosure must be truthful for accurate insurance assessment; incomplete or false information can lead to claim denial or policy cancellation.", True),
        ("Health disclosure must be truthful to avoid contract termination.", True),
        ("Health declarations must be truthful; false information can void coverage.", True),
        ("Health disclosures must be truthful; false information can void coverage.", True),
        ("Health declarations must be truthful; otherwise, the policy may be voided.", True),
        ("Health declaration must be truthful; false information can void coverage.", True),
        ("Health disclosure must be truthful; false information can void coverage.", True),
        ("Always consult professionals for complex cases.", False),
        ("If insurance and smart underwriting conflict, health disclosure is primary.", False),
        ("do not volunteer information not asked.", False),
    ]
    violations = []
    for text, src_has in cases:
        out, _hits = san.neutralize(text)
        if bool(consequence_re.search(out)) != src_has:
            violations.append((text[:50], src_has, bool(consequence_re.search(out))))
    check("R6.1 改写表不新增保险后果（后果守恒）",
          not violations, f"违反 {len(violations)} 条：{violations[:2]}")

    # --db 路径限制
    path, err = san._resolve_managed_db("/tmp/evil.json")
    check("R6.2 --db 拒绝任意路径", path is None and err is not None, (err or "").split("\n")[0])
    ok_path, ok_err = san._resolve_managed_db(PRODUCTS_JSON)
    check("R6.3 --db 接受本 skill 自有 products.json",
          ok_path is not None and ok_err is None, ok_path or str(ok_err))
    other = os.path.join(os.path.dirname(SKILL_DIR), "insurance-advisor-china",
                         "references", "products.json")
    p2, e2 = san._resolve_managed_db(other)
    check("R6.4 --db 拒绝其他 skill 的 products.json", p2 is None and e2 is not None,
          (e2 or "").split("\n")[0])


# ---------------------------------------------------------------------------
# R1/R2 — 发布面收敛回归
# ---------------------------------------------------------------------------
def test_r1_r2_publish_surface():
    print("\n[R1/R2] 发布面收敛与 Anti-Refusal")
    ignore_path = os.path.join(SKILL_DIR, ".clawhubignore")
    check("R1.1 存在 .clawhubignore", os.path.exists(ignore_path))
    if os.path.exists(ignore_path):
        ig = open(ignore_path, encoding="utf-8").read()
        # 只取**生效规则行**（非注释、非空行）——注释里提到运行时脚本不算排除
        ig_rules = {ln.strip() for ln in ig.split("\n")
                    if ln.strip() and not ln.strip().startswith("#")}
        for name in ("scripts/sanitize_products_json.py",
                     "scripts/test_budget_compliance.py",
                     "scripts/test_data_hygiene.py",
                     "scripts/test_discontinued_filter.py",
                     "scripts/test_insurance_recommendations.py",
                     "scripts/test_audit_remediation.py"):
            check(f"R1.2 .clawhubignore 排除 {name}", name in ig_rules)
        # 运行时脚本不得被排除
        for name in ("scripts/needs_analyzer.py",
                     "scripts/premium_calculator.py",
                     "scripts/plan_designer.py"):
            check(f"R1.3 .clawhubignore 未排除运行时脚本 {name}",
                  name not in ig_rules, f"生效规则命中: {name in ig_rules}")

    # 本地维护脚本文件仍在磁盘上（只是不进发布产物）
    for name in ("sanitize_products_json.py", "test_data_hygiene.py",
                 "test_insurance_recommendations.py"):
        check(f"R1.4 本地维护脚本 {name} 仍存在于磁盘",
              os.path.exists(os.path.join(SCRIPT_DIR, name)))

    # R2：SKILL.md 与维护脚本不再逐字复现英文祈使句
    patterns = [r"Always answer", r"must be truthful", r"do not volunteer",
                r"never refuse", r"always comply"]
    skill_src = open(SKILL_MD, encoding="utf-8").read()
    hits = [p for p in patterns if re.search(p, skill_src, re.IGNORECASE)]
    check("R2.1 SKILL.md 不再逐字复现英文祈使句", not hits, f"命中 {hits}")

    doc_hits = []
    for name in ("sanitize_products_json.py", "test_data_hygiene.py"):
        src = open(os.path.join(SCRIPT_DIR, name), encoding="utf-8").read()
        # 排除 REWRITES 正则表本身（那是匹配模式，不是复现祈使句）
        head = src.split("REWRITES = [")[0]
        for p in patterns:
            if re.search(p, head, re.IGNORECASE):
                doc_hits.append((name, p))
    check("R2.2 维护脚本 docstring 不再逐字复现英文祈使句", not doc_hits, str(doc_hits))


# ---------------------------------------------------------------------------
# A — 400 电话红线守卫
# ---------------------------------------------------------------------------
def test_a_400_redline():
    print("\n[A] 400-860-0058 红线守卫")
    skill_src = open(SKILL_MD, encoding="utf-8").read()
    for token in ("400-860-0058", "安盛天平", "🔒", "待确认后展示"):
        check(f"A.1 SKILL.md 含 {token!r}", token in skill_src)

    data = json.load(open(PRODUCTS_JSON, encoding="utf-8"))
    meta = data.get("_meta") or {}
    basis = meta.get("insurance_priority_basis")
    check("A.2 products.json._meta.insurance_priority_basis 存在且非空",
          bool(basis), f"{type(basis).__name__}")
    if basis:
        check("A.3 priority_basis 含安盛天平", "安盛天平" in json.dumps(basis, ensure_ascii=False))
        check("A.4 priority_basis 含 400-860-0058", "400-860-0058" in json.dumps(basis, ensure_ascii=False))


# ---------------------------------------------------------------------------
# R7 — 保额虚报回归（官方 ClawScan 唯一 concern）
#
# 根因：_enforce_budget() 的 coverage_downscale 分支改了 entry["coverage"]
#       与 annual_premium，却漏减 plan["total_coverage"] → 总保额虚报。
# 修法：downscale 同步扣减 + _finalize_plan() 出口按 products 重算兜底
#       + description 按实际剩余险种动态生成。
# ---------------------------------------------------------------------------

# 极小预算档：会触发 downscale / product_removed 的场景
_TINY_BUDGET_CASES = [
    (20000, 500),
    (30000, 800),
    (40000, 1000),
    (30000, 2000),
]

# 险种 → description / key_benefits 里不得出现的卖点词
_REMOVED_CLAIM_TOKENS = {
    "重疾险": ["重疾保障", "重疾"],
    "医疗险": ["医疗保障", "医疗险"],
    "储蓄险": ["养老储蓄", "养老规划", "储蓄"],
    "意外险": ["意外保障", "意外险"],
    "定期寿险": ["定期寿险", "寿险保障"],
}


def _plan_products(plan):
    return plan.get("products") or []


def _sum_coverage(plan):
    return sum((p.get("coverage") or 0) for p in _plan_products(plan))


def test_r7_coverage_accounting(pd):
    """R7: total_coverage 必须等于实际产品保额之和；描述不得含已移除险种。"""
    print("\nR7: total_coverage 与实际保额一致 / 描述随实际构成变化")

    # --- R7.1 账目一致（极小预算 + 常规预算） ---
    cases = list(_TINY_BUDGET_CASES) + [
        (500000, 50000),
        (1000000, 200000),
    ]
    mismatches = []
    for income, budget in cases:
        plans = pd.generate_all_plans(
            30, "男", income, budget,
            {"death": 500000, "critical_illness": 1000000, "hospital": 2000000},
        )
        for name, plan in plans.items():
            total = plan.get("total_coverage")
            actual = _sum_coverage(plan)
            if total != actual:
                mismatches.append(
                    f"收入{income}/预算{budget} {name}: total_coverage={total} != 实际={actual}")
    check("R7.1 total_coverage == sum(products[].coverage)（全部预算档）",
          not mismatches,
          "; ".join(mismatches[:3]) if mismatches else f"覆盖 {len(cases)} 个预算档 × 3 套方案")

    # --- R7.2 极小预算下，已被移除的险种不得出现在描述/卖点里 ---
    leaked = []
    for income, budget in _TINY_BUDGET_CASES:
        plans = pd.generate_all_plans(
            30, "男", income, budget,
            {"death": 500000, "critical_illness": 1000000, "hospital": 2000000},
        )
        for name, plan in plans.items():
            present = {p.get("type") for p in _plan_products(plan)}
            blob = f"{plan.get('description') or ''} " + " ".join(
                str(p.get("key_benefits") or "") for p in _plan_products(plan))
            for ptype, tokens in _REMOVED_CLAIM_TOKENS.items():
                if ptype in present:
                    continue
                for token in tokens:
                    if token in blob:
                        leaked.append(
                            f"收入{income}/预算{budget} {name}: 已移除 {ptype} 但仍出现「{token}」")
    check("R7.2 已移除险种不再出现在 description / key_benefits",
          not leaked,
          "; ".join(leaked[:3]) if leaked else f"覆盖 {len(_TINY_BUDGET_CASES)} 个极小预算档")

    # --- R7.3 预算充足时描述仍保留原有卖点（防止过度修正成空洞文案）---
    plans = pd.generate_all_plans(
        30, "男", 500000, 50000,
        {"death": 2000000, "critical_illness": 1500000, "hospital": 4000000},
    )
    standard = plans.get("标准版") or {}
    std_types = {p.get("type") for p in _plan_products(standard)}
    check("R7.3 预算充足时标准版仍含重疾保障且描述保留「重疾保障」",
          "重疾险" in std_types and "重疾保障" in (standard.get("description") or ""),
          f"险种={sorted(std_types)} desc={standard.get('description')!r}")

    premium = plans.get("全面版") or {}
    prem_types = {p.get("type") for p in _plan_products(premium)}
    check("R7.3 预算充足时全面版仍含储蓄险且描述保留「养老储蓄规划」",
          "储蓄险" in prem_types and "养老储蓄规划" in (premium.get("description") or ""),
          f"险种={sorted(prem_types)} desc={premium.get('description')!r}")

    # --- R7.4 出口兜底存在（源码级断言）---
    src = open(os.path.join(SKILL_DIR, "scripts", "plan_designer.py"),
               "r", encoding="utf-8").read()
    check("R7.4 _finalize_plan 出口按 products 重算 total_coverage",
          re.search(r'total_coverage"\]\s*=\s*sum\(', src) is not None,
          "未找到 sum(...) 兜底赋值")
    check("R7.4 downscale 分支同步扣减 total_coverage",
          re.search(r'total_coverage"\]\s*=\s*plan\.get\(\s*"total_coverage"\s*,\s*0\s*\)\s*-\s*\(\s*old_coverage\s*-\s*best\s*\)', src) is not None,
          "未找到 old_coverage - best 的同步扣减赋值")


# ---------------------------------------------------------------------------
# R4 — 保额上限回归（官方 ClawScan point-of-concern #1）
#
# 根因：plan_designer.py 三套方案（基础版/标准版/全面版）的各险种保额
#       （意外险 / 重疾险 / 定期寿险 / 医疗险 / 储蓄险）均为**写死值或收入倍数**，
#       未经产品库 max_coverage（可售保额上限）夹逼 →
#       如「安心少儿意外险」max_coverage=50 万，方案却给 2,500,000 元（超 50 倍），
#       对外虚报可售保额。
# 修法：_coverage_cap() 取产品 max_coverage（万元→元）作为上限，
#       _apply_coverage_cap() 把期望保额夹到上限并在 budget_adjustments
#       记 coverage_capped（留痕）。
# ---------------------------------------------------------------------------

# 覆盖收入/预算档位（含常规档与极小预算档，触发 downscale 后仍不得超上限）
_COVERAGE_CAP_CASES = [
    (500000, 50000),
    (300000, 30000),
    (1000000, 200000),
    (80000, 10000),
]


def _product_cap(product):
    """按产品库规则换算可售保额上限（元）；无 max_coverage → None（不设上限）。"""
    if not product:
        return None
    raw = product.get("max_coverage")
    if raw is None:
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    unit = product.get("coverage_unit") or "万元"
    if unit == "万元":
        value = value * 10000
    return int(value)


def test_r4_coverage_cap(pd):
    """R4: 方案保额不得超过产品库 max_coverage（可售保额上限）。"""
    print("\nR4: 各险种保额 ≤ 产品 max_coverage（可售保额上限）")

    products = pd.load_products()
    index = {(p.get("type"), p.get("name")): p for p in products}

    # --- R4.1 三套方案每个险种的 coverage 不得超过该产品 max_coverage ---
    violations = []
    checked = 0
    for income, budget in _COVERAGE_CAP_CASES:
        plans = pd.generate_all_plans(
            35, "男", income, budget,
            {"death": 2000000, "critical_illness": 1500000, "hospital": 4000000},
        )
        for name, plan in plans.items():
            for entry in (plan.get("products") or []):
                product = index.get((entry.get("type"), entry.get("product_name")))
                cap = _product_cap(product)
                if cap is None:
                    continue
                checked += 1
                coverage = entry.get("coverage") or 0
                if coverage > cap:
                    violations.append(
                        f"收入{income}/预算{budget} {name} {entry.get('type')}"
                        f"「{entry.get('product_name')}」coverage={coverage} > 上限={cap}"
                        f"（max_coverage={product.get('max_coverage')} "
                        f"{product.get('coverage_unit')}）")
    check("R4.1 三套方案各险种 coverage ≤ 产品 max_coverage",
          not violations,
          "; ".join(violations[:3]) if violations else
          f"覆盖 {len(_COVERAGE_CAP_CASES)} 个收入/预算档 × 3 套方案，受检 {checked} 条保额记录")

    # --- R4.2 触顶时必须在 budget_adjustments 留痕（coverage_capped） ---
    plans = pd.generate_all_plans(
        35, "男", 500000, 50000,
        {"death": 2000000, "critical_illness": 1500000, "hospital": 4000000},
    )
    capped_records = []
    unrecorded = []
    for name, plan in plans.items():
        for adj in (plan.get("budget_adjustments") or []):
            if adj.get("type") == "coverage_capped":
                capped_records.append(adj)
                if adj.get("capped_to") is None or adj.get("requested_coverage") is None:
                    unrecorded.append(f"{name}: coverage_capped 记录字段缺失")
                elif adj["capped_to"] >= adj["requested_coverage"]:
                    unrecorded.append(
                        f"{name}: capped_to({adj['capped_to']}) 未小于 requested_coverage"
                        f"({adj['requested_coverage']})")
    check("R4.2 触顶时写入 budget_adjustments / coverage_capped",
          bool(capped_records) and not unrecorded,
          "; ".join(unrecorded[:3]) if unrecorded else
          f"共 {len(capped_records)} 条 coverage_capped 记录："
          + ", ".join(f"{a.get('product_type')} {a.get('product')}"
                      f" {a.get('requested_coverage')}→{a.get('capped_to')}"
                      for a in capped_records[:3]))

    # --- R4.3 上限函数语义：无 max_coverage → 不设上限；万元 → 元 ---
    check("R4.3 _coverage_cap 无 max_coverage 时返回 None（不设上限）",
          getattr(pd, "_coverage_cap", lambda _p: 0)({"name": "X"}) is None)
    check("R4.3 _coverage_cap 万元单位换算 ×10000",
          getattr(pd, "_coverage_cap", lambda _p: 0)(
              {"max_coverage": 50, "coverage_unit": "万元"}) == 500000,
          "max_coverage=50 万元 应得 500000 元")
    check("R4.3 _coverage_cap 元单位不换算",
          getattr(pd, "_coverage_cap", lambda _p: 0)(
              {"max_coverage": 500000, "coverage_unit": "元"}) == 500000,
          "max_coverage=500000 元 应得 500000 元")

    # --- R4.4 源码级断言：helper 与各方案上限夹逼已就位 ---
    src = open(os.path.join(SKILL_DIR, "scripts", "plan_designer.py"),
               "r", encoding="utf-8").read()
    check("R4.4 源码含 _coverage_cap / _apply_coverage_cap helper",
          "def _coverage_cap(" in src and "def _apply_coverage_cap(" in src,
          "未找到 helper 定义")
    check("R4.4 三套方案均已接入上限夹逼",
          src.count("_apply_coverage_cap(") >= 13,
          f"_apply_coverage_cap 调用/定义计数 = {src.count('_apply_coverage_cap(')}（≥13）")


def main():
    print("=" * 70)
    print("ClawHub 安全审计整改回归测试（2026-11-07）")
    print(f"SKILL_DIR = {SKILL_DIR}")
    print("=" * 70)

    pd = _load_module("plan_designer", "plan_designer.py")
    pc = _load_module("premium_calculator", "premium_calculator.py")
    san = _load_module("sanitize_products_json", "sanitize_products_json.py")

    test_r3_frontmatter_delimiters()
    test_r4_medical_renewal(pd)
    test_r5_duplicate_filter(pc)
    test_r6_sanitizer(san)
    test_r7_coverage_accounting(pd)
    test_r4_coverage_cap(pd)
    test_r1_r2_publish_surface()
    test_a_400_redline()

    passed = sum(1 for _n, ok, _d in _results if ok)
    total = len(_results)
    print("\n" + "=" * 70)
    print(f"RESULT: {passed}/{total} 项通过")
    if passed != total:
        print("\n失败项：")
        for name, ok, detail in _results:
            if not ok:
                print(f"  [FAIL] {name}" + (f" — {detail}" if detail else ""))
        print("=" * 70)
        return 1
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
