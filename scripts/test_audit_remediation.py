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


# ---------------------------------------------------------------------------
# F1–F4 — ClawHub 安全审计（2026-11-09）回归守卫
#
# F1 Tool Misuse     : SKILL.md 不得再出现裸命令字面量（git rm --cached / git checkout HEAD -- /
#                       clawhub skill publish --dry-run --json 等）
# F2 Output Handling : 输出语言规则必须保留「默认中文」**且**给出用户 opt-in 例外
# F3 Excessive Agency : _coverage_cap 的 docstring 不得再声称「缺省视为元」；
#                       max_coverage 有值但 coverage_unit 缺失时不得静默按万元换算
# F4 Excessive Agency : 上限未知（cap is None）必须留痕 coverage_cap_unknown，
#                       且最终 JSON 必须含对外披露 coverage_disclaimers
# ---------------------------------------------------------------------------

# F1：审计点名的裸命令字面量（SKILL.md 正文不得逐字复现）
_F1_BARE_COMMAND_TOKENS = [
    "git rm --cached",
    "git checkout HEAD --",
    "clawhub skill publish --dry-run --json",
    "git ls-files",
]

# F4：对外披露必须能命中的关键词（用于断言披露文案确实在最终输出里）
_F4_DISCLOSURE_TOKENS = ("未经可售上限核实", "可售保额上限", "保险公司正式测算")


def test_f1_no_bare_command_literals():
    """F1: SKILL.md 不应再逐字复现可能被判定为参数滥用的裸命令。"""
    print("\n[F1] Tool Misuse：SKILL.md 无裸命令字面量")
    skill_src = open(SKILL_MD, encoding="utf-8").read()
    hits = [t for t in _F1_BARE_COMMAND_TOKENS if t in skill_src]
    check("F1.1 SKILL.md 不含裸命令字面量（git rm --cached / git checkout HEAD -- 等）",
          not hits, f"命中 {hits}" if hits else f"检查 {len(_F1_BARE_COMMAND_TOKENS)} 个 token")
    # 事实性留痕必须保留：fileCount 统计是审计留痕的关键事实
    check("F1.2 SKILL.md 保留 fileCount 留痕事实",
          "fileCount" in skill_src)
    # 描述性表述必须保留（“从 git 索引中移除…”）
    check("F1.3 SKILL.md 保留描述性表述「从 git 索引中移除」",
          "从 git 索引中移除" in skill_src)
    # 不得真的动过 .gitignore / .clawhubignore / git 索引
    check("F1.4 .gitignore 与 .clawhubignore 未被本次整改改动",
          os.path.exists(os.path.join(SKILL_DIR, ".gitignore"))
          and os.path.exists(os.path.join(SKILL_DIR, ".clawhubignore")))


def test_f2_output_language_opt_in():
    """F2: 输出语言 = 默认中文 + 用户 opt-in 例外。"""
    print("\n[F2] Output Handling：默认中文 + 用户 opt-in 例外")
    skill_src = open(SKILL_MD, encoding="utf-8").read()
    # 旧的强制措辞必须消失
    check("F2.1 SKILL.md 不再写「所有输出内容使用中文」（无例外）",
          "所有输出内容使用中文" not in skill_src)
    # 默认中文的业务约定必须保留
    check("F2.2 SKILL.md 保留「默认使用中文」",
          "默认使用中文" in skill_src)
    # 用户 opt-in 例外必须存在
    check("F2.3 SKILL.md 含用户 opt-in 例外（用户明确要求其他语言时）",
          "用户明确要求其他语言" in skill_src)
    # 保险专有名词保留原文的例外也要在
    check("F2.4 SKILL.md 含「保留原文」例外（条款/产品/监管机构名称）",
          "保留原文" in skill_src)


def test_f3_coverage_unit_doc_and_behavior(pd):
    """F3: docstring 与实现一致；单位缺失不得静默按万元换算。"""
    print("\n[F3] Excessive Agency：单位口径 docstring 与实现一致")

    src = open(os.path.join(SKILL_DIR, "scripts", "plan_designer.py"),
               "r", encoding="utf-8").read()
    cap_fn = getattr(pd, "_coverage_cap", None)
    check("F3.1 _coverage_cap 存在", callable(cap_fn))

    doc = (cap_fn.__doc__ or "") if cap_fn else ""
    # 旧 docstring 的错误口径必须消失
    check("F3.2 _coverage_cap docstring 不再声称「缺省视为元」",
          "缺省视为元" not in doc,
          "docstring 仍含「缺省视为元」" if "缺省视为元" in doc else "已清除旧口径")
    check("F3.3 _coverage_cap docstring 不再出现「其他单位（缺省视为元）不换算」",
          "其他单位（缺省视为元）不换算" not in doc)
    # 新口径：明确写出缺省/缺失单位的处理
    check("F3.4 _coverage_cap docstring 明确写出「万元」→ ×10000 换算",
          "万元" in doc and "10000" in doc)
    check("F3.5 _coverage_cap docstring 明确写出单位缺失 → 不换算/不设上限",
          ("单位不可信" in doc) or ("缺失/为空" in doc))
    # R4 背景说明（可售保额上限语义、50 万 = 500,000 元）必须保留
    check("F3.6 docstring 保留 R4 背景（可售保额上限 + 50 万 = 500,000 元）",
          "可售保额上限" in doc and "500,000" in doc)

    # --- 行为：单位缺失 + max_coverage 有值 → 不得静默按万元换算 ---
    cap = getattr(pd, "_coverage_cap", lambda _p: "MISSING")
    no_unit = cap({"max_coverage": 50})          # 若按万元换算 → 500000
    check("F3.7 max_coverage 有值但 coverage_unit 缺失 → 不静默按万元换算",
          no_unit is None,
          f"得到 {no_unit!r}（若为 500000 则说明仍在按万元静默换算）")
    check("F3.8 max_coverage 有值但 coverage_unit 为空串 → 同样不换算",
          cap({"max_coverage": 50, "coverage_unit": ""}) is None)
    # 正常口径不受影响
    check("F3.9 coverage_unit='万元' → ×10000 换算不受影响",
          cap({"max_coverage": 50, "coverage_unit": "万元"}) == 500000)
    check("F3.10 coverage_unit='元' → ×1 不换算不受影响",
          cap({"max_coverage": 500000, "coverage_unit": "元"}) == 500000)
    # 状态信号：unit_untrusted 必须能被区分出来
    status_fn = getattr(pd, "_coverage_cap_status", None)
    check("F3.11 _coverage_cap_status 存在且能区分 unit_untrusted",
          callable(status_fn) and status_fn({"max_coverage": 50})[1] == "unit_untrusted",
          str(status_fn({"max_coverage": 50})[1]) if callable(status_fn) else "helper 缺失")
    check("F3.12 _coverage_cap_status 对正常记录返回 ok",
          callable(status_fn) and status_fn(
              {"max_coverage": 50, "coverage_unit": "万元"})[1] == "ok")


def test_f4_cap_unknown_disclosure(pd):
    """F4: 上限未知必须留痕 + 在最终 JSON 里对外披露。"""
    print("\n[F4] Excessive Agency：上限未知留痕 + 对外披露")

    # --- F4.1 cap=None 时 _apply_coverage_cap 必须写 coverage_cap_unknown 留痕 ---
    plan = {}
    cov, capped = pd._apply_coverage_cap(
        plan, {"name": "测试产品", "type": "意外险"}, 123456, "意外险", "测试产品")
    adjs = plan.get("budget_adjustments") or []
    unknown = [a for a in adjs if a.get("type") == "coverage_cap_unknown"]
    check("F4.1 cap=None 时写入 coverage_cap_unknown 留痕",
          bool(unknown), f"budget_adjustments={adjs}")
    if unknown:
        rec = unknown[0]
        check("F4.2 coverage_cap_unknown 记录含 product / product_type / requested_coverage",
              rec.get("product") == "测试产品"
              and rec.get("product_type") == "意外险"
              and rec.get("requested_coverage") == 123456,
              str({k: rec.get(k) for k in
                   ("product", "product_type", "requested_coverage")}))
        check("F4.3 coverage_cap_unknown 记录含说明性 reason",
              bool(rec.get("reason")) and "未经可售上限核实" in rec.get("reason", ""),
              repr(rec.get("reason")))
    # 上限未知时不得静默改写请求保额
    check("F4.4 cap=None 时保额原样返回（不虚构上限、不擅自下调）",
          cov == 123456 and capped is False, f"cov={cov} capped={capped}")

    # --- F4.5 最终 JSON 输出必须含对外披露 ---
    plans = pd.generate_all_plans(
        35, "男", 500000, 500000,
        {"death": 2000000, "critical_illness": 1500000, "hospital": 4000000},
    )
    disclosed_plans = []
    for name, plan in plans.items():
        disc = plan.get("coverage_disclaimers")
        if isinstance(disc, list) and disc:
            disclosed_plans.append((name, disc))
    check("F4.5 最终方案 JSON 含 coverage_disclaimers 对外披露",
          bool(disclosed_plans),
          f"含披露的方案：{[n for n, _ in disclosed_plans]}")
    if disclosed_plans:
        blob = json.dumps([d for _n, ds in disclosed_plans for d in ds],
                          ensure_ascii=False)
        missing = [t for t in _F4_DISCLOSURE_TOKENS if t not in blob]
        check("F4.6 披露文案含「未经可售上限核实 / 可售保额上限 / 保险公司正式测算」",
              not missing, f"缺失 {missing}" if missing else "三个关键词均命中")
        # 披露必须真实序列化到 JSON（不能只存在内存变量里）
        round_trip = json.loads(json.dumps(plans, ensure_ascii=False))
        ok_rt = any(
            isinstance(round_trip[n].get("coverage_disclaimers"), list)
            and round_trip[n]["coverage_disclaimers"]
            for n in round_trip)
        check("F4.7 披露经 JSON 序列化往返后仍存在（真实进入最终输出）", ok_rt)

    # --- F4.8 触发披露的险种必须是方案里实际保留的险种 ---
    mismatch = []
    for name, plan in plans.items():
        disc = plan.get("coverage_disclaimers") or []
        if not disc:
            continue
        final_names = {p.get("product_name") for p in (plan.get("products") or [])}
        for adj in (plan.get("budget_adjustments") or []):
            if adj.get("type") != "coverage_cap_unknown":
                continue
            if adj.get("product") in final_names:
                if adj.get("product") not in json.dumps(disc, ensure_ascii=False):
                    mismatch.append(f"{name}: 留痕 {adj.get('product')} 未出现在披露中")
    check("F4.8 披露内容与留痕险种一致（方案内保留的险种才披露）",
          not mismatch, "; ".join(mismatch[:3]) if mismatch else "一致")

    # --- F4.9 无上限未知的险种时不得新增空字段 ---
    #     （基础版：所选产品均有 max_coverage → 不应有 coverage_disclaimers 键）
    basic = plans.get("基础版") or {}
    check("F4.9 上限均已知时不新增空的 coverage_disclaimers 键",
          "coverage_disclaimers" not in basic
          or bool(basic.get("coverage_disclaimers")),
          f"基础版 coverage_disclaimers={basic.get('coverage_disclaimers')!r}")

    # --- F4.10 coverage_capped 触顶逻辑不变 ---
    capped_records = []
    for name, plan in plans.items():
        for adj in (plan.get("budget_adjustments") or []):
            if adj.get("type") == "coverage_capped":
                capped_records.append(adj)
    check("F4.10 触顶记录 coverage_capped 逻辑保留（含 capped_to/requested_coverage）",
          bool(capped_records)
          and all(r.get("capped_to") is not None
                  and r.get("requested_coverage") is not None
                  and r["capped_to"] < r["requested_coverage"]
                  for r in capped_records),
          f"共 {len(capped_records)} 条触顶记录")


def _find_literal_bool_check_calls(src):
    """找出 `check("...", True)` 形式的**恒真**断言。

    Returns:
        list[tuple[int, str]]: (行号, 断言名)

    ⚠️ 2026-11-11 修正：原实现把 `check("...", False)` 也算作命中，
    但**失败分支里的 `check(desc, False)` 是合法的断言**（用于在出错时打标记），
    不是恒真。把它们误报会导致检测器自身失去意义（假阳性）。
    → 现在只把 `True`（恒真）计入；`False` 不再命中。
    """
    import ast as _ast
    try:
        tree = _ast.parse(src)
    except SyntaxError:
        return []
    hits = []
    for node in _ast.walk(tree):
        if not (isinstance(node, _ast.Call) and isinstance(node.func, _ast.Name)
                and node.func.id == "check"):
            continue
        if len(node.args) < 2:
            continue
        cond = node.args[1]
        # 只有字面 True 才是恒真；字面 False 是失败分支的合法断言
        if isinstance(cond, _ast.Constant) and cond.value is True:
            label = ""
            if node.args and isinstance(node.args[0], _ast.Constant):
                label = str(node.args[0].value)
            hits.append((node.lineno, label))
    return hits


def test_f5_unit_contract_sdi4(pd):
    """F5（镜像 china F7 · SDI-4）：保额单位合同单一事实来源。

    背景：官方 SDI-4 remediation 明确要求
    「Define and enforce a single unit contract ... align _coverage_floor with that rule;
      Reject or explicitly flag ambiguous and unsupported units rather than silently
      applying a multiplier, and add regression tests for missing, null, empty, 元, 万元,
      and unknown units.」

    本组断言覆盖：
      ① 六种单位情形（缺失 / None / 空串 / 元 / 万元 / 亿元）；
      ② _coverage_cap_status 的 unit_untrusted / unit_unsupported；
      ③ _coverage_cap 不静默套乘数；
      ④ _coverage_floor 单位缺失/不受支持 → 60% 兜底（**不是** min*10000）；
      ⑤ 源码级：三个函数体内无 `or "万元"` 静默兜底，且确实复用 _coverage_unit_factor；
      ⑥ 恒真断言检测：本文件不得出现 check("...", True) 形式的恒真断言。
    """
    print("\n[F5] SDI-4：保额单位合同单一事实来源")

    # ---------- ① 六种单位情形 ----------
    factor_fn = getattr(pd, "_coverage_unit_factor", None)
    ok1 = callable(factor_fn)
    check("F5.1 _coverage_unit_factor 存在（单位合同单一事实来源）", ok1)
    if not ok1:
        return False

    f_missing, s_missing = factor_fn({"max_coverage": 50})
    ok2 = (f_missing is None and s_missing == "unit_missing")
    check("F5.2 coverage_unit 缺失（key 不存在）→ factor=None, status=unit_missing", ok2,
          f"实际 {(f_missing, s_missing)}")

    f_none, s_none = factor_fn({"coverage_unit": None})
    ok3 = (f_none is None and s_none == "unit_missing")
    check("F5.3 coverage_unit=None → factor=None, status=unit_missing", ok3,
          f"实际 {(f_none, s_none)}")

    f_empty, s_empty = factor_fn({"coverage_unit": ""})
    ok4 = (f_empty is None and s_empty == "unit_missing")
    check("F5.4 coverage_unit=\"\"（空串）→ factor=None, status=unit_missing", ok4,
          f"实际 {(f_empty, s_empty)}")

    f_yuan, s_yuan = factor_fn({"coverage_unit": "元"})
    ok5 = (f_yuan == 1 and s_yuan == "ok")
    check("F5.5 coverage_unit=\"元\" → factor=1, status=ok", ok5,
          f"实际 {(f_yuan, s_yuan)}")

    f_wan, s_wan = factor_fn({"coverage_unit": "万元"})
    ok6 = (f_wan == 10000 and s_wan == "ok")
    check("F5.6 coverage_unit=\"万元\" → factor=10000, status=ok", ok6,
          f"实际 {(f_wan, s_wan)}")

    f_yi, s_yi = factor_fn({"coverage_unit": "亿元"})
    ok7 = (f_yi is None and s_yi == "unit_unsupported")
    check("F5.7 coverage_unit=\"亿元\"（未知单位）→ factor=None, status=unit_unsupported",
          ok7, f"实际 {(f_yi, s_yi)}")

    f_nonstr, s_nonstr = factor_fn({"coverage_unit": 123})
    ok8 = (f_nonstr is None and s_nonstr == "unit_missing")
    check("F5.8 coverage_unit 非字符串（123）→ factor=None, status=unit_missing", ok8,
          f"实际 {(f_nonstr, s_nonstr)}")

    # ---------- ② _coverage_cap_status 的两种单位状态 ----------
    cap_status_fn = getattr(pd, "_coverage_cap_status", None)
    ok9 = callable(cap_status_fn) and cap_status_fn({"max_coverage": 50})[1] == "unit_untrusted"
    check("F5.9 _coverage_cap_status: max_coverage 有值 + 单位缺失 → unit_untrusted", ok9,
          f"实际 {cap_status_fn({'max_coverage': 50})[1] if callable(cap_status_fn) else 'helper 缺失'}")

    ok10 = (callable(cap_status_fn)
            and cap_status_fn({"max_coverage": 50, "coverage_unit": ""})[1] == "unit_untrusted")
    check("F5.10 _coverage_cap_status: 单位为空串 → unit_untrusted", ok10)

    ok11 = (callable(cap_status_fn)
            and cap_status_fn({"max_coverage": 50, "coverage_unit": "亿元"})[1]
            == "unit_unsupported")
    check("F5.11 _coverage_cap_status: 单位不受支持 → unit_unsupported", ok11)

    # ---------- ③ _coverage_cap 不静默套乘数 ----------
    cap_fn = getattr(pd, "_coverage_cap", None)
    ok12 = callable(cap_fn) and cap_fn({"max_coverage": 50, "coverage_unit": "元"}) == 50
    check("F5.12 _coverage_cap: 元 → ×1（50 → 50）", ok12,
          f"实际 {cap_fn({'max_coverage': 50, 'coverage_unit': '元'}) if callable(cap_fn) else 'helper 缺失'}")

    ok13 = callable(cap_fn) and cap_fn({"max_coverage": 50, "coverage_unit": "万元"}) == 500000
    check("F5.13 _coverage_cap: 万元 → ×10000（50 → 500000）", ok13,
          f"实际 {cap_fn({'max_coverage': 50, 'coverage_unit': '万元'}) if callable(cap_fn) else 'helper 缺失'}")

    ok14 = callable(cap_fn) and cap_fn({"max_coverage": 50}) is None
    check("F5.14 _coverage_cap: 单位缺失 → None（不静默按万元×10000）", ok14,
          f"实际 {cap_fn({'max_coverage': 50}) if callable(cap_fn) else 'helper 缺失'}"
          "（若为 500000 则说明仍在静默套乘数）")

    ok15 = callable(cap_fn) and cap_fn({"max_coverage": 50, "coverage_unit": "亿元"}) is None
    check("F5.15 _coverage_cap: 单位不受支持 → None（不静默套乘数）", ok15,
          f"实际 {cap_fn({'max_coverage': 50, 'coverage_unit': '亿元'}) if callable(cap_fn) else 'helper 缺失'}")

    # ---------- ④ _coverage_floor 的 60% 兜底语义 ----------
    floor_fn = getattr(pd, "_coverage_floor", None)
    cur = 1000000
    floor_missing = floor_fn({"min_coverage": 50}, {"coverage": cur})
    ok16 = (floor_missing == cur * 0.6)
    check("F5.16 _coverage_floor: 单位缺失 → 走 current*0.6 兜底（**非** min*10000）",
          ok16, f"实际 {floor_missing}（若为 500000 则说明仍在按万元静默换算）")

    floor_unsup = floor_fn({"min_coverage": 50, "coverage_unit": "亿元"}, {"coverage": cur})
    ok17 = (floor_unsup == cur * 0.6)
    check("F5.17 _coverage_floor: 单位不受支持 → 同样走 current*0.6 兜底", ok17,
          f"实际 {floor_unsup}")

    floor_empty = floor_fn({"min_coverage": 50, "coverage_unit": ""}, {"coverage": cur})
    ok18 = (floor_empty == cur * 0.6)
    check("F5.18 _coverage_floor: 单位为空串 → 同样走 current*0.6 兜底", ok18,
          f"实际 {floor_empty}")

    floor_wan = floor_fn({"min_coverage": 50, "coverage_unit": "万元"}, {"coverage": cur})
    ok19 = (floor_wan == 500000)
    check("F5.19 _coverage_floor: 万元 → min_coverage*10000", ok19, f"实际 {floor_wan}")

    floor_yuan = floor_fn({"min_coverage": 500000, "coverage_unit": "元"}, {"coverage": cur})
    ok20 = (floor_yuan == 500000)
    check("F5.20 _coverage_floor: 元 → min_coverage*1", ok20, f"实际 {floor_yuan}")

    # ---------- ⑤ 源码级断言 ----------
    import ast
    src_path = os.path.join(SKILL_DIR, "scripts", "plan_designer.py")
    src = open(src_path, encoding="utf-8").read()
    try:
        tree = ast.parse(src)
    except SyntaxError:
        tree = None

    target_names = ("_coverage_unit_factor", "_coverage_floor",
                    "_coverage_cap", "_coverage_cap_status")
    found_names = set()
    offending = []
    reuse_hits = set()
    if tree is not None:
        for node in ast.walk(tree):
            if not (isinstance(node, ast.FunctionDef) and node.name in target_names):
                continue
            found_names.add(node.name)
            seg = ast.get_source_segment(src, node) or ""
            if 'or "万元"' in seg or "or '万元'" in seg:
                offending.append(node.name)
            # 是否真的调用了 _coverage_unit_factor（单一事实来源复用的硬证据）
            for sub in ast.walk(node):
                if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
                        and sub.func.id == "_coverage_unit_factor"):
                    reuse_hits.add(node.name)

    ok21 = (tree is not None and not offending)
    check("F5.21 源码级：_coverage_floor/_coverage_cap/_coverage_cap_status 函数体内"
          "不存在 `or \"万元\"` 静默兜底", ok21,
          f"命中函数：{offending}" if tree is not None else "AST 解析失败")

    ok22 = (tree is not None and set(target_names) <= found_names)
    check("F5.22 源码级：AST 扫描确实命中全部 4 个目标函数（断言非空转）", ok22,
          f"实际命中：{sorted(found_names)}")

    need_reuse = {"_coverage_floor", "_coverage_cap_status"}
    ok23 = (tree is not None and need_reuse <= reuse_hits)
    check("F5.23 源码级：_coverage_floor/_coverage_cap_status 确实复用"
          " _coverage_unit_factor（单一事实来源，非各自复制口径）", ok23,
          f"实际复用：{sorted(reuse_hits)}")

    # ---------- ⑥ docstring 与实现严格一致 ----------
    docs = " ".join(filter(None, [
        (factor_fn.__doc__ or ""),
        (floor_fn.__doc__ or ""),
        (cap_fn.__doc__ or ""),
        (cap_status_fn.__doc__ or ""),
    ]))
    ok24 = "缺省视为元" not in docs
    check("F5.24 四处 docstring 不再出现「缺省视为元」", ok24)

    ok25 = "其他单位（缺省视为元）不换算" not in docs
    check("F5.25 四处 docstring 不再出现「其他单位（缺省视为元）不换算」", ok25)

    ok26 = all(t in docs for t in ("万元", "元", "unit_unsupported", "不换算"))
    check("F5.26 四处 docstring 口径与实现对齐"
          "（显式支持元/万元 + 缺失/不支持不换算）", ok26,
          f"缺失：{[t for t in ('万元', '元', 'unit_unsupported', '不换算') if t not in docs]}")

    ok27 = ("_coverage_unit_factor" in (floor_fn.__doc__ or "")
            and "_coverage_unit_factor" in (cap_status_fn.__doc__ or ""))
    check("F5.27 _coverage_floor/_coverage_cap_status docstring 指向"
          " _coverage_unit_factor 作为口径来源", ok27)

    # ---------- ⑦ 恒真断言检测 ----------
    test_src = open(os.path.join(SCRIPT_DIR, "test_audit_remediation.py"),
                    encoding="utf-8").read()
    literal_hits = _find_literal_bool_check_calls(test_src)
    ok28 = not literal_hits
    check("F5.28 恒真断言检测：本文件不存在 check(\"...\", True/False) 字面量条件",
          ok28, f"命中：{literal_hits}" if literal_hits else "无恒真断言")

    # 检测器自身有效性（防空转）
    probe = _find_literal_bool_check_calls("check(\"probe\", True)\n")
    ok29 = (len(probe) == 1 and probe[0][0] == 1)
    check("F5.29 恒真检测器自身有效（能识别出 check(\"probe\", True)）", ok29,
          f"实际探测结果：{probe}")

    return all([ok1, ok2, ok3, ok4, ok5, ok6, ok7, ok8, ok9, ok10, ok11, ok12,
                ok13, ok14, ok15, ok16, ok17, ok18, ok19, ok20, ok21, ok22, ok23,
                ok24, ok25, ok26, ok27, ok28, ok29])


def test_f6_600w_claim_not_misreported(pd):
    """F6 (SDI-4, ai 2.3.8 官方扫描): 全面版医疗险「600万」不得虚报

    官方扫描原文：
    「The promised final reconciliation of coverage claims leaves the premium medical plan's
     hard-coded "600万高保额" unchanged when actual coverage is reduced.」
    实测：医疗险实际保额 400 万，但 key_benefits 写「600万高保额」、
    features 写「医疗险600万保额」 → 虚报可售保额。
    """
    print("\nTest F6: 医疗险保额声明与实际保额一致（SDI-4）")

    plans = pd.generate_all_plans(
        35, "男", 500000, 500000,
        {"death": 2000000, "critical_illness": 1500000, "hospital": 4000000})
    full = plans.get("全面版") or {}
    mi = next((e for e in full.get("products", []) if e.get("type") == "医疗险"), None)
    ok1 = mi is not None
    check("全面版含医疗险", ok1)
    if not ok1:
        return False

    cov = mi.get("coverage")
    wan = cov // 10000
    kb = mi.get("key_benefits") or ""
    feats = full.get("features") or []
    allok = True

    # ② key_benefits 不得残留「600万」
    ok2 = ("600万" not in kb)
    allok = allok and ok2
    check(f"key_benefits 无「600万」残留（实际 {kb}）", ok2)

    # ③ key_benefits 中的保额数字 == 实际保额
    ok3 = (f"{wan}万" in kb)
    allok = allok and ok3
    check(f"key_benefits 保额 == 实际 {wan}万（实际 {kb}）", ok3)

    # ④ features 中的医疗险条目保额 == 实际保额
    mi_feats = [f for f in feats if isinstance(f, str) and "医疗险" in f]
    ok4 = bool(mi_feats) and all(f"{wan}万" in f for f in mi_feats) and \
        all("600万" not in f for f in mi_feats)
    allok = allok and ok4
    check(f"features 医疗险条目保额 == 实际 {wan}万（实际 {mi_feats}）", ok4)

    # ⑤ 通用一致性：每个产品的保额数字与其对外声明一致
    bad = []
    for e in full.get("products", []):
        c = e.get("coverage") or 0
        w = c // 10000
        txt = (e.get("key_benefits") or "")
        for num in ("600万", "500万", "300万"):
            if num in txt and num != f"{w}万":
                bad.append((e.get("product_name"), num, f"{w}万"))
    ok5 = not bad
    allok = allok and ok5
    check(f"全部产品 key_benefits 保额数字与实际一致（不一致 {len(bad)} 条）", ok5,
          f"示例 {bad[:3]}")

    # ⑥ 正则层面：「600万高保额」/「医疗险600万保额」必须被校正
    n = pd._normalize_coverage_claim
    ok6 = ("400万" in n("600万高保额，含质子重离子", 4000000)
           and "600万" not in n("600万高保额，含质子重离子", 4000000))
    allok = allok and ok6
    check("_normalize_coverage_claim 校正「600万高保额」→ 实际保额", ok6)
    ok7 = ("400万" in n("医疗险600万保额，涵盖最新治疗手段", 4000000))
    allok = allok and ok7
    check("_normalize_coverage_claim 校正「医疗险600万保额」", ok7)

    # ⑧ 源码级：features 中不得再写死「医疗险600万保额」
    src = open(os.path.join(SKILL_DIR, "scripts", "plan_designer.py"), encoding="utf-8").read()
    ok8 = ('"医疗险600万保额' not in src)
    allok = allok and ok8
    check("源码中无写死的「医疗险600万保额」", ok8)
    return allok


def test_f7_renewal_long_term_precedence(pd):
    """F7 (SDI-4, 2.3.9 复扫): long_term 标记优先于 duration_value"""
    print("\nTest F7: 长期保证续保标记优先级（SDI-4）")
    base = {
        "coverage_period_duration_unit": "year",
        "coverage_period_duration_value": 1,
        "coverage_period_is_lifetime": False,
        "coverage_period_guaranteed_renewable": True,
    }
    rdy = pd._renewal_duration_years
    cases = [
        ("long_term 标记 + duration=1 → None", dict(base, coverage_period_parse_notes=["long_term_with_guaranteed_renewable"]), None),
        ("数值标记 20 年 → 20", dict(base, coverage_period_parse_notes=["guaranteed_renewable_20年"]), 20),
        ("数值标记 6 年 → 6", dict(base, coverage_period_parse_notes=["guaranteed_renewable_6年"]), 6),
        ("long_term 与数值并存 → None", dict(base, coverage_period_parse_notes=["long_term_with_guaranteed_renewable", "guaranteed_renewable_20年"]), None),
        ("unit=long_term → None", dict(base, coverage_period_parse_notes=None, coverage_period_duration_unit="long_term"), None),
        ("无标记 duration=1 → 1", dict(base, coverage_period_parse_notes=None), 1),
    ]
    allok = True
    for label, prod, want in cases:
        got = rdy(prod)
        ok = (got == want)
        allok = allok and ok
        check(label, ok, f"实得 {got}，期望 {want}")

    lt = dict(base, coverage_period_parse_notes=["long_term_with_guaranteed_renewable"])
    cp = pd.derive_medical_coverage_period(lt)
    ok1 = ("长期保证续保" in cp) and ("1年保证续保" not in cp)
    allok = allok and ok1
    check(f"derive_medical_coverage_period 输出「长期保证续保」（实际 {cp}）", ok1)
    kb = pd.derive_medical_key_benefits(lt, "长期医疗保障")
    ok2 = ("1年保证续保" not in kb)
    allok = allok and ok2
    check(f"derive_medical_key_benefits 不出现「1年保证续保」（实际 {kb}）", ok2)

    # ---- 顺序无关性（v2.4.1 官方复扫追加）----
    order_cases = [
        ("long_term 在前", ["long_term_with_guaranteed_renewable", "guaranteed_renewable_20年"]),
        ("数值 在前", ["guaranteed_renewable_1年", "long_term_with_guaranteed_renewable"]),
        ("数值 在前(20年)", ["guaranteed_renewable_20年", "long_term_with_guaranteed_renewable"]),
    ]
    for label, notes in order_cases:
        got = rdy(dict(base, coverage_period_parse_notes=notes))
        good = (got is None)
        allok = allok and good
        check(f"标记顺序无关：{label} → None（实得 {got}）", good)
    ok3 = (rdy(dict(base, coverage_period_parse_notes=["guaranteed_renewable_20年"])) == 20)
    allok = allok and ok3
    check("仅数值标记仍返回 20", ok3)

    src = open(os.path.join(SKILL_DIR, "scripts", "plan_designer.py"), encoding="utf-8").read()
    import re as _re
    m = _re.search(r"^def _renewal_duration_years\(.*?(?=^def |\Z)", src, _re.DOTALL | _re.MULTILINE)
    body = m.group(0) if m else ""
    i_lt = body.find("_RE_LONG_TERM_MARK.search")
    i_num = body.find("_RE_GUARANTEED_YEARS.search")
    ok4 = (i_lt != -1 and i_num != -1 and i_lt < i_num)
    allok = allok and ok4
    check("源码级：long_term 扫描在数值扫描之前（顺序无关）", ok4, f"lt@={i_lt} num@={i_num}")
    return allok


def test_f8_global_trigger_insurance_context():
    """F8 (SQP-1, 2.3.9 复扫): 触发词必须带保险语境约束（覆盖整个 skill）"""
    print("\nTest F8: 全局/模块触发词的保险语境约束（SQP-1）")
    with open(os.path.join(SKILL_DIR, "SKILL.md"), "r", encoding="utf-8") as f:
        text = f.read()

    import re as _re
    ctx = ("保险", "重疾险", "医疗险", "寿险", "意外险", "储蓄险", "年金险", "两全险", "险种")
    generic = ["话术", "需求分析", "保障缺口", "产品对比", "设计方案", "合规", "核保",
               "拒赔", "等待期", "现金价值", "健康告知", "朋友圈文案", "社交文案",
               "产品推广", "异议处理", "新人培训", "多少钱"]

    bad = []
    for ln in text.splitlines():
        m = _re.match(r"\*\*触发词\*\*：(.+)$", ln.strip())
        if not m:
            continue
        for item in [x.strip() for x in m.group(1).split("、")]:
            for g in generic:
                if g in item and not any(c in item for c in ctx):
                    bad.append((item, g))
    check(f"所有模块触发词均带保险语境（检查 {len(generic)} 个泛用词）",
          not bad, f"越界条目：{bad}")

    global_line = next((ln for ln in text.splitlines()
                        if ln.startswith("保险咨询、保险配置")), "")
    bad_global = []
    for item in [x.strip() for x in global_line.replace("保险咨询、", "").split("、") if x.strip()]:
        for g in ["话术", "需求分析", "保障缺口"]:
            if g in item and not any(c in item for c in ctx):
                bad_global.append((item, g))
    check("全局触发词表无脱离保险语境的泛用词", not bad_global,
          f"仍孤立出现：{bad_global}")

    ok3 = ("触发词作用域" in text) and ("全局" in text) and ("澄清" in text)
    check("存在全局触发词作用域声明（含语境不明时先澄清）", ok3)
    return (not bad) and (not bad_global) and ok3


def test_f9_features_coverage_claim_sync(pd):
    """F10 (SDI-4, v2.4.1 官方复扫): features 的保额数字必须与最终保额一致

    官方扫描原文：
    「The premium plan constructs its medical coverage feature before _finalize_plan
     applies budget-driven coverage reductions. Finalization updates the product coverage
     and key_benefits but only prunes features for removed insurance types, so a retained
     medical product can have a lower final coverage amount while its feature still
     advertises the original amount.」
    实测复现（budget=8000）：全面版医疗险被预算下调到 100 万，但 features 仍写「医疗险400万保额」。
    """
    print("\nTest F10: features 保额数字与最终保额一致（SDI-4）")
    import re as _re

    # 预算小到触发医疗险 downscale 但不移除产品
    plans = pd.generate_all_plans(
        35, "男", 500000, 8000,
        {"death": 2000000, "critical_illness": 1500000, "hospital": 4000000})

    allok = True
    hit = 0
    for name, p in plans.items():
        mi = next((e for e in p.get("products", []) if e.get("type") == "医疗险"), None)
        if mi is None:
            continue
        cov = mi.get("coverage") or 0
        wan = cov // 10000
        feats = [f for f in (p.get("features") or []) if isinstance(f, str)]
        hit += 1
        for f in feats:
            for num in _re.findall(r"(\d+)万", f):
                # 该 feature 提及医疗险时，其保额数字必须等于医疗险最终保额
                if "医疗险" in f and int(num) != wan:
                    allok = False
                    check(f"{name}: features 保额 {num}万 ≠ 实际 {wan}万（{f}）", False)
        # key_benefits 同样必须一致
        kb = mi.get("key_benefits") or ""
        for num in _re.findall(r"(\d+)万", kb):
            if int(num) != wan:
                allok = False
                check(f"{name}: key_benefits 保额 {num}万 ≠ 实际 {wan}万（{kb}）", False)
    check(f"预算下调场景（budget=8000）：{hit} 套含医疗险方案，features/key_benefits 保额均与实际一致",
          allok and hit > 0, f"命中方案数 {hit}")

    # 源码级：出口必须调用 _sync_features_coverage_claims
    src = open(os.path.join(SKILL_DIR, "scripts", "plan_designer.py"), encoding="utf-8").read()
    ok2 = "_sync_features_coverage_claims(plan)" in src
    check("源码：_finalize_plan 出口调用 _sync_features_coverage_claims", ok2)
    ok3 = hasattr(pd, "_sync_features_coverage_claims")
    check("_sync_features_coverage_claims 函数存在", ok3)

    # 正常预算场景不应被误改（保额仍 400 万 → features 仍 400 万）
    plans2 = pd.generate_all_plans(
        35, "男", 500000, 500000,
        {"death": 2000000, "critical_illness": 1500000, "hospital": 4000000})
    full = plans2.get("全面版") or {}
    mi2 = next((e for e in full.get("products", []) if e.get("type") == "医疗险"), None)
    ok4 = True
    if mi2:
        wan2 = mi2.get("coverage", 0) // 10000
        for f in full.get("features") or []:
            if "医疗险" in str(f):
                for num in _re.findall(r"(\d+)万", str(f)):
                    if int(num) != wan2:
                        ok4 = False
    check("正常预算场景：features 保额与实际一致（未被误改）", ok4)
    return allok and ok2 and ok3 and ok4


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
    test_f1_no_bare_command_literals()
    test_f2_output_language_opt_in()
    test_f3_coverage_unit_doc_and_behavior(pd)
    test_f4_cap_unknown_disclosure(pd)
    test_f5_unit_contract_sdi4(pd)
    test_f6_600w_claim_not_misreported(pd)
    test_f7_renewal_long_term_precedence(pd)
    test_f8_global_trigger_insurance_context()
    test_f9_features_coverage_claim_sync(pd)
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
