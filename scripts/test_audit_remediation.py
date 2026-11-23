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


def test_f11_income_multiple_claim_sync(pd):
    """F11 (SDI-4, 2.4.3 官方复扫): 「年收入 N 倍」卖点必须随最终保额同步

    官方扫描原文（ai-insurance-advisor 2.4.3）：
    「The comprehensive plan retains a five-times-income coverage claim even when
     actual critical-illness coverage is capped or reduced.」

    根因：出口同步 `_sync_features_coverage_claims()` / `_normalize_coverage_claim()`
    只处理「数字+万」形态；「重疾险保额高达年收入5倍」不含「万」→ 完全不被校正。

    实测复现（budget=8000，annual_income=500000）：全面版重疾险被预算下调到
    105,717 元（≈0.21× 年收入），但 features 仍宣称「重疾险保额高达年收入5倍」。

    断言：
      ① 预算受限场景：features 中的倍数 ≤ 实际保额 / 年收入（不得虚报）；
      ② 不残留与实际保额不符的硬编码「年收入5倍」；
      ③ 正常场景（实际倍数 ≥ 5）表述保持原样（不得弱化、不得「5倍 → 5.0倍」）；
      ④ 同步函数幂等。
    """
    print("\nTest F11: features「年收入 N 倍」与最终保额一致（SDI-4 · 2.4.3 复扫）")
    import re as _re

    _MULT_RE = _re.compile(r"年收入(\d+(?:\.\d+)?)倍")

    def _claims(plan):
        """提取该方案 features 中所有「年收入 N 倍」表述。"""
        return [(f, float(_MULT_RE.search(f).group(1)))
                for f in (plan.get("features") or [])
                if isinstance(f, str) and _MULT_RE.search(f)]

    def _ci_coverage(plan):
        e = next((x for x in (plan.get("products") or []) if x.get("type") == "重疾险"), None)
        return (e.get("coverage") or 0) if e else None

    # ---- ① 预算受限场景：倍数不得超过实际保额 / 年收入 ----
    income = 500000
    plans = pd.generate_all_plans(
        35, "男", income, 8000,
        {"death": 2000000, "critical_illness": 1500000, "hospital": 4000000})
    over = []
    checked = 0
    for name, p in plans.items():
        cov = _ci_coverage(p)
        if cov is None:
            continue
        ratio = cov / income
        for f, mult in _claims(p):
            checked += 1
            if mult > ratio + 1e-9:
                over.append(f"{name}: 倍数 {mult} > 实际 {ratio:.4f}（{f}）")
    check("预算受限场景（budget=8000）：features 倍数 ≤ 实际保额/年收入",
          not over, "; ".join(over[:3]) if over else f"校验 {checked} 条倍数表述")

    # ---- ② 不得残留与实际保额不符的硬编码「年收入5倍」 ----
    full = plans.get("全面版") or {}
    cov = _ci_coverage(full)
    ratio = (cov / income) if cov else 0
    stale = [f for f, mult in _claims(full) if mult > ratio + 1e-9]
    check("预算受限场景：不残留虚报的「年收入5倍」硬编码倍数",
          not stale, "; ".join(stale[:3]) if stale else
          (f"实际保额={cov}（{ratio:.4f}× 年收入），倍数表述已同步"))

    # ---- ③ 正常场景：实际倍数 ≥ 5 时表述保持原样（不弱化、无无意义 diff）----
    # income=100000 且重疾险保额 500000 → 恰好 5× 年收入 → 原文案必须原样保留
    plans_ok = pd.generate_all_plans(
        35, "男", 100000, 100000, {"death": 100000, "hospital": 1000000})
    ok_claims = _claims(plans_ok.get("全面版") or {})
    check("正常场景（实际倍数=5）：表述保持原样「重疾险保额高达年收入5倍」",
          any("重疾险保额高达年收入5倍" == f for f, _ in ok_claims),
          str([f for f, _ in ok_claims]))

    # 正常场景不得出现「5.0倍」这类无意义改写
    no_dot = [f for f, _ in ok_claims if "5.0倍" in f]
    check("正常场景：不得出现「5.0倍」无意义 diff", not no_dot, str(no_dot))

    # 正常场景（收入 500000，重疾险 500000 = 1×）必须同步下调，不得仍宣称 5 倍
    plans_norm = pd.generate_all_plans(
        35, "男", 500000, 500000,
        {"death": 2000000, "critical_illness": 1500000, "hospital": 4000000})
    norm_claims = _claims(plans_norm.get("全面版") or {})
    ok_norm = bool(norm_claims) and all(m <= 1.0 + 1e-9 for _, m in norm_claims)
    check("预算充足场景：倍数同样必须与实际保额一致（1× 年收入 → 不得宣称 5 倍）",
          ok_norm, str([f for f, _ in norm_claims]))

    # ---- ④ 幂等性：连续同步结果一致 ----
    p1 = dict(plans.get("全面版") or {})
    p1 = {"features": list(p1.get("features") or []), "products": p1.get("products") or []}
    a1 = pd._sync_features_income_multiple_claims(p1, income)
    a2 = pd._sync_features_income_multiple_claims(
        {"features": a1, "products": p1["products"]}, income)
    a3 = pd._sync_features_income_multiple_claims(
        {"features": a2, "products": p1["products"]}, income)
    check("同步函数幂等（连续 3 次同步结果一致）", a1 == a2 == a3)

    # ---- ⑤ 源码级：出口必须调用新同步函数 ----
    src = open(os.path.join(SKILL_DIR, "scripts", "plan_designer.py"), encoding="utf-8").read()
    ok_src = "_sync_features_income_multiple_claims(plan, annual_income)" in src
    check("源码：_finalize_plan 出口调用 _sync_features_income_multiple_claims", ok_src)
    ok_has = hasattr(pd, "_sync_features_income_multiple_claims")
    check("_sync_features_income_multiple_claims 函数存在", ok_has)

    return (not over) and (not stale) and ok_norm and (a1 == a2 == a3) and ok_src and ok_has



def test_f12_crx_claim_derivation(PD):
    """F12 (SDI-4, 官方 2.4.4 复扫): 重疾险对外宣称必须由**产品真实字段**派生

    官方原文：
    「The comprehensive plan can advertise multiple critical-illness payouts and lifetime
     protection for a fallback product whose terms have not been verified.」

    根因（两处叠加）：
      ① 全面版「多次赔付」选品条件恒假（`"多次" in (p.get("core_coverage") or "")`
         对全部重疾险恒假）→ 永远退化为兜底任意一款 → 公告级 finding
         「fallback product whose terms have not been verified」；
      ② `coverage_period` 写死「终身」、`key_benefits` 写死
         「重疾多次赔付，终身保障」「120种重疾+轻症保障」→ 无论兜底品条款如何照写虚报。

    三类用例：
      ① **低预算档位**（income=200000, budget=5000）：重疾条目的 `coverage_period`
         必须等于产品库真实字段（不得写死）；
      ② **对抗场景**：产品池里所有重疾险换成非多次/非终身的「康宁惠享版（定期）」
         → 方案**不得**宣称「多次赔付」「终身保障」「轻症」「N种重疾」，
         且 `coverage_period != "终身"`；
      ③ **年收入缺失**（income=0）：不得出现「年收入 N 倍」形态的宣称。

    事实源（不依赖 plan_designer 里的派生 helper，直接读产品库原始字段）：
      - 「多次赔付」← `subtype` 含「多次」
      - 「终身」     ← `coverage_period_is_lifetime` / `coverage_period == "终身"`
      - 病种/轻症    ← `highlights` 字符串含「轻症」且能匹配「N种重疾」
    """
    print("\nTest F12: 重疾险对外宣称由产品真实字段派生（SDI-4 · 官方 2.4.4 复扫）")
    import re as _re

    _DISEASE_RE = _re.compile(r"\d+\s*种重疾")
    _BANNED = ("多次赔付", "终身保障", "轻症")

    products = PD.load_products()
    index = {(p.get("name"), p.get("company")): p for p in products}

    def _is_lifetime(p):
        flag = p.get("coverage_period_is_lifetime")
        if flag is True:
            return True
        if flag is False:
            return False
        return (p.get("coverage_period") or "").strip() == "终身"

    def _crx_entries(plan):
        return [e for e in (plan.get("products") or []) if e.get("type") == "重疾险"]

    # ==================================================================
    # ① 低预算档位：coverage_period 必须等于产品库真实字段
    # ==================================================================
    low_plans = PD.generate_all_plans(
        35, "男", 200000, 5000,
        {"death": 2000000, "critical_illness": 1500000, "hospital": 4000000})
    mismatch = []
    checked = 0
    for pname, plan in low_plans.items():
        if not plan:
            continue
        for entry in _crx_entries(plan):
            real = index.get((entry.get("product_name"), entry.get("company")))
            if real is None:
                mismatch.append(f"{pname}: 产品库无 {entry.get('product_name')}")
                continue
            checked += 1
            expect = (real.get("coverage_period") or "").strip()
            got = (entry.get("coverage_period") or "").strip()
            if got != expect:
                mismatch.append(f"{pname}: cp={got!r} != 真实 {expect!r}")
    check("低预算档位（income=200000, budget=5000）：重疾 coverage_period == 产品真实字段",
          bool(checked) and not mismatch,
          "; ".join(mismatch[:3]) if mismatch else f"校验 {checked} 条重疾条目")

    # ==================================================================
    # ② 对抗场景：产品池全为非多次/非终身重疾 → 兜底品必须如实描述
    # ==================================================================
    crx_all = [p for p in products if p.get("type") == "重疾险"]
    adversarial = next(
        (p for p in crx_all
         if "多次" not in (p.get("subtype") or "")
         and not _is_lifetime(p)
         and "轻症" not in (p.get("highlights") or "")
         and not _DISEASE_RE.search(p.get("highlights") or "")),
        None)
    check("产品库存在可用于对抗场景的重疾险（非多次/非终身/无轻症）",
          adversarial is not None,
          adversarial.get("name") if adversarial else "产品库无对抗品")

    if adversarial is not None:
        adv_pool = [adversarial if p.get("type") == "重疾险" else p for p in products]
        orig_load = PD.load_products
        PD.load_products = lambda include_discontinued=False: list(adv_pool)
        try:
            adv_plans = PD.generate_all_plans(
                35, "男", 300000, 200000,
                {"death": 2000000, "critical_illness": 1500000, "hospital": 4000000})
        finally:
            PD.load_products = orig_load

        adv_claims = []
        adv_cp_bad = []
        adv_seen = 0
        for pname, plan in adv_plans.items():
            if not plan:
                continue
            for entry in _crx_entries(plan):
                adv_seen += 1
                kb = entry.get("key_benefits") or ""
                cp = entry.get("coverage_period") or ""
                text = kb + "\n" + cp
                for word in _BANNED:
                    if word in text:
                        adv_claims.append(f"{pname}: {word} in {text!r}")
                if _DISEASE_RE.search(text):
                    adv_claims.append(f"{pname}: 病种数宣称 in {text!r}")
                if cp.strip() == "终身":
                    adv_cp_bad.append(f"{pname}: cp={cp!r}")
                if cp.strip() != (adversarial.get("coverage_period") or "").strip():
                    adv_cp_bad.append(
                        f"{pname}: cp={cp!r} != 真实 {(adversarial.get('coverage_period') or '')!r}")

        check("对抗场景：方案产出重疾条目（用例有效）", adv_seen > 0, f"共 {adv_seen} 条")
        check("对抗场景：不得宣称「多次赔付」「终身保障」「轻症」「N种重疾」",
              not adv_claims, "; ".join(adv_claims[:3]))
        check("对抗场景：coverage_period 不得写「终身」且须与产品真实字段一致",
              not adv_cp_bad, "; ".join(adv_cp_bad[:3]))

    # ==================================================================
    # ③ 年收入缺失（income=0）：不得出现「年收入 N 倍」形态的宣称
    # ==================================================================
    zero_plans = PD.generate_all_plans(
        35, "男", 0, 100000,
        {"death": 2000000, "critical_illness": 1500000, "hospital": 4000000})
    mult_claims = []
    for pname, plan in zero_plans.items():
        if not plan:
            continue
        for feat in (plan.get("features") or []):
            if isinstance(feat, str) and _re.search(r"年收入\s*\d+(?:\.\d+)?\s*倍", feat):
                mult_claims.append(f"{pname}: {feat!r}")
        for lim in (plan.get("limitations") or []):
            s = lim if isinstance(lim, str) else json.dumps(lim, ensure_ascii=False)
            if _re.search(r"年收入\s*\d+(?:\.\d+)?\s*倍", s):
                mult_claims.append(f"{pname}: limitation {s!r}")
    check("年收入缺失（income=0）：不得出现「年收入 N 倍」形态的宣称",
          not mult_claims, "; ".join(mult_claims[:3]))

    return True


# ==================================================================
# F13 — SDI-4 官方 2.4.7 复扫：治疗手段宣称的「否定语境」回归守卫
# ==================================================================
def test_f13_treatment_negation_context(pd):
    """F13 (SDI-4, 官方 2.4.7 复扫): 治疗手段宣称必须感知**否定语境**

    官方原文（scanner 2.12.0 · SDI-4 · Excessive Agency · MEDIUM · 置信 0.99）：
    「Treatment claims are presented as covered benefits based on keyword presence,
      even when the source excludes them.」

    根因：`_medical_treatment_claims` 只判「关键词是否出现」（`kw in blob`），
         **不判**「这次出现是否被条款排除」→ 「不含CAR-T」「质子重离子不予报销」
         也会被转成「，含CAR-T治疗」的**承保宣称**（纯除外条款被误读为承保）。

    修法：逐次出现判定 —— 每次出现都取上下文窗口判断是否落在否定/除外语境；
         同一关键词全部出现皆为否定 → 不计入 claims；
         存在非否定出现（肯定 + 否定并存）→ 仍计入。
         ⚠️ 2026-11-17 官方 2.4.15 SDI-4 #2 口径收紧：最后一条**已失效** ——
         肯定 + 否定并存 → 一律 unverified → 不宣称（记录级冲突）。

    覆盖：6 个对抗场景 + 1 条源码级断言（防止否定判断被删回无条件判定）。
    """
    print("\n[F13] 治疗手段宣称的否定语境感知（SDI-4 · 官方 2.4.7 复扫）")

    # ------------------------------------------------------------------
    # ① 6 个对抗场景
    # ------------------------------------------------------------------
    # (名称, 产品字典, 期望 claims, 期望 suffix)
    scenarios = [
        ("裸关键词无肯定授权证据（残余 C 口径）：质子重离子治疗",
         {"key_benefits": ["质子重离子治疗"], "highlights": ""},
         [], ""),
        ("有明确肯定授权证据（残余 C 不得过度收紧）：质子重离子治疗费用报销",
         {"key_benefits": ["质子重离子治疗费用报销"], "highlights": ""},
         ["质子重离子"], "，含质子重离子治疗"),
        ("纯否定：不含CAR-T",
         {"key_benefits": ["不含CAR-T"], "highlights": ""},
         [], ""),
        ("纯否定：质子重离子不予报销",
         {"key_benefits": [], "highlights": "质子重离子不予报销"},
         [], ""),
        # ⚠️ 官方 2.4.15 复扫 SDI-4 #2 口径收紧（2026-11-17）：同一治疗手段在
        #    **整条产品记录**内既有肯定证据又有除外证据 → 一律 unverified →
        #    不宣称（官方 remediation 原文「...anywhere in the product record as
        #    an unresolved conflict, regardless of element or field boundaries.」）。
        #    这是**官方要求的口径收紧**，不是产品行为回归（真实产品库实测零影响）。
        ("肯定+否定并存：含CAR-T / 不含CAR-T",
         {"key_benefits": ["含CAR-T", "不含CAR-T"], "highlights": ""},
         [], ""),
        ("跨字段纯否定：key_benefits 进口药 + highlights 不予报销",
         {"key_benefits": ["进口药"], "highlights": "进口药不予报销"},
         [], ""),
        ("空 blob",
         {"key_benefits": [], "highlights": ""},
         [], ""),
    ]
    for name, product, expect_claims, expect_suffix in scenarios:
        got_claims = pd._medical_treatment_claims(product)
        got_suffix = pd._medical_treatment_suffix(product)
        check(f"F13.1 对抗场景「{name}」：claims == {expect_claims}",
              got_claims == expect_claims, f"实际 {got_claims}")
        check(f"F13.1 对抗场景「{name}」：suffix == {expect_suffix!r}",
              got_suffix == expect_suffix, f"实际 {got_suffix!r}")

    # 纯否定场景的关键语义：suffix 不得出现「含<关键词>治疗」
    for kw in ("CAR-T", "质子重离子", "进口药"):
        bad = []
        for product in ({"key_benefits": [f"不含{kw}"], "highlights": ""},
                        {"key_benefits": [], "highlights": f"{kw}不予报销"},
                        {"key_benefits": [f"{kw}"], "highlights": f"{kw}不予报销"}):
            suffix = pd._medical_treatment_suffix(product)
            if f"含{kw}" in suffix:
                bad.append(suffix)
        check(f"F13.2 纯否定「{kw}」不得被转成承保宣称（suffix 不含「含{kw}」）",
              not bad, "; ".join(bad[:3]))

    # ⚠️ 口径变更（官方 2.4.15 复扫 SDI-4 #2 · 2026-11-17）：「肯定+否定并存」
    #    **不再**算有授权。官方 remediation 原文：
    #      「Treat positive and negative evidence for the same treatment anywhere in
    #        the product record as an unresolved conflict, regardless of element or
    #        field boundaries.」
    #    → 同一治疗手段既有肯定证据又有除外证据 → 一律 unverified → 不宣称。
    #    这是**官方要求的口径收紧**，不是产品行为回归（真实产品库实测零影响）。
    both = pd._medical_treatment_claims(
        {"key_benefits": ["含CAR-T", "不含CAR-T"], "highlights": ""})
    check("F13.3 肯定+否定并存（官方 2.4.15 SDI-4 #2 口径）：记录级冲突 → 不得计入 claims",
          "CAR-T" not in both, f"实际 {both}")

    # ------------------------------------------------------------------
    # ② 源码级断言：不得再出现无条件 `kw in blob` 直接判定
    # ------------------------------------------------------------------
    src = open(os.path.join(SCRIPT_DIR, "plan_designer.py"), encoding="utf-8").read()
    fn_m = re.search(
        r"^def _medical_treatment_claims\(product\):\n(?P<body>(?:[ \t].*\n|\n)*)",
        src, re.MULTILINE)
    if fn_m is None:
        check("F13.4 源码级：定位到 _medical_treatment_claims 函数体", False)
        return False
    body = fn_m.group("body")
    ok_src = not re.search(r"\bkw\s+in\s+blob\b", body)
    check("F13.4 源码级：_medical_treatment_claims 函数体内不得出现无条件 `kw in blob` 判定",
          ok_src, "命中无条件子串判定" if not ok_src else "")
    check("F13.5 源码级：_medical_treatment_claims 走否定语境判定（_keyword_is_negated）",
          "_keyword_is_negated" in body)

    # 事实源口径不得被改动（只对**实际代码**断言，不看 docstring）
    fact_m = re.search(
        r"^def _medical_fact_text\(product\):\n(?P<body>(?:[ \t].*\n|\n)*)",
        src, re.MULTILINE)
    fact_body = fact_m.group("body") if fact_m else ""
    fact_code = re.sub(r'"""[\s\S]*?"""', "", fact_body, count=1)
    check("F13.6 事实源口径未变：_medical_fact_text 仍只用 key_benefits + highlights",
          ("key_benefits" in fact_code) and ("highlights" in fact_code)
          and ("notes" not in fact_code) and ("suitable_for" not in fact_code)
          and ("competitive_edge" not in fact_code))

    kw_m = re.search(r"^_TREATMENT_CLAIMS\s*=\s*\(([^)]*)\)", src, re.MULTILINE)
    kw_set = tuple(re.findall(r'"([^"]+)"', kw_m.group(1))) if kw_m else ()
    check("F13.7 _TREATMENT_CLAIMS 关键词集合未被改动",
          kw_set == ("质子重离子", "CAR-T", "靶向药", "外购药", "特药", "进口药"),
          f"实际 {kw_set}")

    return True


def test_f14_treatment_negation_scope(pd):
    """F14 (SDI-4 变体 · 官方 2.4.8 复扫): 肯定回退不得越过**除外作用域**

    官方 finding 原文（scanner 2.12.0 · SDI-4 · Excessive Agency · MEDIUM · 置信 0.99）：
    「Excluded treatments can still be advertised as covered, contradicting the
      documented prohibition on converting exclusions into coverage claims.」

    官方 explanation 原文：
    「The treatment-claim logic can override a detected exclusion because
      _occurrence_is_affirmative does not require the treatment occurrence or its
      affirmative wording to be outside the negated scope. For example,
      "不包含CAR-T治疗费用给付" marks CAR-T as excluded, but the nearby "给付"
      satisfies the affirmative check, causing _medical_treatment_suffix to
      advertise "含CAR-T治疗".」

    根因：否定**词字符跨度** ≠ 否定**作用域**。
    「不含」的字符跨度只有 (0,2)，但它的作用域一直延伸到子句末尾 ——
    作用域内的「报销」「给付」属于除外条款自身，**不得**当作对 CAR-T 的承保授权。

    修法：肯定证据必须 (a) 落在该次出现之外、(b) 落在**整个除外作用域**之外、
         (c) 与除外条款**同字段**（跨字段冲突 → 官方口径「unverified」不宣称）。

    覆盖：8 个对抗场景 + 源码级断言（防改回）+ F13 全场景交叉验证。
    """
    print("\n[F14] 除外作用域内的肯定词不得授权承保宣称（SDI-4 变体 · 官方 2.4.8 复扫）")

    # ==================================================================
    # ① 8 个对抗场景（期望值是手写常量，不从实现推导）
    # ==================================================================
    scenarios = [
        ("官方 finding 原文场景：不含CAR-T治疗费用报销",
         {"key_benefits": ["不含CAR-T治疗费用报销"], "highlights": ""},
         [], ""),
        ("官方 finding 原文场景：不包含CAR-T治疗费用给付",
         {"key_benefits": ["不包含CAR-T治疗费用给付"], "highlights": ""},
         [], ""),
        ("纯肯定：质子重离子治疗费用报销",
         {"key_benefits": ["质子重离子治疗费用报销"], "highlights": ""},
         ["质子重离子"], "，含质子重离子治疗"),
        # ⚠️ 官方 2.4.15 复扫 SDI-4 #2 口径收紧（2026-11-17）：同一治疗手段在
        #    **整条产品记录**内既有肯定证据又有除外证据 → 一律 unverified →
        #    不宣称（官方 remediation 原文「...anywhere in the product record as
        #    an unresolved conflict, regardless of element or field boundaries.」）。
        #    这是**官方要求的口径收紧**，不是产品行为回归（真实产品库实测零影响）。
        ("肯定+否定并存：含CAR-T / 不含CAR-T",
         {"key_benefits": ["含CAR-T", "不含CAR-T"], "highlights": ""},
         [], ""),
        ("别子句的肯定词不得授权 CAR-T：不含CAR-T，质子重离子可报销",
         {"key_benefits": ["不含CAR-T，质子重离子可报销"], "highlights": ""},
         ["质子重离子"], "，含质子重离子治疗"),
        ("跨字段纯否定：kb 进口药 + highlights 不予报销",
         {"key_benefits": ["进口药"], "highlights": "进口药不予报销"},
         [], ""),
        ("跨字段冲突（kb 肯定 + highlights 否定）→ unverified 不宣称",
         {"key_benefits": ["含CAR-T"], "highlights": "CAR-T不予报销"},
         [], ""),
        ("同字段否定 + 跨字段肯定 → 不得授权",
         {"key_benefits": ["不含CAR-T治疗"], "highlights": "CAR-T费用可报销"},
         [], ""),
    ]
    for name, product, expect_claims, expect_suffix in scenarios:
        got_claims = pd._medical_treatment_claims(product)
        got_suffix = pd._medical_treatment_suffix(product)
        check(f"F14.1 对抗场景「{name}」：claims == {expect_claims}",
              got_claims == expect_claims, f"实际 {got_claims}")
        check(f"F14.1 对抗场景「{name}」：suffix == {expect_suffix!r}",
              got_suffix == expect_suffix, f"实际 {got_suffix!r}")

    # ==================================================================
    # ② 源码级断言：不得把「作用域外」这一维改回去
    # ==================================================================
    src = open(os.path.join(SCRIPT_DIR, "plan_designer.py"), encoding="utf-8").read()

    aff_m = re.search(
        r"^def _has_affirmative\((?P<sig>.*?)\):\n(?P<body>(?:[ \t].*\n|\n)*)",
        src, re.MULTILINE)
    if aff_m is None:
        check("F14.2 源码级：定位到 _has_affirmative 函数", False)
    else:
        sig = aff_m.group("sig")
        check("F14.2 源码级：_has_affirmative 签名含 excluded 参数（作用域排除）",
              "excluded" in sig, f"实际签名 ({sig.strip()})")
        aff_body = aff_m.group("body")
        check("F14.3 源码级：_has_affirmative 函数体使用了 excluded",
              "excluded" in aff_body)

    claims_m = re.search(
        r"^def _medical_treatment_claims\(product\):\n(?P<body>(?:[ \t].*\n|\n)*)",
        src, re.MULTILINE)
    if claims_m is None:
        check("F14.4 源码级：定位到 _medical_treatment_claims 函数体", False)
    else:
        claims_body = claims_m.group("body")
        check("F14.4 源码级：_medical_treatment_claims 走 _negation_scope_map 作用域判定",
              "_negation_scope_map" in claims_body)
        check("F14.5 源码级：_negation_scope_map 函数已定义",
              "_negation_scope_map" in src)

    # ==================================================================
    # ③ F13 全场景交叉验证（F14 的改动不得把 F13 打挂）
    # ==================================================================
    f13_scenarios = [
        ("裸关键词无肯定授权证据（残余 C 口径）：质子重离子治疗",
         {"key_benefits": ["质子重离子治疗"], "highlights": ""},
         [], ""),
        ("有明确肯定授权证据（残余 C 不得过度收紧）：质子重离子治疗费用报销",
         {"key_benefits": ["质子重离子治疗费用报销"], "highlights": ""},
         ["质子重离子"], "，含质子重离子治疗"),
        ("纯否定：不含CAR-T",
         {"key_benefits": ["不含CAR-T"], "highlights": ""}, [], ""),
        ("纯否定：质子重离子不予报销",
         {"key_benefits": [], "highlights": "质子重离子不予报销"}, [], ""),
        # ⚠️ 官方 2.4.15 复扫 SDI-4 #2 口径收紧（2026-11-17）：同一治疗手段在
        #    **整条产品记录**内既有肯定证据又有除外证据 → 一律 unverified →
        #    不宣称（官方 remediation 原文「...anywhere in the product record as
        #    an unresolved conflict, regardless of element or field boundaries.」）。
        #    这是**官方要求的口径收紧**，不是产品行为回归（真实产品库实测零影响）。
        ("肯定+否定并存：含CAR-T / 不含CAR-T",
         {"key_benefits": ["含CAR-T", "不含CAR-T"], "highlights": ""},
         [], ""),
        ("跨字段纯否定：key_benefits 进口药 + highlights 不予报销",
         {"key_benefits": ["进口药"], "highlights": "进口药不予报销"}, [], ""),
        ("空 blob",
         {"key_benefits": [], "highlights": ""}, [], ""),
    ]
    for name, product, expect_claims, expect_suffix in f13_scenarios:
        got_claims = pd._medical_treatment_claims(product)
        got_suffix = pd._medical_treatment_suffix(product)
        check(f"F14.6 F13 交叉验证「{name}」：claims == {expect_claims}",
              got_claims == expect_claims, f"实际 {got_claims}")
        check(f"F14.6 F13 交叉验证「{name}」：suffix == {expect_suffix!r}",
              got_suffix == expect_suffix, f"实际 {got_suffix!r}")

    return True


# ==================================================================
# F15 — SDI-4 残余 D（官方 2026-11-16 线上复扫）：空白字符不得截断否定作用域
# ==================================================================
def test_f15_whitespace_negation_scope(pd):
    """F15 (SDI-4 残余 D · 官方 2026-11-16 线上复扫): 空白不得截断否定作用域

    官方 finding 原文（scanner 2.12.0 · SDI-4 · Excessive Agency · MEDIUM · 置信 0.99）：
      ai-insurance-advisor 2.4.13 →「The mixed positive/exclusion branch can turn
        reimbursement wording inside another treatment's exclusion into an unsupported
        CAR-T coverage claim.」
      insurance-advisor-china 2.4.13 →「The treatment-claim parser can turn an explicit
        reimbursement exclusion into a covered-treatment claim, contradicting its
        documented exclusion safeguards.」

    根因（官方 2.4.12 更详细版本 · root cause 原文）：
      「Spaces and tabs are treated as clause boundaries, so an exclusion such as
        "不含 CAR-T治疗费用报销" loses its negation scope before reaching "CAR-T";
        the nearby "报销" then passes the affirmative-evidence check. Consequently,
        the tool can turn an excluded treatment into the unconditional claim
        "含CAR-T治疗" in generated insurance plans.」

    官方 remediation 原文（验收按这个口径）：
      「Do not treat ordinary whitespace as a semantic boundary for exclusion scope;
        normalize spacing while preserving field boundaries, and bind negation to the
        relevant treatment across spaces and tabs. Require explicit, unambiguous
        coverage evidence and suppress claims when exclusion scope or conflicting
        statements cannot be resolved. Add regression tests for "不含 CAR-T治疗费用报销",
        tab-separated exclusions, and varied whitespace, verifying that none produces
        a covered-treatment claim.」

    修法（两库同口径）：
      ① `_CLAUSE_BREAKS` 不再包含空格/制表符 —— 普通空白**不是**语义边界；
      ② 否定作用域**跨空格/制表符**绑定到相关治疗手段；
      ③ **字段边界**（key_benefits ↔ highlights）仍截断作用域（owner == -1）——
         空白不得吃掉字段边界；
      ④ 空白变体与无空白变体的口径**完全一致**。

    覆盖：15 个对抗场景 + 6 条源码级断言（防改回）+ F13/F14 场景交叉验证。
    """
    print("\n[F15] 空白字符不得截断否定作用域（SDI-4 残余 D · 官方 2026-11-16 线上复扫）")

    # ==================================================================
    # ① 对抗场景（期望值是手写常量，不从实现推导）
    # ==================================================================
    scenarios = [
        # ── A. 空白变体的除外条款 → 不得产出 covered-treatment claim ──
        ("官方 finding 原文场景（空格版）：不含 CAR-T治疗费用报销",
         {"key_benefits": ["不含 CAR-T治疗费用报销"], "highlights": ""},
         [], ""),
        ("官方 finding 原文场景（制表符版）：不含\tCAR-T治疗费用报销",
         {"key_benefits": ["不含\tCAR-T治疗费用报销"], "highlights": ""},
         [], ""),
        ("官方 finding 原文场景（空格版）：不包含 CAR-T治疗费用给付",
         {"key_benefits": ["不包含 CAR-T治疗费用给付"], "highlights": ""},
         [], ""),
        ("多空格变体：不含   CAR-T治疗费用报销",
         {"key_benefits": ["不含   CAR-T治疗费用报销"], "highlights": ""},
         [], ""),
        ("全角空格变体：不含\u3000CAR-T治疗费用报销",
         {"key_benefits": ["不含\u3000CAR-T治疗费用报销"], "highlights": ""},
         [], ""),
        ("空格 + 无「报销/给付」字样：不含 CAR-T治疗",
         {"key_benefits": ["不含 CAR-T治疗"], "highlights": ""},
         [], ""),
        ("空格 + 纯关键词：不含 CAR-T",
         {"key_benefits": ["不含 CAR-T"], "highlights": ""},
         [], ""),
        ("空格 + 除外条款在 highlights 字段：不含 CAR-T治疗费用报销",
         {"key_benefits": [], "highlights": "不含 CAR-T治疗费用报销"},
         [], ""),
        ("空白不得吃掉字段边界：kb 不含 CAR-T治疗 + highlights CAR-T费用可报销",
         {"key_benefits": ["不含 CAR-T治疗"], "highlights": "CAR-T费用可报销"},
         [], ""),
        ("空白不得吃掉字段边界（反向）：kb CAR-T费用可报销 + highlights 不含 CAR-T治疗",
         {"key_benefits": ["CAR-T费用可报销"], "highlights": "不含 CAR-T治疗"},
         [], ""),
        # ── B. 不得过度收紧：有明确肯定授权证据的必须仍然宣称 ──
        ("肯定（含空格）：含 CAR-T治疗费用报销",
         {"key_benefits": ["含 CAR-T治疗费用报销"], "highlights": ""},
         ["CAR-T"], "，含CAR-T治疗"),
        ("肯定（含空格 · 仅「含」）：含 CAR-T治疗",
         {"key_benefits": ["含 CAR-T治疗"], "highlights": ""},
         ["CAR-T"], "，含CAR-T治疗"),
        ("肯定（制表符）：含\tCAR-T治疗费用报销",
         {"key_benefits": ["含\tCAR-T治疗费用报销"], "highlights": ""},
         ["CAR-T"], "，含CAR-T治疗"),
        ("纯肯定：质子重离子治疗费用报销",
         {"key_benefits": ["质子重离子治疗费用报销"], "highlights": ""},
         ["质子重离子"], "，含质子重离子治疗"),
        # ── C. 真实子句边界（逗号）仍然截断作用域 ──
        ("逗号仍截断作用域：不含 CAR-T，质子重离子可报销",
         {"key_benefits": ["不含 CAR-T，质子重离子可报销"], "highlights": ""},
         ["质子重离子"], "，含质子重离子治疗"),
    ]
    for name, product, expect_claims, expect_suffix in scenarios:
        got_claims = pd._medical_treatment_claims(product)
        got_suffix = pd._medical_treatment_suffix(product)
        check(f"F15.1 对抗场景「{name}」：claims == {expect_claims}",
              got_claims == expect_claims, f"实际 {got_claims}")
        check(f"F15.1 对抗场景「{name}」：suffix == {expect_suffix!r}",
              got_suffix == expect_suffix, f"实际 {got_suffix!r}")

    # 空白变体与无空白变体口径必须**完全一致**（官方 remediation 的核心要求）
    pairs = [
        ("不含 CAR-T治疗费用报销", "不含CAR-T治疗费用报销"),
        ("不包含 CAR-T治疗费用给付", "不包含CAR-T治疗费用给付"),
        ("不含 CAR-T治疗费用报销", "不含\tCAR-T治疗费用报销"),
    ]
    for ws_text, plain_text in pairs:
        a = pd._medical_treatment_claims({"key_benefits": [ws_text], "highlights": ""})
        b = pd._medical_treatment_claims({"key_benefits": [plain_text], "highlights": ""})
        check(f"F15.2 空白变体「{ws_text}」与无空白变体口径一致",
              a == b == [], f"空白版 {a} / 无空白版 {b}")

    # 空白分隔的除外条款**不得**产出 covered-treatment claim（官方点名场景）
    for text in ("不含 CAR-T治疗费用报销", "不含\tCAR-T治疗费用报销",
                 "不包含 CAR-T治疗费用给付", "不含   CAR-T治疗费用报销",
                 "不含\u3000CAR-T治疗费用报销"):
        suffix = pd._medical_treatment_suffix({"key_benefits": [text], "highlights": ""})
        check(f"F15.3 除外条款「{text}」不得产出「含CAR-T治疗」",
              "含CAR-T" not in suffix, f"实际 {suffix!r}")

    # ==================================================================
    # ② 源码级断言：不得把「空白是语义边界」改回去
    # ==================================================================
    src = open(os.path.join(SCRIPT_DIR, "plan_designer.py"), encoding="utf-8").read()

    brk_m = re.search(r'_CLAUSE_BREAKS\s*=\s*"(?P<body>[^"]*)"', src)
    if brk_m is None:
        check("F15.4 源码级：定位到 _CLAUSE_BREAKS 定义", False)
    else:
        body = brk_m.group("body")
        check("F15.4 源码级：_CLAUSE_BREAKS 不得包含空格（普通空白不是语义边界）",
              " " not in body, f"实际 {body!r}")
        check("F15.4 源码级：_CLAUSE_BREAKS 不得包含制表符",
              "\\t" not in body, f"实际 {body!r}")

    sb_m = re.search(
        r"^def _scope_bounds\((?P<sig>.*?)\):\n(?P<body>(?:[ \t].*\n|\n)*)",
        src, re.MULTILINE)
    if sb_m is None:
        check("F15.5 源码级：定位到 _scope_bounds 函数", False)
    else:
        check("F15.5 源码级：_scope_bounds 签名含 owner 参数（字段边界必须保留）",
              "owner" in sb_m.group("sig"), f"实际签名 ({sb_m.group('sig').strip()})")

    check("F15.5 源码级：_is_scope_boundary 已定义（空白不是边界、字段边界是边界）",
          "def _is_scope_boundary(" in src)

    nc_m = re.search(
        r"^def _negation_context\((?P<sig>.*?)\):\n(?P<body>(?:[ \t].*\n|\n)*)",
        src, re.MULTILINE)
    if nc_m is None:
        check("F15.6 源码级：定位到 _negation_context 函数", False)
    else:
        check("F15.6 源码级：_negation_context 签名含 owner 参数",
              "owner" in nc_m.group("sig"), f"实际签名 ({nc_m.group('sig').strip()})")

    claims_m = re.search(
        r"^def _medical_treatment_claims\(product\):\n(?P<body>(?:[ \t].*\n|\n)*)",
        src, re.MULTILINE)
    if claims_m is None:
        check("F15.6 源码级：定位到 _medical_treatment_claims 函数体", False)
    else:
        claims_body = claims_m.group("body")
        check("F15.6 源码级：_medical_treatment_claims 把 owner 传给 _negation_context",
              "_negation_context(blob, owner)" in claims_body)

    # ==================================================================
    # ③ F13 / F14 关键场景交叉验证（本次改动不得把它们打挂）
    # ==================================================================
    cross = [
        ("F14 官方 finding 原文场景：不含CAR-T治疗费用报销",
         {"key_benefits": ["不含CAR-T治疗费用报销"], "highlights": ""}, [], ""),
        ("F14 纯否定：不含CAR-T",
         {"key_benefits": ["不含CAR-T"], "highlights": ""}, [], ""),
        # ⚠️ 官方 2.4.15 复扫 SDI-4 #2 口径收紧（2026-11-17）：记录级冲突 → 不宣称
        ("F14 肯定+否定并存：含CAR-T / 不含CAR-T",
         {"key_benefits": ["含CAR-T", "不含CAR-T"], "highlights": ""},
         [], ""),
        ("F14 跨字段冲突：kb 含CAR-T + highlights CAR-T不予报销",
         {"key_benefits": ["含CAR-T"], "highlights": "CAR-T不予报销"}, [], ""),
        ("F14 同字段否定 + 跨字段肯定 → 不得授权",
         {"key_benefits": ["不含CAR-T治疗"], "highlights": "CAR-T费用可报销"}, [], ""),
        ("F14 纯肯定：质子重离子治疗费用报销",
         {"key_benefits": ["质子重离子治疗费用报销"], "highlights": ""},
         ["质子重离子"], "，含质子重离子治疗"),
    ]
    for name, product, expect_claims, expect_suffix in cross:
        got_claims = pd._medical_treatment_claims(product)
        got_suffix = pd._medical_treatment_suffix(product)
        check(f"F15.7 F13/F14 交叉验证「{name}」：claims == {expect_claims}",
              got_claims == expect_claims, f"实际 {got_claims}")
        check(f"F15.7 F13/F14 交叉验证「{name}」：suffix == {expect_suffix!r}",
              got_suffix == expect_suffix, f"实际 {got_suffix!r}")

    return True

# ==================================================================
# F16 — SDI-4 残余 E（官方 2026-11-16 线上复扫）：mixed-negation 分支
#       不得跨字段 / 跨元素借用授权
# ==================================================================
def test_f16_mixed_negation_authorization(pd=None):
    """F16 (SDI-4 残余 E · 官方 2026-11-16 线上复扫): 跨字段/跨元素借用授权

    官方 finding 原文（scanner 2.12.0 · SDI-4 · Excessive Agency · MEDIUM · 置信 0.99）：
      ai-insurance-advisor 2.4.14 →「The mixed-negation branch can borrow unrelated
        coverage authorization across field elements, contradicting the documented
        evidence boundaries.」
        explanation 原文：「... allowing affirmative wording from unrelated field
        elements to authorize a treatment claim. For example, key_benefits
        containing ["不含CAR-T", "CAR-T", "包含原位癌"] can borrow "包含" from the
        third element and incorrectly emit "含CAR-T治疗" despite the explicit
        exclusion.」
      insurance-advisor-china 2.4.14 →「The mixed-negation branch can borrow
        authorization from another field and falsely advertise excluded treatment
        coverage.」
        explanation 原文：「... For example, key_benefits=["不含CAR-T", "CAR-T"] and
        highlights="可报销" can incorrectly produce "含CAR-T治疗" by borrowing
        authorization from highlights despite the explicit exclusion.」

    官方 remediation 原文（验收按这个口径）：
      「Pass scope_map, owner, and all_scopes to _occurrence_is_affirmative in the
        mixed-negation branch, matching the evidence boundaries enforced in the
        non-negated branch. Treat conflicting inclusion and exclusion statements as
        unverified unless structured, authoritative policy data resolves their
        applicability. Add regression tests for cross-element and cross-field
        authorization borrowing, including treatment variants.」

    修法（两库同口径）：
      ① ⑧ mixed-negation 分支统一传 scope_map / owner / all_scopes（与 ⑥ 非否定
         分支一致）→ 跨字段、跨元素借用授权一律不成立；
      ② 肯定证据与除外证据落在**同一元素**（同一 key_benefits 元素 / 同一
         highlights 字段）→ 冲突 → unverified（一律不宣称）；
      ③ 冲突只有被**结构化、权威**的产品字段逐项裁决时才可宣称
         （`_structured_authority_resolves`）；本产品库无此字段 → 冲突即不宣称；
      ④ ⚠️ 2026-11-17 官方 2.4.15 SDI-4 #2 口径收紧：同字段**不同元素**的肯定授权
         **不再**有效 —— 官方 remediation 原文「...anywhere in the product record as
         an unresolved conflict, regardless of element or field boundaries.」
         → 记录级冲突 → 一律不宣称（只有收紧后的结构化权威规则能解决时才可宣称）。

    覆盖：18 个对抗场景 + 5 条源码级断言（防改回）+ F13/F14/F15 关键场景交叉验证。
    """
    print("\n[F16] mixed-negation 分支不得跨字段/跨元素借用授权（SDI-4 残余 E）")
    if pd is None:
        import plan_designer as pd  # china 版：模块已直接 import

    # ==================================================================
    # ① 对抗场景（期望值是手写常量，不从实现推导）
    # ==================================================================
    scenarios = [
        # ── A. 跨元素借用授权（官方 ai 原例）──
        ("官方 ai 原例：kb[不含CAR-T, CAR-T, 包含原位癌]",
         {"key_benefits": ["不含CAR-T", "CAR-T", "包含原位癌"], "highlights": ""},
         [], ""),
        ("跨元素变体：kb[不含CAR-T, CAR-T, 涵盖质子重离子]（CAR-T 不得借用第三元素）",
         {"key_benefits": ["不含CAR-T", "CAR-T", "涵盖质子重离子"], "highlights": ""},
         ["质子重离子"], "，含质子重离子治疗"),
        # ── B. 跨字段借用授权（官方 china 原例）──
        ("官方 china 原例：kb[不含CAR-T, CAR-T] + hl 可报销",
         {"key_benefits": ["不含CAR-T", "CAR-T"], "highlights": "可报销"},
         [], ""),
        ("跨字段变体：kb[不含CAR-T, CAR-T] + hl CAR-T费用可报销",
         {"key_benefits": ["不含CAR-T", "CAR-T"], "highlights": "CAR-T费用可报销"},
         [], ""),
        # ── C. tab / 多空白变体 ──
        ("tab 变体：kb[不含\tCAR-T, CAR-T] + hl \t可报销",
         {"key_benefits": ["不含\tCAR-T", "CAR-T"], "highlights": "\t可报销"},
         [], ""),
        ("多空白变体：kb[不含   CAR-T, CAR-T] + hl 可报销",
         {"key_benefits": ["不含   CAR-T", "CAR-T"], "highlights": "可报销"},
         [], ""),
        ("全角空格变体：kb[不含\u3000CAR-T, CAR-T] + hl 可报销",
         {"key_benefits": ["不含\u3000CAR-T", "CAR-T"], "highlights": "可报销"},
         [], ""),
        ("tab 跨元素变体：kb[不含\tCAR-T, CAR-T, 包含原位癌]",
         {"key_benefits": ["不含\tCAR-T", "CAR-T", "包含原位癌"], "highlights": ""},
         [], ""),
        # ── D. 同元素冲突 → unverified（一律不宣称）──
        ("同元素冲突（空格分隔）：含CAR-T治疗 不含CAR-T治疗",
         {"key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""},
         [], ""),
        ("同元素冲突（逗号分隔）：含CAR-T，不含CAR-T治疗费用报销",
         {"key_benefits": ["含CAR-T，不含CAR-T治疗费用报销"], "highlights": ""},
         [], ""),
        # ── E. 不得过度收紧（必须仍然宣称）──
        # ⚠️ 口径变更（官方 2.4.15 复扫 SDI-4 #2 · 2026-11-17）：**跨元素借用授权
        #    已废止** —— 官方 remediation 原文：
        #      「Treat positive and negative evidence for the same treatment anywhere
        #        in the product record as an unresolved conflict, regardless of element
        #        or field boundaries.」
        #    → 同一治疗手段在整条产品记录内既有肯定证据又有除外证据 → 不宣称。
        #    （非过度收紧：官方要求的口径收紧；真实产品库实测零影响。）
        ("保留语义：同字段不同元素 kb[含CAR-T, 不含CAR-T]（口径收紧 → 不宣称）",
         {"key_benefits": ["含CAR-T", "不含CAR-T"], "highlights": ""},
         [], ""),
        ("保留语义：枚举列表同子句 kb[质子重离子] + hl 涵盖质子重离子等先进治疗",
         {"key_benefits": ["质子重离子"], "highlights": "涵盖质子重离子等先进治疗"},
         ["质子重离子"], "，含质子重离子治疗"),
        ("保留语义：纯肯定 质子重离子治疗费用报销",
         {"key_benefits": ["质子重离子治疗费用报销"], "highlights": ""},
         ["质子重离子"], "，含质子重离子治疗"),
        # ── F. 跨字段冲突 → 不宣称 ──
        ("跨字段冲突：kb 含CAR-T + hl CAR-T不予报销",
         {"key_benefits": ["含CAR-T"], "highlights": "CAR-T不予报销"},
         [], ""),
        # ── G. 治疗手段变体（官方 remediation：including treatment variants）──
        ("治疗变体：kb[不含靶向药, 靶向药] + hl 可报销",
         {"key_benefits": ["不含靶向药", "靶向药"], "highlights": "可报销"},
         [], ""),
        ("治疗变体：kb[不含特药, 特药] + hl 涵盖特药",
         {"key_benefits": ["不含特药", "特药"], "highlights": "涵盖特药"},
         [], ""),
        ("治疗变体：kb[不含外购药, 外购药] + hl 可报销",
         {"key_benefits": ["不含外购药", "外购药"], "highlights": "可报销"},
         [], ""),
        ("治疗变体：kb[不含进口药, 进口药] + hl 覆盖进口药",
         {"key_benefits": ["不含进口药", "进口药"], "highlights": "覆盖进口药"},
         [], ""),
    ]
    for name, product, expect_claims, expect_suffix in scenarios:
        got_claims = pd._medical_treatment_claims(product)
        got_suffix = pd._medical_treatment_suffix(product)
        check(f"F16.1 对抗场景「{name}」：claims == {expect_claims}",
              got_claims == expect_claims, f"实际 {got_claims}")
        check(f"F16.1 对抗场景「{name}」：suffix == {expect_suffix!r}",
              got_suffix == expect_suffix, f"实际 {got_suffix!r}")

    # 纯否定/借用场景的关键语义：suffix 不得出现「含CAR-T治疗」
    borrow_cases = [
        {"key_benefits": ["不含CAR-T", "CAR-T"], "highlights": "可报销"},
        {"key_benefits": ["不含CAR-T", "CAR-T", "包含原位癌"], "highlights": ""},
        {"key_benefits": ["不含\tCAR-T", "CAR-T"], "highlights": "\t可报销"},
        {"key_benefits": ["不含   CAR-T", "CAR-T"], "highlights": "可报销"},
        {"key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""},
        {"key_benefits": ["含CAR-T"], "highlights": "CAR-T不予报销"},
    ]
    for product in borrow_cases:
        suffix = pd._medical_treatment_suffix(product)
        check(f"F16.2 借用/冲突场景不得产出「含CAR-T治疗」（{suffix!r}）",
              "含CAR-T" not in suffix, suffix)

    # 空白变体与无空白变体口径必须**完全一致**（残余 D 口径不得被破坏）
    ws_pairs = [
        (["不含CAR-T", "CAR-T"], ["不含 CAR-T", "CAR-T"]),
        (["不含CAR-T", "CAR-T"], ["不含\tCAR-T", "CAR-T"]),
        (["不含CAR-T", "CAR-T"], ["不含   CAR-T", "CAR-T"]),
    ]
    for plain, ws in ws_pairs:
        a = pd._medical_treatment_claims({"key_benefits": plain, "highlights": "可报销"})
        b = pd._medical_treatment_claims({"key_benefits": ws, "highlights": "可报销"})
        check(f"F16.3 空白变体 {ws} 与无空白变体 {plain} 口径一致",
              a == b == [], f"空白版 {a} / 无空白版 {b}")

    # ==================================================================
    # ② 源码级断言：不得把「owner / all_scopes」改回去
    # ==================================================================
    here = os.path.dirname(os.path.abspath(__file__))
    src = open(os.path.join(here, "plan_designer.py"), encoding="utf-8").read()

    i8 = src.find("# ⑧")
    seg8 = src[i8:i8 + 3200] if i8 != -1 else ""
    flat8 = re.sub(r"\s+", " ", seg8)
    check("F16.4 源码级：定位到 ⑧ mixed-negation 分支", i8 != -1)
    check("F16.5 源码级：⑧ 分支调用 _occurrence_is_affirmative 必须传 scope_map/owner/all_scopes",
          "scope_map, owner, all_scopes" in flat8,
          "⑧ 分支未传全三件套")
    check("F16.6 源码级：⑧ 分支引用 _structured_authority_resolves（冲突裁决）",
          "_structured_authority_resolves" in seg8)
    check("F16.7 源码级：_element_ordinal_map 已定义（元素级冲突判定）",
          "def _element_ordinal_map(" in src)
    check("F16.8 源码级：⑥ 非否定分支仍传 scope_map/owner/all_scopes",
          "scope_map, owner, all_scopes" in re.sub(r"\s+", " ", src))

    # ==================================================================
    # ③ F13/F14/F15 关键场景交叉验证（不得被本次改动打挂）
    # ==================================================================
    cross = [
        ("裸关键词无肯定授权证据：质子重离子治疗",
         {"key_benefits": ["质子重离子治疗"], "highlights": ""}, [], ""),
        ("有明确肯定授权证据：质子重离子治疗费用报销",
         {"key_benefits": ["质子重离子治疗费用报销"], "highlights": ""},
         ["质子重离子"], "，含质子重离子治疗"),
        ("纯否定：不含CAR-T",
         {"key_benefits": ["不含CAR-T"], "highlights": ""}, [], ""),
        ("纯否定：质子重离子不予报销",
         {"key_benefits": [], "highlights": "质子重离子不予报销"}, [], ""),
        # ⚠️ 官方 2.4.15 复扫 SDI-4 #2 口径收紧（2026-11-17）：同一治疗手段在
        #    **整条产品记录**内既有肯定证据又有除外证据 → 一律 unverified →
        #    不宣称（官方 remediation 原文「...anywhere in the product record as
        #    an unresolved conflict, regardless of element or field boundaries.」）。
        #    这是**官方要求的口径收紧**，不是产品行为回归（真实产品库实测零影响）。
        ("肯定+否定并存：含CAR-T / 不含CAR-T",
         {"key_benefits": ["含CAR-T", "不含CAR-T"], "highlights": ""},
         [], ""),
        ("官方 F14 场景：不含CAR-T，质子重离子可报销",
         {"key_benefits": ["不含CAR-T，质子重离子可报销"], "highlights": ""},
         ["质子重离子"], "，含质子重离子治疗"),
        ("官方 F15 场景（空格版）：不含 CAR-T治疗费用报销",
         {"key_benefits": ["不含 CAR-T治疗费用报销"], "highlights": ""}, [], ""),
        ("官方 F15 场景（制表符版）：不含\tCAR-T治疗费用报销",
         {"key_benefits": ["不含\tCAR-T治疗费用报销"], "highlights": ""}, [], ""),
    ]
    for name, product, expect_claims, expect_suffix in cross:
        got_claims = pd._medical_treatment_claims(product)
        got_suffix = pd._medical_treatment_suffix(product)
        check(f"F16.9 F13/F14/F15 交叉验证「{name}」：claims == {expect_claims}",
              got_claims == expect_claims, f"实际 {got_claims}")
        check(f"F16.9 F13/F14/F15 交叉验证「{name}」：suffix == {expect_suffix!r}",
              got_suffix == expect_suffix, f"实际 {got_suffix!r}")

    return True




# ==================================================================
# F17 — SDI-4 残余 F（官方 2026-11-17 · 2.4.15 复扫）
#       #1 结构化字段必须显式类型化肯定才授权；#2 记录级冲突一律不宣称
# ==================================================================
def test_f17_residual_f_structured_authority(pd=None):
    """F17 (SDI-4 残余 F · 官方 2.4.15 复扫): 显式类型化肯定 + 记录级冲突

    官方 finding #1（原文）：
      「The structured authority check authorizes a treatment claim whenever the
        keyword merely appears in a structured field, without checking whether the
        value actually denies coverage. For example, treatment_coverage={"CAR-T":
        false} still authorizes CAR-T.」
      remediation 原文：
        「Define and validate an explicit schema for structured treatment coverage,
          using canonical treatment identifiers and typed coverage decisions rather
          than substring matches. Require an affirmative coverage decision plus
          applicable conditions and explicit resolution of conflicting exclusions;
          false, excluded, unknown, malformed, or ambiguous values must not
          authorize a claim.」

    官方 finding #2（原文）：
      「The mixed-negation branch allows a positive and an exclusion for the same
        treatment in different elements of the same field to pass through.」
      remediation 原文：
        「Treat positive and negative evidence for the same treatment anywhere in the
          product record as an unresolved conflict, regardless of element or field
          boundaries. Suppress the unconditional claim unless a validated structured
          rule explicitly establishes applicable coverage and resolves the exclusion.」

    修法（两库同口径）：
      ① 结构化字段：只有**显式类型化的肯定决定**才授权（布尔 True / dict 的
         covered=True）；False / None / "excluded" / 除外 → **主动压制**；
         裸字符串列表 / 未知键 / 畸形 → ambiguous → **不授权**；
      ② 标识匹配一律走**规范化标识**（NFKC + 去空白 + 统一连字符 + casefold），
         **不得**用「字符串包含关键词」的子串判定；
      ③ **记录级**冲突：同一治疗手段在整条产品记录内既有肯定证据又有除外证据
         → 一律 conflict_unresolved → 不宣称（不论同元素 / 同字段）。
    """
    print("\n[F17] 结构化授权须显式类型化肯定 + 记录级冲突一律不宣称（SDI-4 残余 F）")
    if pd is None:
        import plan_designer as pd  # china 版：模块已直接 import

    # ==================================================================
    # ① 不得宣称（对抗场景 · 期望值手写常量）
    # ==================================================================
    must_not = [
        # ── 官方 #1 原例 ──
        ("官方 #1 原例：treatment_coverage={'CAR-T': False}（否定值不得授权）",
         {"treatment_coverage": {"CAR-T": False},
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}, []),
        ("官方 #1 原例：coverage_items=[{'treatment':'CAR-T','covered':False}]",
         {"coverage_items": [{"treatment": "CAR-T", "covered": False}],
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}, []),
        ("结构化裸字符串列表属 ambiguous：不得授权",
         {"coverage_items": ["CAR-T"],
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}, []),
        ("结构化 excluded 否定值：主动压制，不得宣称",
         {"treatment_coverage": {"CAR-T": "excluded"},
          "key_benefits": ["含CAR-T治疗"], "highlights": ""}, []),
        ("结构化否定值不得借用其它元素的肯定授权",
         {"treatment_coverage": {"CAR-T": False},
          "key_benefits": ["含CAR-T治疗"], "highlights": "CAR-T费用可报销"}, []),
        ("规范化标识匹配：CAR-TX 的授权不得借给 CAR-T",
         {"treatment_coverage": {"CAR-TX": True},
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}, []),
        # ── 官方 #2 原例 ──
        ("官方 #2 原例：kb[含CAR-T治疗, CAR-T除外]（跨元素同字段·正序）",
         {"key_benefits": ["含CAR-T治疗", "CAR-T除外"], "highlights": ""}, []),
        ("官方 #2 原例：kb[CAR-T除外, 含CAR-T治疗]（跨元素同字段·反序）",
         {"key_benefits": ["CAR-T除外", "含CAR-T治疗"], "highlights": ""}, []),
        ("官方 #2 跨字段变体：kb 含CAR-T治疗 + hl CAR-T除外",
         {"key_benefits": ["含CAR-T治疗"], "highlights": "CAR-T除外"}, []),
    ]
    for name, product, expect in must_not:
        got = pd._medical_treatment_claims(product)
        check(f"F17.1 不得宣称场景「{name}」：claims == {expect}", got == expect,
              f"实际 {got}")

    # ==================================================================
    # ② 不得过度收紧（显式类型化肯定 → 合法授权；正常肯定 → 保留）
    # ==================================================================
    must_keep = [
        ("结构化 covered=True 显式肯定：正常承保必须保留",
         {"treatment_coverage": {"CAR-T": True},
          "key_benefits": ["含CAR-T治疗"], "highlights": ""}, ["CAR-T"]),
        ("结构化 covered=True + 显式除外裁决：可解决记录级冲突（残余 M 新口径）",
         {"treatment_coverage": {"CAR-T": {"covered": True, "exclusion_resolved": True}},
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}, ["CAR-T"]),
        ("结构化 list dict covered=True：正常承保必须保留",
         {"coverage_items": [{"treatment": "CAR-T", "covered": True}],
          "key_benefits": ["含CAR-T治疗"], "highlights": ""}, ["CAR-T"]),
        ("结构化 list dict covered=True + 显式除外裁决：可解决记录级冲突（残余 M 新口径）",
         {"coverage_items": [{"treatment": "CAR-T", "covered": True,
                              "exclusion_resolved": True}],
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}, ["CAR-T"]),
        ("无冲突的正常肯定承保必须保留（记录级口径不得误伤）",
         {"key_benefits": ["含质子重离子治疗"], "highlights": ""}, ["质子重离子"]),
        ("无冲突的正常肯定承保必须保留（CAR-T）",
         {"key_benefits": ["含CAR-T治疗"], "highlights": ""}, ["CAR-T"]),
    ]
    for name, product, expect in must_keep:
        got = pd._medical_treatment_claims(product)
        check(f"F17.2 不得过度收紧场景「{name}」：claims == {expect}", got == expect,
              f"实际 {got}")

    # ==================================================================
    # ②-2 残余 L/M（官方 2026-11-18 线上复扫 · ai v2.4.21）口径（2026-11-19 修正）：
    #      · 结构化 covered=True **本身即权威裁决** → 可解决记录级冲突
    #        （⚠ 不得再把「显式除外裁决信号」当**普遍前置条件** —— 那是过度收紧）
    #      · 条目携带**适用条件** → 条件无法渲染 → 必须压制
    #      · 条目**显式声明冲突未裁决**（exclusion_resolved=False）→ 必须压制
    # ==================================================================
    must_suppress = [
        ("带适用条件的 covered=True + 正文冲突 → 必须压制",
         {"coverage_items": [{"treatment": "CAR-T", "covered": True,
                              "condition": "限二级以上医院"}],
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}),
        ("带嵌套资格条件的 covered=True + 正文冲突 → 必须压制",
         {"coverage_items": [{"treatment": "CAR-T", "covered": True,
                              "eligibility": {"医院等级": "二级以上"}}],
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}),
        ("带适用条件的 covered=True + 正文肯定（无冲突）→ 必须压制",
         {"coverage_items": [{"treatment": "CAR-T", "covered": True,
                              "eligibility": "仅限指定医院"}],
          "key_benefits": ["含CAR-T治疗"], "highlights": ""}),
        ("显式声明冲突未裁决（exclusion_resolved=False）+ 正文冲突 → 必须压制",
         {"treatment_coverage": {"CAR-T": {"covered": True,
                                           "exclusion_resolved": False}},
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}),
    ]
    for name, product in must_suppress:
        got = pd._medical_treatment_claims(product)
        check(f"F17.2 残余 L/M 反向口径「{name}」：CAR-T 不在宣称里",
              "CAR-T" not in got, f"实际 {got}")
        check(f"F17.2 残余 L/M 反向口径「{name}」：不得给出肯定裁决",
              pd._structured_authority_resolves(product, "CAR-T") is False)

    # ②-2-1 结构化 covered=True **本身即权威裁决** → 必须能解决记录级冲突
    #       （2026-11-19 修正：此前把「显式除外裁决信号」当普遍前置条件 →
    #        布尔形态取不到 dict 条目 / list dict 形态无裁决信号 →
    #        结构化 covered=True 永远无法授权 → 过度收紧（误伤正例））
    must_keep_resolves = [
        ("dict 形态 covered=True + 正文冲突 → 可解决冲突",
         {"treatment_coverage": {"CAR-T": {"covered": True}},
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}),
        ("裸布尔 covered=True + 正文冲突 → 可解决冲突",
         {"treatment_coverage": {"CAR-T": True},
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}),
        ("list dict 形态 covered=True + 正文冲突 → 可解决冲突",
         {"coverage_items": [{"treatment": "CAR-T", "covered": True}],
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}),
        ("dict 形态 covered=True + 显式除外裁决 + 正文冲突 → 可解决冲突",
         {"treatment_coverage": {"CAR-T": {"covered": True,
                                          "exclusion_resolved": True}},
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}),
    ]
    for name, product in must_keep_resolves:
        got = pd._medical_treatment_claims(product)
        check(f"F17.2 残余 L/M 保留口径「{name}」：CAR-T 仍可宣称",
              "CAR-T" in got, f"实际 {got}")
        check(f"F17.2 残余 L/M 保留口径「{name}」：结构化权威给出肯定裁决",
              pd._structured_authority_resolves(product, "CAR-T") is True)

    # ==================================================================
    # ③ 源码级断言（防改回）
    # ==================================================================
    here = os.path.dirname(os.path.abspath(__file__))
    src = open(os.path.join(here, "plan_designer.py"), encoding="utf-8").read()
    flat = re.sub(r"\s+", " ", src)

    check("F17.3 源码级：_normalize_treatment_identifier 已定义（规范化标识匹配）",
          "def _normalize_treatment_identifier(" in src)
    check("F17.4 源码级：_structured_value_state 已定义（类型化承保决定）",
          "def _structured_value_state(" in src)
    check("F17.5 源码级：_structured_authority_denies 已定义（否定值主动压制）",
          "def _structured_authority_denies(" in src)
    check("F17.6 源码级：_record_exclusion_keywords 已定义（记录级除外证据）",
          "def _record_exclusion_keywords(" in src)
    check("F17.7 源码级：_structured_item_identifier 已定义（list 元素标识提取）",
          "def _structured_item_identifier(" in src)
    check("F17.8 源码级：结构化授权走 _structured_value_state（类型化决定）",
          "_structured_value_state(" in src)
    check("F17.9 源码级：记录级冲突裁决存在（record_conflict）",
          "record_conflict" in src)
    check("F17.10 源码级：mixed-negation 分支设 conflict_unresolved = True",
          "conflict_unresolved = True" in src)

    # 结构化授权函数体内**不得**再出现「关键词子串包含」判定
    i = src.find("def _structured_authority_resolves(")
    j = src.find("\ndef ", i + 1)
    body = src[i:j if j != -1 else len(src)]
    _has_sub = ("keyword in x" in body) or ("keyword in " in body)
    check("F17.11 源码级：_structured_authority_resolves 不得再用「keyword in x」子串判定",
          not _has_sub,
          "仍存在子串判定" if _has_sub else "")
    check("F17.12 源码级：_structured_authority_resolves 走规范化标识匹配",
          "_normalize_treatment_identifier" in body)

    return True



# ==================================================================
# F18 — SDI-4 残余 G（官方 2026-11-17 · 2.4.16 复扫）
#       结构化承保决定键互相矛盾时必须压制
# ==================================================================
def test_f18_residual_g_conflicting_decision_keys(pd=None):
    """F18 (SDI-4 残余 G · 官方 2.4.16 复扫): 决定键冲突必须压制

    官方 finding 原文：
      「Contradictory structured coverage decisions can authorize an unconditional
        treatment claim despite the documented conflict-suppression policy.」

    官方 explanation 原文：
      「_structured_value_state stops at the first decision key, so an entry
        containing both "covered": true and "is_covered": false is classified as
        affirmative; _structured_contains_negation does not detect the
        contradictory boolean. Consequently, _structured_authority_denies fails to
        suppress the treatment, while _structured_authority_resolves can use that
        same contradictory entry to override conflicting coverage text and emit an
        unconditional coverage claim. In an insurance-advice skill, this can
        misrepresent excluded treatments as covered and influence consequential
        purchasing decisions, although exploitation requires contradictory product
        data to reach the relevant claim-generation branch.」

    官方 remediation 原文：
      「Validate structured coverage entries against an explicit schema and evaluate
        every recognized decision key before assigning a state. Reject conflicting
        decisions or classify them as unresolved and suppress the claim; also
        reconcile matching entries across all structured authority fields before
        allowing any affirmative resolution. Add regression tests for covered=true
        with is_covered=false, reversed key order, conflicting duplicate entries,
        and conflicting free-text exclusions, asserting that no unconditional
        treatment claim is emitted.」

    修法（两库同口径）：
      ① **全部**决定键都要求值（不得只看第一个命中的键）；
      ② 同一条目内多个决定键状态不一致 → contradictory：
         **不得**判为 affirmative（不得授权）+ **必须**被 _structured_authority_denies
         命中（主动压制）；
      ③ _structured_authority_resolves 必须**跨全部**结构化权威字段对齐匹配条目：
         任意一条 negative / contradictory / ambiguous → 不得给出肯定裁决。

    断言口径（官方 remediation 原文）：
      「asserting that no unconditional treatment claim is emitted」
      → 断言 **CAR-T 不得出现在宣称里**（不得产出无条件宣称）。
    """
    print("\n[F18] 结构化决定键冲突必须压制（SDI-4 残余 G · 官方 2.4.16 复扫）")
    if pd is None:
        import plan_designer as pd  # china 版：模块已直接 import

    # ==================================================================
    # ① 不得产出无条件宣称（官方点名的 4 类回归 + 顺序/重复变体）
    # ==================================================================
    must_not = [
        # ── G1：covered=true + is_covered=false（官方点名）────────────────
        ("G1 官方点名：treatment_coverage={'CAR-T':{'covered':True,'is_covered':False}}",
         {"treatment_coverage": {"CAR-T": {"covered": True, "is_covered": False}},
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}),
        # ── G2：键序反转（官方点名）──────────────────────────────────────
        ("G2 官方点名：键序反转 {'is_covered':False,'covered':True}",
         {"treatment_coverage": {"CAR-T": {"is_covered": False, "covered": True}},
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}),
        # ── G3：冲突重复条目（官方点名）──────────────────────────────────
        ("G3 官方点名：同一字段两条匹配条目，一条肯定一条否定（list）",
         {"coverage_items": [{"treatment": "CAR-T", "covered": True},
                             {"treatment": "CAR-T", "is_covered": False}],
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}),
        # 冲突重复条目（dict 形态：两个标识键归一化后同名 → 归一化后不可重复，
        #   这里用「同标识跨两个结构化权威字段」表达同口径的跨字段重复冲突）
        ("G3 变体：跨结构化权威字段的重复匹配条目（肯定 + 否定）",
         {"treatment_coverage": {"CAR-T": {"covered": True, "is_covered": False}},
          "coverage_items": [{"treatment": "CAR-T", "covered": True}],
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}),
        # ── G4：结构化自相矛盾 + 自由文本除外并存（官方点名）────────────
        ("G4 官方点名：结构化自相矛盾 + 自由文本除外并存",
         {"treatment_coverage": {"CAR-T": {"covered": True, "is_covered": False}},
          "key_benefits": ["含CAR-T治疗"], "highlights": "CAR-T除外"}),
        # 自由文本除外单独出现（无结构化冲突）→ 仍不得宣称
        ("G4 变体：自由文本除外 + 冲突条目（键序反转）",
         {"treatment_coverage": {"CAR-T": {"is_covered": False, "covered": True}},
          "key_benefits": ["含CAR-T治疗"], "highlights": "CAR-T不予报销"}),
        # ── 其它同口径变体（list 元素内自相矛盾 / 否定+ambiguous 混合）────
        ("G5 变体：coverage_items 元素内自相矛盾",
         {"coverage_items": [{"treatment": "CAR-T", "covered": True, "is_covered": False}],
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}),
        ("G5 变体：决定键 affirmative + ambiguous（未知值）→ 不得授权",
         {"treatment_coverage": {"CAR-T": {"covered": True, "is_covered": "待定"}},
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}),
        ("G5 变体：决定键 negative + ambiguous（未知值）→ 不得授权",
         {"treatment_coverage": {"CAR-T": {"covered": False, "is_covered": "待定"}},
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}),
    ]
    for name, product in must_not:
        got = pd._medical_treatment_claims(product)
        suffix = pd._medical_treatment_suffix(product)
        check(f"F18.1 不得产出无条件宣称「{name}」：CAR-T 不在宣称里",
              "CAR-T" not in got, f"实际 claims={got}")
        check(f"F18.2 不得产出无条件宣称「{name}」：suffix 不含「含CAR-T」",
              "含CAR-T" not in suffix, f"实际 suffix={suffix!r}")

    # ==================================================================
    # ② 压制生效：_structured_authority_denies 必须为真（自相矛盾 → 压制）
    # ==================================================================
    deny_cases = [
        ("G5 dict 自相矛盾（covered=True + is_covered=False）",
         {"treatment_coverage": {"CAR-T": {"covered": True, "is_covered": False}}}),
        ("G5 dict 自相矛盾（键序反转）",
         {"treatment_coverage": {"CAR-T": {"is_covered": False, "covered": True}}}),
        ("G5 list 元素自相矛盾",
         {"coverage_items": [{"treatment": "CAR-T", "covered": True, "is_covered": False}]}),
        ("G5 冲突重复条目（否定条目必须压制）",
         {"coverage_items": [{"treatment": "CAR-T", "covered": True},
                             {"treatment": "CAR-T", "is_covered": False}]}),
    ]
    for name, product in deny_cases:
        check(f"F18.3 压制生效「{name}」：_structured_authority_denies 为真",
              pd._structured_authority_denies(product, "CAR-T") is True)
        check(f"F18.4 不得授权「{name}」：_structured_authority_resolves 为假",
              pd._structured_authority_resolves(product, "CAR-T") is False)

    # ==================================================================
    # ③ 跨字段对齐：任一匹配条目否定 / 矛盾 → 不得给出肯定裁决
    # ==================================================================
    cross_cases = [
        ("跨字段：coverage_items 肯定 + treatment_coverage 否定",
         {"coverage_items": [{"treatment": "CAR-T", "covered": True}],
          "treatment_coverage": {"CAR-T": False}}),
        ("跨字段：treatment_coverage 肯定 + covered_treatments 否定",
         {"treatment_coverage": {"CAR-T": True},
          "covered_treatments": {"CAR-T": False}}),
        ("跨字段：treatment_coverage 肯定 + treatment_responsibilities 矛盾",
         {"treatment_coverage": {"CAR-T": True},
          "treatment_responsibilities": {"CAR-T": {"covered": True, "is_covered": False}}}),
    ]
    for name, product in cross_cases:
        check(f"F18.5 跨字段对齐「{name}」：不得给出肯定裁决",
              pd._structured_authority_resolves(product, "CAR-T") is False)

    # ==================================================================
    # ④ 不得过度收紧（一致的决定键 → 授权仍须保留）
    # ==================================================================
    must_keep = [
        ("一致 affirmative（两个决定键都是 True）",
         {"treatment_coverage": {"CAR-T": {"covered": True, "is_covered": True}},
          "key_benefits": ["含CAR-T治疗"], "highlights": ""}, ["CAR-T"]),
        ("一致 affirmative + 显式除外裁决（结构化字段 + 正文冲突 · 残余 M 新口径）",
         {"treatment_coverage": {"CAR-T": {"covered": True, "is_covered": True,
                                          "exclusion_resolved": True}},
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}, ["CAR-T"]),
        ("显式类型化肯定（原有残余 F 口径不得被破坏）",
         {"treatment_coverage": {"CAR-T": True},
          "key_benefits": ["含CAR-T治疗"], "highlights": ""}, ["CAR-T"]),
        ("list dict covered=True（原有残余 F 口径不得被破坏）",
         {"coverage_items": [{"treatment": "CAR-T", "covered": True}],
          "key_benefits": ["含CAR-T治疗"], "highlights": ""}, ["CAR-T"]),
    ]
    for name, product, expect in must_keep:
        got = pd._medical_treatment_claims(product)
        check(f"F18.6 不得过度收紧「{name}」：claims == {expect}", got == expect,
              f"实际 {got}")

    # ==================================================================
    # ⑤ 源码级断言（防改回）
    # ==================================================================
    here = os.path.dirname(os.path.abspath(__file__))
    src = open(os.path.join(here, "plan_designer.py"), encoding="utf-8").read()

    check("F18.7 源码级：_structured_decision_state 已定义（标量决定状态判定）",
          "def _structured_decision_state(" in src)
    check("F18.8 源码级：_structured_authority_states 已定义（跨字段对齐收集）",
          "def _structured_authority_states(" in src)
    check("F18.9 源码级：状态口径含 contradictory（自相矛盾）",
          "contradictory" in src)

    # 决定键求值必须**遍历全部**键 → 不得再出现「取第一个就 break」
    i = src.find("def _structured_value_state(")
    j = src.find("\ndef ", i + 1)
    body = src[i:j if j != -1 else len(src)]
    _ok10 = ("break" not in body) or ("for key in _STRUCTURED_DECISION_KEYS" in body
                                      and "states.append(" in body)
    check("F18.10 源码级：_structured_value_state 不得再「取第一个决定键就 break」",
          _ok10, "" if _ok10 else "仍存在首个命中即 break")
    check("F18.11 源码级：_structured_value_state 遍历全部决定键并收集状态",
          "states.append(" in body)

    # 压制必须覆盖 contradictory
    i = src.find("def _structured_authority_denies(")
    j = src.find("\ndef ", i + 1)
    dbody = src[i:j if j != -1 else len(src)]
    check("F18.12 源码级：_structured_authority_denies 必须压制 contradictory",
          "contradictory" in dbody)

    # 肯定裁决必须跨全部结构化权威字段对齐
    i = src.find("def _structured_authority_resolves(")
    j = src.find("\ndef ", i + 1)
    rbody = src[i:j if j != -1 else len(src)]
    check("F18.13 源码级：_structured_authority_resolves 走 _structured_authority_states 对齐",
          "_structured_authority_states(" in rbody)
    _ok14 = ('return True' not in rbody.split("_structured_authority_states(")[0]
             or 'all(state == "affirmative"' in rbody)
    check("F18.14 源码级：_structured_authority_resolves 不得「见到 affirmative 就 return True」",
          _ok14, "" if _ok14 else "仍是首个 affirmative 即返回")

    return True


# ==================================================================
# F19 — SDI-4 残余 H（官方 2026-11-18 线上复扫 · 2.4.17）
#       结构化排除证据未压制宣称 + 明示不报销被当成承保
# ==================================================================
def test_f19_residual_h_exclusion_and_reimbursement(pd=None):
    """F19 (SDI-4 残余 H · 官方 2026-11-18 线上复扫 · 2.4.17): 排除证据压制 + 明示不报销

    官方 finding #1 原文（ai-insurance-advisor · 693-695）：
      「Structured exclusion evidence can still result in an affirmative
        treatment-coverage claim.」
    官方 remediation #1 原文：
      「Validate structured coverage entries against an explicit schema and treat
        affirmative decisions accompanied by exclusion evidence as contradictory
        or negative. Before authorizing any treatment claim, reconcile all
        matching structured entries and suppress the claim if any entry is
        negative, contradictory, ambiguous, or malformed; free text must not
        override these states. Add regression tests for co…」

    官方 finding #2 原文（insurance-advisor-china · 689-691）：
      「Contradictory structured coverage entries do not reliably suppress
        treatment claims.」
    官方 remediation #2 原文：
      「Reconcile all matching structured entries into one authoritative state
        before considering free-text claims. Classify affirmative decisions
        paired with negative metadata as contradictory, and suppress claims
        whenever a matching entry is ambiguous, malformed, negative, or
        contradictory; apply this gate to every claim-generation branch. Add
        regression tests covering contradictory metadata, conflictin…」

    官方 finding #3 原文（insurance-advisor-china · 953-963）：
      「An explicit reimbursement exclusion can become an affirmative
        treatment-coverage claim.」
    官方 remediation #3 原文：
      「Require validated, typed treatment-coverage decisions before generating
        affirmative claims; treat free-text evidence as unverified unless its
        meaning and applicable conditions are established. As an immediate
        mitigation, recognize constructions such as 「不可报销」 and post-treatment
        negation, suppress ambiguous statements, and add regression tests proving
        that reimbursement exclusions never generate af…」

    修法（两库同口径）：
      ① 结构化侧：affirmative 决定 + 同条目排除证据 → **contradictory**
         （不得是 ambiguous：ambiguous 既不授权**也不**压制 → 自由文本肯定
          证据照样产出无条件承保宣称）；
      ② 压制集合覆盖 negative / contradictory / **ambiguous**（= 未知 / 畸形）；
      ③ 结构化闸加到**每一个宣称生成分支**（free text must not override）；
      ④ 自由文本侧：否定词表补齐「不可报销」「不可支付」「不可赔付」→
         **双向**绑定（否定词在治疗手段**之前** / **之后**都生效 →
         post-treatment negation）；「不可报销」内的「报销」必须被否定作用域吃掉。

    断言口径（官方原文）：
      「asserting that no unconditional treatment claim is emitted」
      → 断言 **CAR-T 不得出现在宣称里**（不得产出无条件宣称），
        **不**写「claims 必须恰好等于 []」这类过严断言（防过度收紧）。
    """
    print("\n[F19] 结构化排除证据必须压制 + 明示不报销不得变成承保"
          "（SDI-4 残余 H · 官方 2026-11-18 线上复扫 · 2.4.17）")
    if pd is None:
        import plan_designer as pd  # china 版：模块已直接 import

    # ==================================================================
    # ① F19.1 affirmative 决定 + 同条目排除证据 → 不得产出无条件宣称
    #    （dict 形态 / list 形态；否定语义关键词两种写法）
    # ==================================================================
    must_not = [
        ("H1-1 dict 形态：covered=True + exclusion=除外",
         {"treatment_coverage": {"CAR-T": {"covered": True, "exclusion": "除外"}},
          "key_benefits": ["含CAR-T治疗费用报销"], "highlights": ""}),
        ("H1-2 dict 形态：covered=True + note=不承保（否定语义字符串）",
         {"treatment_coverage": {"CAR-T": {"covered": True, "note": "不承保"}},
          "key_benefits": ["含CAR-T治疗费用报销"], "highlights": ""}),
        ("H1-3 list 形态：元素 covered=True + exclusion=除外",
         {"treatment_coverage": [{"treatment": "CAR-T", "covered": True,
                                  "exclusion": "除外"}],
          "key_benefits": ["含CAR-T治疗费用报销"], "highlights": ""}),
        ("H1-4 list 形态：元素 covered=True + note=不承保",
         {"coverage_items": [{"treatment": "CAR-T", "covered": True,
                              "note": "不承保"}],
          "key_benefits": ["含CAR-T治疗费用报销"], "highlights": ""}),
        ("H1-5 跨字段变体：treatment_coverage 有排除证据 + coverage_items 肯定",
         {"treatment_coverage": {"CAR-T": {"covered": True, "exclusion": "除外"}},
          "coverage_items": [{"treatment": "CAR-T", "covered": True}],
          "key_benefits": ["含CAR-T治疗费用报销"], "highlights": ""}),
    ]
    for name, product in must_not:
        got = pd._medical_treatment_claims(product)
        suffix = pd._medical_treatment_suffix(product)
        check(f"F19.1 不得产出无条件宣称「{name}」：CAR-T 不在宣称里",
              "CAR-T" not in got, f"实际 claims={got}")
        check(f"F19.1 不得产出无条件宣称「{name}」：suffix 不含「含CAR-T」",
              "含CAR-T" not in suffix, f"实际 suffix={suffix!r}")

    # ==================================================================
    # ② F19.2 矛盾 / 畸形 / ambiguous 条目 → denies=True（且不得授权）
    # ==================================================================
    deny_cases = [
        ("H2-1 contradictory：covered=True + is_covered=False",
         {"treatment_coverage": {"CAR-T": {"covered": True, "is_covered": False}}}),
        ("H2-2 contradictory：covered=True + 同条目排除证据",
         {"treatment_coverage": {"CAR-T": {"covered": True, "exclusion": "除外"}}}),
        ("H2-3 contradictory：list 元素 covered=True + 同条目排除证据",
         {"coverage_items": [{"treatment": "CAR-T", "covered": True,
                              "exclusion": "除外"}]}),
        ("H2-4 malformed：条目无任何承保决定键",
         {"treatment_coverage": {"CAR-T": {"foo": "bar"}}}),
        ("H2-5 malformed：条目值是 list（未知类型）",
         {"treatment_coverage": {"CAR-T": ["CAR-T"]}}),
        ("H2-6 ambiguous：条目值是未知字符串",
         {"treatment_coverage": {"CAR-T": "待定"}}),
        ("H2-7 ambiguous：list 元素无承保决定键",
         {"coverage_items": [{"treatment": "CAR-T", "remark": "待定"}]}),
    ]
    for name, product in deny_cases:
        check(f"F19.2 压制生效「{name}」：_structured_authority_denies 为真",
              pd._structured_authority_denies(product, "CAR-T") is True)
        check(f"F19.2 不得授权「{name}」：_structured_authority_resolves 为假",
              pd._structured_authority_resolves(product, "CAR-T") is False)

    # ==================================================================
    # ③ F19.3 明示不报销 / 不支付 / 不赔付 → 不得产出承保宣称
    # ==================================================================
    reimbursement = [
        ("H3-1 不可报销（含肯定字样「含」+「报销」）",
         "含CAR-T治疗费用不可报销"),
        ("H3-2 不可支付",
         "含CAR-T治疗费用不可支付"),
        ("H3-3 不可赔付",
         "含CAR-T治疗费用不可赔付"),
        ("H3-4 前置否定：不可报销CAR-T治疗费用",
         "不可报销CAR-T治疗费用"),
    ]
    for name, text in reimbursement:
        product = {"key_benefits": [text], "highlights": ""}
        got = pd._medical_treatment_claims(product)
        suffix = pd._medical_treatment_suffix(product)
        check(f"F19.3 明示不报销不得宣称「{name}」：CAR-T 不在宣称里",
              "CAR-T" not in got, f"实际 claims={got}")
        check(f"F19.3 明示不报销不得宣称「{name}」：suffix 不含「含CAR-T」",
              "含CAR-T" not in suffix, f"实际 suffix={suffix!r}")

    # ==================================================================
    # ④ F19.4 post-treatment negation（否定词在治疗手段**之后**）
    # ==================================================================
    post_neg = [
        ("H3-5 后置否定：CAR-T治疗不可报销",
         "CAR-T治疗不可报销"),
        ("H3-6 后置否定：CAR-T治疗费用不可支付",
         "CAR-T治疗费用不可支付"),
        ("H3-7 后置否定：CAR-T治疗不可赔付",
         "CAR-T治疗不可赔付"),
        ("H3-8 后置否定 + 前置肯定字样：报销CAR-T治疗费用不可报销",
         "报销CAR-T治疗费用不可报销"),
    ]
    for name, text in post_neg:
        product = {"key_benefits": [text], "highlights": ""}
        got = pd._medical_treatment_claims(product)
        suffix = pd._medical_treatment_suffix(product)
        check(f"F19.4 post-treatment negation 不得宣称「{name}」：CAR-T 不在宣称里",
              "CAR-T" not in got, f"实际 claims={got}")
        check(f"F19.4 post-treatment negation 不得宣称「{name}」：suffix 不含「含CAR-T」",
              "含CAR-T" not in suffix, f"实际 suffix={suffix!r}")

    # ==================================================================
    # ⑤ F19.5 不得过度收紧：一致 affirmative → 仍须 claims == ['CAR-T']
    # ==================================================================
    must_keep = [
        ("一致 affirmative（两个决定键都是 True）",
         {"treatment_coverage": {"CAR-T": {"covered": True, "is_covered": True}},
          "key_benefits": ["含CAR-T治疗"], "highlights": ""}),
        ("显式类型化肯定（treatment_coverage={'CAR-T': True}）",
         {"treatment_coverage": {"CAR-T": True},
          "key_benefits": ["含CAR-T治疗"], "highlights": ""}),
        ("list dict covered=True",
         {"coverage_items": [{"treatment": "CAR-T", "covered": True}],
          "key_benefits": ["含CAR-T治疗"], "highlights": ""}),
        ("一致 affirmative + 显式除外裁决 + 正文冲突（可解决记录级冲突 · 残余 M 新口径）",
         {"treatment_coverage": {"CAR-T": {"covered": True, "is_covered": True,
                                          "exclusion_resolved": True}},
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}),
    ]
    for name, product in must_keep:
        got = pd._medical_treatment_claims(product)
        check(f"F19.5 不得过度收紧「{name}」：claims == ['CAR-T']", got == ["CAR-T"],
              f"实际 {got}")

    # ==================================================================
    # ⑥ F19.6 源码级断言（防改回）
    # ==================================================================
    here = os.path.dirname(os.path.abspath(__file__))
    src = open(os.path.join(here, "plan_designer.py"), encoding="utf-8").read()

    # 否定词表：必须含「不可报销」「不可支付」「不可赔付」（post-treatment negation）
    i = src.find("_NEG_MARKERS_BOTH = (")
    nbody = src[i:src.find(")", i)] if i != -1 else ""
    check("F19.6 源码级：否定词表含「不可报销」", "不可报销" in nbody,
          "" if "不可报销" in nbody else "未找到")
    check("F19.6 源码级：否定词表含「不可支付」", "不可支付" in nbody,
          "" if "不可支付" in nbody else "未找到")
    check("F19.6 源码级：否定词表含「不可赔付」", "不可赔付" in nbody,
          "" if "不可赔付" in nbody else "未找到")
    check("F19.6 源码级：三者必须在双向否定词表 _NEG_MARKERS_BOTH"
          "（否定词在治疗手段之前 / 之后都生效 → post-treatment negation）",
          all(t in nbody for t in ("不可报销", "不可支付", "不可赔付")))

    # _structured_value_state：affirmative + 同条目否定语义 → 必须 contradictory
    i = src.find("if _structured_contains_negation(value):")
    seg = ""
    if i != -1:
        j = src.find('return "affirmative"', i)
        seg = src[i:j] if j != -1 else src[i:i + 300]
    _ok_vs = ('return "contradictory"' in seg) and ('return "ambiguous"' not in seg)
    check("F19.6 源码级：affirmative + 同条目否定语义 → 必须判 contradictory"
          "（不得再是 ambiguous）", _ok_vs,
          "" if _ok_vs else "该分支仍返回 ambiguous 或未找到该分支")

    # 压制集合：必须覆盖 contradictory / ambiguous
    i = src.find("def _structured_authority_denies(")
    j = src.find("\ndef ", i + 1)
    dbody = src[i:j if j != -1 else len(src)]
    check("F19.6 源码级：denies 判定集合必须覆盖 contradictory",
          '"contradictory"' in dbody)
    check("F19.6 源码级：denies 判定集合必须覆盖 ambiguous（未知 / 畸形）",
          '"ambiguous"' in dbody)

    # 结构化闸必须落在**每一个宣称生成分支**
    i = src.find("def _medical_treatment_claims(")
    j = src.find("\ndef ", i + 1)
    mbody = src[i:j if j != -1 else len(src)]
    _ok_gate = ("structured_denies" in mbody
                and mbody.count("if ok and structured_denies:") >= 2)
    check("F19.6 源码级：结构化压制闸必须加到每一个宣称生成分支"
          "（free text must not override structured states）", _ok_gate,
          "" if _ok_gate else "宣称生成分支未全部过结构化闸")

    return True


# ==================================================================
# F20 — SDI-4 残余 I（官方 2026-11-18 线上复扫 · 2.4.18）
#       裸字符串治疗标识绕过压制闸
# ==================================================================
def test_f20_residual_i_bare_string_identifier(pd=None):
    """F20 (SDI-4 残余 I · 官方 2026-11-18 线上复扫 · 2.4.18): 裸字符串标识必须压制

    官方 finding 原文（ai-insurance-advisor v2.4.18 · scripts/plan_designer.py 855-861）：
      「Ambiguous bare-string treatment entries bypass the documented
        claim-suppression gate.」
    官方 remediation 原文：
      「Validate treatment entries against a single explicit schema shared by
        authorization and suppression checks. Classify a matching bare-string
        treatment identifier as ambiguous and suppress its claim rather than
        falling back to affirmative free text; retain suppression for explicit
        exclusions. Add regression tests for bare-string identifiers, ambiguous
        entries alongside affirmative text, and conflict…」

    根因（裸字符串是「三不管」状态）：
      ① `_structured_authority_states()` 遇到裸字符串**直接 continue** → 不产生
         任何状态 → states 为空 → 不授权；
      ② `_structured_authority_denies()` 裸字符串**只在自带否定语义时**才压制
         → 裸标识符（"CAR-T"）**不压制**；
      → 自由文本的肯定证据照样产出**无条件承保宣称**。

    修法（两库同口径）：
      ① 裸字符串与 dict 条目走**同一套显式 schema**（`_structured_bare_string_state`）
         → 授权判定（`_structured_authority_states`）与压制判定
           （`_structured_authority_denies`）**共用同一个状态函数**；
      ② **匹配**该治疗手段的裸标识符 → 判 **ambiguous** → **必须压制**
         （官方：suppress its claim，**不得** fallback 到肯定自由文本）；
      ③ 裸字符串**自带否定语义** → 判 negative（保留显式除外的压制）；
      ④ 标识匹配一律走**规范化标识**（`_normalize_treatment_identifier`）
         + 标识边界判定 → **不得**用裸子串判定（"CAR-TX" ≠ "CAR-T"）。

    断言口径（官方原文）：
      「asserting that no unconditional treatment claim is emitted」
      → 断言 **CAR-T 不得出现在宣称里**（不得产出无条件宣称），
        **不**写「claims 必须恰好等于 []」这类过严断言（防过度收紧）。
    """
    print("\n[F20] 裸字符串治疗标识必须压制（SDI-4 残余 I · 官方 2026-11-18 线上复扫 · 2.4.18）")
    if pd is None:
        import plan_designer as pd  # china 版：模块已直接 import

    # ==================================================================
    # ① F20.1 裸字符串治疗标识符 → 不得产出无条件宣称（list 形态 + dict 形态）
    # ==================================================================
    must_not = [
        ("I1-1 list 形态：treatment_coverage=['CAR-T']",
         {"treatment_coverage": ["CAR-T"]}),
        ("I1-2 list 形态：covered_treatments=['CAR-T']",
         {"covered_treatments": ["CAR-T"]}),
        ("I1-3 list 形态：coverage_items=['CAR-T']",
         {"coverage_items": ["CAR-T"]}),
        ("I1-4 dict 形态：treatment_coverage={'CAR-T': 'CAR-T'}",
         {"treatment_coverage": {"CAR-T": "CAR-T"}}),
        ("I1-5 dict 形态：coverage_items={'CAR-T': ['CAR-T']}",
         {"coverage_items": {"CAR-T": ["CAR-T"]}}),
    ]
    for name, struct in must_not:
        product = dict(struct)
        product["key_benefits"] = ["含CAR-T治疗费用报销"]
        product["highlights"] = ""
        got = pd._medical_treatment_claims(product)
        suffix = pd._medical_treatment_suffix(product)
        check(f"F20.1 不得产出无条件宣称「{name}」：CAR-T 不在宣称里",
              "CAR-T" not in got, f"实际 claims={got}")
        check(f"F20.1 不得产出无条件宣称「{name}」：suffix 不含「含CAR-T」",
              "含CAR-T" not in suffix, f"实际 suffix={suffix!r}")
        check(f"F20.1 压制生效「{name}」：_structured_authority_denies 为真",
              pd._structured_authority_denies(product, "CAR-T") is True)
        check(f"F20.1 不得授权「{name}」：_structured_authority_resolves 为假",
              pd._structured_authority_resolves(product, "CAR-T") is False)

    # ==================================================================
    # ② F20.2 裸字符串 + 肯定自由文本并存 → 仍不得宣称（不得 fallback）
    # ==================================================================
    with_text = [
        ("I2-1 裸字符串 + key_benefits 肯定文本",
         {"treatment_coverage": ["CAR-T"]},
         {"key_benefits": ["含CAR-T治疗费用报销"], "highlights": ""}),
        ("I2-2 裸字符串 + highlights 肯定文本（跨字段）",
         {"treatment_coverage": ["CAR-T"]},
         {"key_benefits": ["含CAR-T治疗"], "highlights": "CAR-T费用可报销"}),
        ("I2-3 裸字符串 + 显式肯定条目并存（conflict）",
         {"treatment_coverage": ["CAR-T"],
          "coverage_items": [{"treatment": "CAR-T", "covered": True}]},
         {"key_benefits": ["含CAR-T治疗费用报销"], "highlights": ""}),
        ("I2-4 裸字符串 + 显式肯定条目跨字段并存（conflict）",
         {"covered_treatments": ["CAR-T"],
          "treatment_coverage": {"CAR-T": {"covered": True, "is_covered": True}}},
         {"key_benefits": ["含CAR-T治疗费用报销"], "highlights": ""}),
    ]
    for name, struct, text in with_text:
        product = dict(struct)
        product.update(text)
        got = pd._medical_treatment_claims(product)
        suffix = pd._medical_treatment_suffix(product)
        check(f"F20.2 不得 fallback 到肯定自由文本「{name}」：CAR-T 不在宣称里",
              "CAR-T" not in got, f"实际 claims={got}")
        check(f"F20.2 不得 fallback 到肯定自由文本「{name}」：suffix 不含「含CAR-T」",
              "含CAR-T" not in suffix, f"实际 suffix={suffix!r}")
        check(f"F20.2 压制生效「{name}」：_structured_authority_denies 为真",
              pd._structured_authority_denies(product, "CAR-T") is True)
        check(f"F20.2 不得授权「{name}」：_structured_authority_resolves 为假",
              pd._structured_authority_resolves(product, "CAR-T") is False)

    # ==================================================================
    # ③ F20.3 标识变体（大小写 / 连字符 / 全角）→ 走规范化标识匹配仍须压制
    # ==================================================================
    variants = [
        ("I3-1 小写 car-t", "car-t"),
        ("I3-2 下划线 CAR_T", "CAR_T"),
        ("I3-3 非断行连字符 CAR‑T", "CAR‑T"),
        ("I3-4 短横线 car–t", "car–t"),
        ("I3-5 全角 ＣＡＲ－Ｔ", "ＣＡＲ－Ｔ"),
        ("I3-6 首尾空白 ' car-t '", " car-t "),
    ]
    for name, raw in variants:
        product = {"treatment_coverage": [raw],
                   "key_benefits": ["含CAR-T治疗费用报销"], "highlights": ""}
        got = pd._medical_treatment_claims(product)
        check(f"F20.3 标识变体必须压制「{name}」：CAR-T 不在宣称里",
              "CAR-T" not in got, f"实际 claims={got}")
        check(f"F20.3 标识变体必须压制「{name}」：denies 为真",
              pd._structured_authority_denies(product, "CAR-T") is True)
        check(f"F20.3 标识变体不得授权「{name}」：resolves 为假",
              pd._structured_authority_resolves(product, "CAR-T") is False)

    # ==================================================================
    # ④ F20.4 裸字符串自带否定语义 → 仍须压制（retain explicit exclusions）
    # ==================================================================
    negatives = [
        ("I4-1 除外", "CAR-T 除外"),
        ("I4-2 不予报销", "CAR-T 不予报销"),
        ("I4-3 前置否定 不承保", "不承保 CAR-T"),
        ("I4-4 后置否定 不可报销", "CAR-T治疗费用不可报销"),
        ("I4-5 英文 excluded", "CAR-T excluded"),
    ]
    for name, raw in negatives:
        product = {"treatment_coverage": [raw],
                   "key_benefits": ["含CAR-T治疗费用报销"], "highlights": ""}
        got = pd._medical_treatment_claims(product)
        check(f"F20.4 显式除外必须压制「{name}」：CAR-T 不在宣称里",
              "CAR-T" not in got, f"实际 claims={got}")
        check(f"F20.4 显式除外必须压制「{name}」：denies 为真",
              pd._structured_authority_denies(product, "CAR-T") is True)

    # ==================================================================
    # ⑤ F20.5 标识不匹配 → 不得误压制 CAR-T
    # ==================================================================
    not_matching = [
        ("I5-1 其它治疗手段裸标识（质子重离子）",
         {"treatment_coverage": ["质子重离子"]}),
        ("I5-2 更长的标识（CAR-TX）",
         {"treatment_coverage": ["CAR-TX"]}),
    ]
    for name, struct in not_matching:
        product = dict(struct)
        product["key_benefits"] = ["含CAR-T治疗费用报销"]
        product["highlights"] = ""
        check(f"F20.5 不得误压制「{name}」：_structured_authority_denies 为假",
              pd._structured_authority_denies(product, "CAR-T") is False)
        check(f"F20.5 不得误压制「{name}」：_structured_authority_resolves 为假",
              pd._structured_authority_resolves(product, "CAR-T") is False)
        got = pd._medical_treatment_claims(product)
        check(f"F20.5 不得误压制「{name}」：CAR-T 仍可正常宣称",
              "CAR-T" in got, f"实际 claims={got}")

    # ==================================================================
    # ⑥ F20.6 不得过度收紧：一致 affirmative → 仍须 claims == ['CAR-T']
    # ==================================================================
    must_keep = [
        ("一致 affirmative（covered=True + is_covered=True）",
         {"treatment_coverage": {"CAR-T": {"covered": True, "is_covered": True}}}),
        ("显式类型化肯定（treatment_coverage={'CAR-T': True}）",
         {"treatment_coverage": {"CAR-T": True}}),
        ("list dict covered=True",
         {"coverage_items": [{"treatment": "CAR-T", "covered": True}]}),
        ("裸字符串（其它治疗手段）不得影响 CAR-T 的显式肯定",
         {"treatment_coverage": ["质子重离子"],
          "coverage_items": [{"treatment": "CAR-T", "covered": True}]}),
    ]
    for name, struct in must_keep:
        product = dict(struct)
        product["key_benefits"] = ["含CAR-T治疗"]
        product["highlights"] = ""
        got = pd._medical_treatment_claims(product)
        check(f"F20.6 不得过度收紧「{name}」：claims == ['CAR-T']", got == ["CAR-T"],
              f"实际 {got}")

    # ==================================================================
    # ⑦ F20.7 源码级断言（防改回）
    # ==================================================================
    here = os.path.dirname(os.path.abspath(__file__))
    src = open(os.path.join(here, "plan_designer.py"), encoding="utf-8").read()

    check("F20.7 源码级：裸字符串状态判定函数已定义"
          "（授权与压制共用的唯一 schema）",
          "def _structured_bare_string_state(" in src)
    check("F20.7 源码级：裸字符串标识匹配函数已定义（规范化标识 + 标识边界）",
          "def _structured_bare_string_matches(" in src)

    # _structured_authority_states：裸字符串**不得**再被直接 continue 跳过
    i = src.find("def _structured_authority_states(")
    j = src.find("\ndef ", i + 1)
    sbody = src[i:j if j != -1 else len(src)]
    check("F20.7 源码级：_structured_authority_states 必须调用裸字符串状态判定"
          "（匹配时产生 ambiguous 状态）",
          "_structured_bare_string_state(" in sbody)
    _old_skip = "裸字符串 → ambiguous → 不授权"
    check("F20.7 源码级：_structured_authority_states 不得再出现"
          "「裸字符串 → ambiguous → 不授权」的直接跳过",
          _old_skip not in src,
          "仍存在直接跳过裸字符串的旧口径" if _old_skip in src else "")

    # _structured_authority_denies：裸字符串匹配项必须被压制
    i = src.find("def _structured_authority_denies(")
    j = src.find("\ndef ", i + 1)
    dbody = src[i:j if j != -1 else len(src)]
    check("F20.7 源码级：_structured_authority_denies 必须调用裸字符串状态判定"
          "（裸字符串匹配项必须被压制）",
          "_structured_bare_string_state(" in dbody)
    check("F20.7 源码级：denies 判定必须覆盖裸字符串的 ambiguous 状态",
          '"ambiguous"' in dbody)

    # 裸字符串匹配必须走规范化标识（不得裸子串判定）
    i = src.find("def _structured_bare_string_state(")
    j = src.find("\ndef ", i + 1)
    stbody = src[i:j if j != -1 else len(src)]
    check("F20.7 源码级：裸字符串状态判定必须走规范化标识",
          "_normalize_treatment_identifier(" in stbody)
    check("F20.7 源码级：裸字符串的 ambiguous 判定必须走标识匹配函数",
          "_structured_bare_string_matches(" in stbody)

    i = src.find("def _structured_bare_string_matches(")
    j = src.find("\ndef ", i + 1)
    bbody = src[i:j if j != -1 else len(src)]
    check("F20.7 源码级：标识匹配必须做**标识边界**判定"
          "（CAR-TX 不得匹配 CAR-T）",
          "_structured_is_identifier_char(" in bbody)

    # 结构化压制闸必须落在**每一个宣称生成分支**
    i = src.find("def _medical_treatment_claims(")
    j = src.find("\ndef ", i + 1)
    mbody = src[i:j if j != -1 else len(src)]
    check("F20.7 源码级：结构化压制闸必须覆盖每一个宣称生成分支"
          "（free text must not override structured states）",
          mbody.count("if ok and structured_denies:") >= 2)

    return True


def test_f21_residual_j_post_treatment_negation(pd=None):
    """F21 (SDI-4 残余 J · 官方 2026-11-18 线上复扫 · 2.4.19): post-treatment 否定必须绑定

    官方 finding 原文（insurance-advisor-china v2.4.19 · scripts/plan_designer.py 442-454）：
      「Some exclusion markers remain forward-only, so a product statement such as
        「CAR-T治疗不支持报销」 does not negate the preceding CAR-T occurrence; the
        subsequent 「报销」 can instead satisfy the affirmative-evidence check and
        generate 「含CAR-T治疗」. The record-level exclusion check uses the same
        incomplete logic, and absent structured coverage fields provide no
        suppression, making this particularly consequential in an insurance-advice
        skill where users may rely on a false coverage claim.」

    官方 remediation 原文：
      「Handle post-treatment exclusions such as 「CAR-T治疗不支持报销」 and
        「CAR-T治疗不包含在保障范围」 by binding exclusion semantics to the relevant
        treatment regardless of word order, while preventing reimbursement words
        inside those exclusions from authorizing coverage. Treat uncertain or
        conflicting interpretations as unverified and suppress affirmative claims.
        Add end-to-end regression tests covering these examples, alternative negation
        wording, punctuation and spacing variants, and records without structured
        coverage fields.」

    根因：
      ① 「不支持」「不包含」等是**纯前瞻型**否定词 —— 否定词在治疗手段**之后**
         （post-treatment negation）时，前瞻作用域落在治疗手段之后 → 绑不到它；
      ② 否定词跨度不含谓词 → 其后的「报销」落在跨度之外 → 通过肯定授权检查；
      ③ 记录级除外证据 `_record_exclusion_keywords()` 复用同一套判定 → 同样漏判
         （真实语料存在「质子重离子不含」形态）。

    修法（两库同口径）：
      A. **复合除外短语**：「<否定词><除外谓词>」是一个除外短语 —— 谓词纳入否定
         跨度 + 该短语**双向**绑定；
      B. **post-treatment 回溯绑定**：纯前瞻否定词若前瞻作用域内无治疗手段 →
         回溯绑定到最近一次治疗手段出现。

    断言口径（官方原文）：「asserting that no unconditional treatment claim is
    emitted」→ 断言被排除的治疗手段**不得**出现在宣称里（**不**写「claims 必须
    恰好等于 []」这类过严断言）；同时用 F21.6 守住**不得过度收紧**。
    """
    print("\n[F21] post-treatment 否定必须绑定到治疗手段（SDI-4 残余 J · 官方 2026-11-18 线上复扫 · 2.4.19）")
    if pd is None:
        import plan_designer as pd  # china 版：模块已直接 import

    # ==================================================================
    # ① F21.1 官方原文给出的两个形态 → 不得产出无条件承保宣称
    # ==================================================================
    official_cases = [
        ("J1-1「CAR-T治疗不支持报销」",
         {"key_benefits": ["CAR-T治疗不支持报销"], "highlights": ""}),
        ("J1-2「CAR-T治疗不包含在保障范围」",
         {"key_benefits": ["CAR-T治疗不包含在保障范围"], "highlights": ""}),
    ]
    for name, product in official_cases:
        got = pd._medical_treatment_claims(product)
        suffix = pd._medical_treatment_suffix(product)
        check(f"F21.1 不得宣称「{name}」：CAR-T 不在宣称里",
              "CAR-T" not in got, f"实际 claims={got}")
        check(f"F21.1 不得宣称「{name}」：suffix 不含「含CAR-T」",
              "含CAR-T" not in suffix, f"实际 suffix={suffix!r}")

    # ==================================================================
    # ② F21.2 同义否定措辞变体 → 不得宣称
    # ==================================================================
    wording_cases = [
        ("J2-1「CAR-T治疗不支持医保报销」",
         {"key_benefits": ["CAR-T治疗不支持医保报销"], "highlights": ""}),
        ("J2-2「CAR-T治疗不涵盖报销费用」",
         {"key_benefits": ["CAR-T治疗不涵盖报销费用"], "highlights": ""}),
        ("J2-3「CAR-T治疗不包括报销」",
         {"key_benefits": ["CAR-T治疗不包括报销"], "highlights": ""}),
        ("J2-4「质子重离子治疗不支持报销」",
         {"key_benefits": ["质子重离子治疗不支持报销"], "highlights": ""}),
        ("J2-5「CAR-T治疗不予报销」",
         {"key_benefits": ["CAR-T治疗不予报销"], "highlights": ""}),
        ("J2-6「CAR-T治疗不可报销」",
         {"key_benefits": ["CAR-T治疗不可报销"], "highlights": ""}),
        ("J2-7「质子重离子不含」（真实语料形态）",
         {"key_benefits": ["含质子重离子治疗费用报销"], "highlights": "",
          "weakness": ["质子重离子不含"]}),
    ]
    for name, product in wording_cases:
        got = pd._medical_treatment_claims(product)
        suffix = pd._medical_treatment_suffix(product)
        check(f"F21.2 不得宣称「{name}」：被排除治疗手段不在宣称里",
              not any(t in got for t in ("CAR-T", "质子重离子")),
              f"实际 claims={got}")
        check(f"F21.2 不得宣称「{name}」：suffix 不含「含」",
              "含CAR-T" not in suffix and "含质子重离子" not in suffix,
              f"实际 suffix={suffix!r}")

    # ==================================================================
    # ③ F21.3 标点 / 空白变体 → 不得宣称（普通空白不构成语义边界）
    # ==================================================================
    punct_cases = [
        ("J3-1 空格分隔「CAR-T治疗 不支持报销」",
         {"key_benefits": ["CAR-T治疗 不支持报销"], "highlights": ""}),
        ("J3-2 全角空格「CAR-T治疗　不支持报销」",
         {"key_benefits": ["CAR-T治疗　不支持报销"], "highlights": ""}),
        ("J3-3 逗号分句「CAR-T治疗，不支持报销」",
         {"key_benefits": ["CAR-T治疗，不支持报销"], "highlights": ""}),
        ("J3-4 句号结尾「CAR-T治疗不支持报销。」",
         {"key_benefits": ["CAR-T治疗不支持报销。"], "highlights": ""}),
        ("J3-5「CAR-T治疗不支持报销费用」",
         {"key_benefits": ["CAR-T治疗不支持报销费用"], "highlights": ""}),
    ]
    for name, product in punct_cases:
        got = pd._medical_treatment_claims(product)
        check(f"F21.3 不得宣称「{name}」：CAR-T 不在宣称里",
              "CAR-T" not in got, f"实际 claims={got}")

    # ==================================================================
    # ④ F21.4 跨字段（记录级冲突）→ 不得宣称
    # ==================================================================
    cross_field_cases = [
        ("J4-1 key_benefits 除外 + highlights 肯定",
         {"key_benefits": ["CAR-T治疗不支持报销"], "highlights": "含CAR-T治疗费用报销"}),
        ("J4-2 key_benefits 肯定 + highlights 除外",
         {"key_benefits": ["含CAR-T治疗费用报销"], "highlights": "CAR-T治疗不支持报销"}),
    ]
    for name, product in cross_field_cases:
        got = pd._medical_treatment_claims(product)
        check(f"F21.4 不得宣称「{name}」：CAR-T 不在宣称里",
              "CAR-T" not in got, f"实际 claims={got}")

    # ==================================================================
    # ⑤ F21.5 无结构化覆盖字段 → 自由文本不得自行授权
    # ==================================================================
    no_struct_cases = [
        ("J5-1 无结构化字段 · 仅除外文本",
         {"key_benefits": ["CAR-T治疗不支持报销"], "highlights": ""}),
        ("J5-2 无结构化字段 · 除外在 notes",
         {"key_benefits": ["含CAR-T治疗费用报销"], "highlights": "",
          "notes": "CAR-T治疗不支持报销"}),
    ]
    for name, product in no_struct_cases:
        got = pd._medical_treatment_claims(product)
        check(f"F21.5 无结构化字段时不得宣称「{name}」：CAR-T 不在宣称里",
              "CAR-T" not in got, f"实际 claims={got}")

    # ==================================================================
    # ⑥ F21.6 不得过度收紧：真正的承保证明 → 仍须正常宣称
    # ==================================================================
    positive_cases = [
        ("J6-1「含CAR-T治疗费用报销」",
         {"key_benefits": ["含CAR-T治疗费用报销"], "highlights": ""}, "CAR-T"),
        ("J6-2「CAR-T治疗费用可报销」",
         {"key_benefits": ["CAR-T治疗费用可报销"], "highlights": ""}, "CAR-T"),
        ("J6-3「覆盖CAR-T细胞免疫治疗」",
         {"key_benefits": ["覆盖CAR-T细胞免疫治疗"], "highlights": ""}, "CAR-T"),
        ("J6-4「支持CAR-T治疗但不支持质子重离子治疗」",
         {"key_benefits": ["支持CAR-T治疗但不支持质子重离子治疗"], "highlights": ""}, "CAR-T"),
        ("J6-5「含CAR-T治疗费用报销」+「质子重离子除外」",
         {"key_benefits": ["含CAR-T治疗费用报销", "质子重离子除外"], "highlights": ""}, "CAR-T"),
        ("J6-6「含质子重离子治疗费用报销」",
         {"key_benefits": ["含质子重离子治疗费用报销"], "highlights": ""}, "质子重离子"),
    ]
    for name, product, must in positive_cases:
        got = pd._medical_treatment_claims(product)
        check(f"F21.6 不得过度收紧「{name}」：{must} 仍可正常宣称",
              must in got, f"实际 claims={got}")

    # ==================================================================
    # ⑦ F21.7 源码级断言（防改回）
    # ==================================================================
    src = open(os.path.join(os.path.dirname(__file__), "plan_designer.py"),
               "r", encoding="utf-8").read()
    check("F21.7 源码级：复合除外短语判定已定义",
          "def _compound_exclusion_span(" in src)
    check("F21.7 源码级：post-treatment 回溯绑定已定义",
          "def _post_treatment_bindings(" in src)
    check("F21.7 源码级：否定词方向口径已统一到 _marker_directions",
          "def _marker_directions(" in src
          and "_marker_directions(marker)" in src)
    check("F21.7 源码级：_negation_context 必须调用 post-treatment 回溯绑定",
          "_post_treatment_bindings(blob, occurrences, spans, owner)" in src)
    check("F21.7 源码级：_negation_scope_map 必须登记 post-treatment 作用域",
          src.count("_post_treatment_bindings(blob, occurrences, spans, owner)") >= 2)
    check("F21.7 源码级：除外谓词表已定义",
          "_PREDICATE_TAILS" in src)

    return True


def test_f22_residual_k_uncertainty_guard(pd=None):
    """F22 (SDI-4 残余 K · 官方 2026-11-18 线上复扫 · 2.4.20): 不确定表述不得转为承保证言

    官方 finding 原文（insurance-advisor-china v2.4.20 · scripts/plan_designer.py 1259-1269）：
      「Uncertain treatment statements are converted into affirmative coverage claims
        despite the documented requirement to suppress unverified benefits.」
      「The affirmative-evidence check accepts words such as 「报销」 or 「含」 without
        establishing that the surrounding statement actually confirms coverage. For example,
        a product highlight reading 「CAR-T治疗是否报销待核实」 contains an accepted affirmative
        marker and no recognized exclusion, allowing it to become the unconditional claim
        「含CAR-T治疗」.」

    官方 remediation 原文：
      「Require validated, treatment-specific affirmative coverage decisions and preserve
        applicable conditions before emitting benefit claims. Treat questions, uncertainty,
        conditional eligibility, pending verification, and conflicting evidence as unverified,
        suppressing affirmative claims rather than relying on keyword presence. Add regression
        tests for phrases such as 「CAR-T治疗是否报销待核实」, 「可能包含CAR-T治疗」, and
        「CAR-T报销以核保结果为准」, alongside verified positive and explicit exclusion cases.」

    根因：`_occurrence_is_affirmative()` 只要在治疗手段邻近窗口里找到肯定关键字
         （报销 / 含 / 包含 / 覆盖 …）就判定「有承保授权」—— **没有校验这句话本身
         是否真的在确认承保**。疑问、可能性、条件性、待核实都会带着肯定关键字被当成授权。

    修法（两库同口径 · 业务逻辑零改动）：
      ① **字段元素级**守卫：元素内出现疑问 / 不确定 / 条件性 / 待核实表述
         → 该次出现的肯定证据**不成立**；
      ② **记录级**守卫：同一治疗手段在**任一文本叶子的同一子句**里带不确定表述
         → 属「未经确认」→ 跨字段 / 跨元素一律不宣称（**不得**被结构化裁决翻案）。

    断言口径：被不确定表述覆盖的治疗手段**不得**出现在宣称里（**不**写「claims 必须
    恰好等于 []」这类过严断言）；同时用 F22.5 守住**verified positive** 仍能宣称。
    """
    print("\n[F22] 不确定 / 条件性表述不得转为承保证言（SDI-4 残余 K · 官方 2026-11-18 线上复扫 · 2.4.20）")
    if pd is None:
        import plan_designer as pd  # china 版：模块已直接 import

    # ==================================================================
    # ① F22.1 官方原文给出的三个反例 → 不得宣称
    # ==================================================================
    official_cases = [
        ("K1-1「CAR-T治疗是否报销待核实」",
         {"key_benefits": ["CAR-T治疗是否报销待核实"], "highlights": ""}),
        ("K1-2「可能包含CAR-T治疗」",
         {"key_benefits": ["可能包含CAR-T治疗"], "highlights": ""}),
        ("K1-3「CAR-T报销以核保结果为准」",
         {"key_benefits": ["CAR-T报销以核保结果为准"], "highlights": ""}),
    ]
    for name, product in official_cases:
        got = pd._medical_treatment_claims(product)
        suffix = pd._medical_treatment_suffix(product)
        check(f"F22.1 不得宣称「{name}」：CAR-T 不在宣称里",
              "CAR-T" not in got, f"实际 claims={got}")
        check(f"F22.1 不得宣称「{name}」：suffix 不含「含CAR-T」",
              "含CAR-T" not in suffix, f"实际 suffix={suffix!r}")

    # ==================================================================
    # ② F22.2 疑问 / 不确定性 / 条件性措辞变体 → 不得宣称
    # ==================================================================
    wording_cases = [
        ("K2-1「CAR-T治疗能否报销」",
         {"key_benefits": ["CAR-T治疗能否报销"], "highlights": ""}),
        ("K2-2「CAR-T治疗报销情况待定」",
         {"key_benefits": ["CAR-T治疗报销情况待定"], "highlights": ""}),
        ("K2-3「含CAR-T治疗（待核实）」",
         {"key_benefits": ["含CAR-T治疗（待核实）"], "highlights": ""}),
        ("K2-4「CAR-T报销以实际理赔为准」",
         {"key_benefits": ["CAR-T报销以实际理赔为准"], "highlights": ""}),
        ("K2-5「视情况包含CAR-T治疗」",
         {"key_benefits": ["视情况包含CAR-T治疗"], "highlights": ""}),
        ("K2-6「CAR-T治疗是否承保待确认」",
         {"key_benefits": ["CAR-T治疗是否承保待确认"], "highlights": ""}),
        ("K2-7「可能涵盖质子重离子治疗」",
         {"key_benefits": ["可能涵盖质子重离子治疗"], "highlights": ""}),
    ]
    for name, product in wording_cases:
        got = pd._medical_treatment_claims(product)
        check(f"F22.2 不得宣称「{name}」：被不确定表述覆盖的治疗手段不在宣称里",
              not any(t in got for t in ("CAR-T", "质子重离子")),
              f"实际 claims={got}")

    # ==================================================================
    # ③ F22.3 跨字段（记录级不确定证据）→ 不得宣称
    # ==================================================================
    cross_field_cases = [
        ("K3-1 key_benefits 肯定 + highlights 疑问",
         {"key_benefits": ["含CAR-T治疗费用报销"], "highlights": "CAR-T治疗是否报销待核实"}),
        ("K3-2 key_benefits 疑问 + highlights 肯定",
         {"key_benefits": ["CAR-T治疗是否报销待核实"], "highlights": "含CAR-T治疗费用报销"}),
    ]
    for name, product in cross_field_cases:
        got = pd._medical_treatment_claims(product)
        check(f"F22.3 不得宣称「{name}」：CAR-T 不在宣称里",
              "CAR-T" not in got, f"实际 claims={got}")

    # ==================================================================
    # ④ F22.4 显式除外（explicit exclusion）→ 仍须压制
    # ==================================================================
    exclusion_cases = [
        ("K4-1「CAR-T治疗不支持报销」",
         {"key_benefits": ["CAR-T治疗不支持报销"], "highlights": ""}),
        ("K4-2「不含CAR-T治疗费用报销」",
         {"key_benefits": ["不含CAR-T治疗费用报销"], "highlights": ""}),
    ]
    for name, product in exclusion_cases:
        got = pd._medical_treatment_claims(product)
        check(f"F22.4 显式除外必须压制「{name}」：CAR-T 不在宣称里",
              "CAR-T" not in got, f"实际 claims={got}")

    # ==================================================================
    # ⑤ F22.5 verified positive（官方要求 alongside verified positive）
    # ==================================================================
    positive_cases = [
        ("K5-1「含CAR-T治疗费用报销」",
         {"key_benefits": ["含CAR-T治疗费用报销"], "highlights": ""}, "CAR-T"),
        ("K5-2「CAR-T治疗费用可报销」",
         {"key_benefits": ["CAR-T治疗费用可报销"], "highlights": ""}, "CAR-T"),
        ("K5-3「覆盖CAR-T细胞免疫治疗」",
         {"key_benefits": ["覆盖CAR-T细胞免疫治疗"], "highlights": ""}, "CAR-T"),
        ("K5-4「含质子重离子治疗费用报销」",
         {"key_benefits": ["含质子重离子治疗费用报销"], "highlights": ""}, "质子重离子"),
        ("K5-5「特药费用可报销」",
         {"key_benefits": ["特药费用可报销"], "highlights": ""}, "特药"),
    ]
    for name, product, must in positive_cases:
        got = pd._medical_treatment_claims(product)
        check(f"F22.5 不得过度收紧「{name}」：{must} 仍可正常宣称",
              must in got, f"实际 claims={got}")

    # ==================================================================
    # ⑥ F22.6 源码级断言（防改回）
    # ==================================================================
    src = open(os.path.join(os.path.dirname(__file__), "plan_designer.py"),
               "r", encoding="utf-8").read()
    check("F22.6 源码级：不确定判定函数已定义",
          "def _has_uncertainty(" in src)
    check("F22.6 源码级：记录级不确定证据判定已定义",
          "def _record_uncertain_keywords(" in src)
    check("F22.6 源码级：不确定 / 疑问 / 条件性词表已定义",
          "_UNCERTAINTY_MARKERS" in src)
    check("F22.6 源码级：「以……为准」通用形态已覆盖",
          "_RE_SUBJECT_TO" in src)
    check("F22.6 源码级：_occurrence_is_affirmative 必须过不确定守卫",
          "_has_uncertainty(blob, el_lo, el_hi)" in src)
    check("F22.6 源码级：_medical_treatment_claims 必须调用记录级不确定闸",
          "_record_uncertain_keywords(product)" in src)
    check("F22.6 源码级：记录级不确定闸必须压制宣称",
          src.count("if ok and kw in record_uncertain:") >= 2)

    return True


def test_f23_residual_lmn_conditions_and_structured_authority(pd=None):
    """F23 (SDI-4 残余 L/M/N · 官方 2026-11-18 线上复扫 · 2.4.21): 条件 / 结构化裁决

    【残余 L · china v2.4.21 · L1359-1376 · Excessive Agency / MEDIUM】
      finding: "Conditional treatment coverage can become an unconditional benefit claim
                despite documented suppression of conditional statements."
      remediation: "Require validated, treatment-specific coverage decisions with explicit
                    applicability conditions before generating benefit claims. Preserve those
                    conditions in the output, or suppress the claim when conditions cannot be
                    reliably interpreted; do not treat affirmative free-text keywords as
                    sufficient authorization. Add regression tests for hospital restrictions,
                    prior authorization, designated-drug lists, eligibility requirements, and
                    conditional structured entries."

    【残余 M · ai v2.4.21 · L1617-1629 · Excessive Agency / MEDIUM】
      finding: "Structured affirmative flags can override exclusions without preserving
                coverage conditions."
      remediation: "Require treatment-specific, validated coverage decisions that explicitly
                    resolve conflicting exclusions and include applicable conditions. Preserve
                    those conditions in generated benefit descriptions; if a conflict or
                    condition cannot be reliably interpreted and rendered, suppress the claim and
                    report it as unverified. Add regression tests combining affirmative flags,
                    textual exclusions, and nested eligibility conditions."

    【残余 N · ai v2.4.21 · L1691-1704 · Excessive Agency / MEDIUM】
      finding: "Critical-illness benefit derivation converts excluded mild-illness coverage
                into an affirmative benefit."
      remediation: "Derive mild-illness coverage and disease counts from validated,
                    product-specific structured fields rather than keyword presence. Suppress
                    affirmative claims when evidence is negative, uncertain, conditional, or
                    contradictory, and preserve relevant limitations in the output."

    修法（两库同口径 · 业务逻辑零改动 · 仅判定层）：
      L. 适用条件闸（仅限指定医院 / 需转诊 / 预授权 / 目录内 / 符合条件 …）
         → 条件无法在对外文案里渲染 → 肯定授权证据**不成立**；
      M. 结构化条目携带适用条件 → 不得无条件宣称；结构化 covered=True **本身即
         权威裁决** → 可解决记录级冲突（不得再要求「显式除外裁决信号」当普遍
         前置条件）；显式声明「冲突未裁决」→ 不得授权；
      N. `_crx_disease_claim` 感知除外 / 条件 / 不确定表述。
    """
    print("\n[F23] 适用条件与结构化裁决（SDI-4 残余 L/M/N · 官方 2026-11-18 线上复扫 · 2.4.21）")
    if pd is None:
        import plan_designer as pd  # china 版：模块已直接 import

    # ==================================================================
    # ① F23.1 残余 L：条件性表述 → 不得产出无条件承保宣称
    # ==================================================================
    condition_cases = [
        ("L1-1「仅限指定医院CAR-T治疗可报销」",
         {"key_benefits": ["仅限指定医院CAR-T治疗可报销"], "highlights": ""}),
        ("L1-2「CAR-T治疗需转诊后可报销」",
         {"key_benefits": ["CAR-T治疗需转诊后可报销"], "highlights": ""}),
        ("L1-3「CAR-T治疗限于社保目录内」",
         {"key_benefits": ["CAR-T治疗限于社保目录内"], "highlights": ""}),
        ("L1-4「CAR-T治疗须经审核通过」",
         {"key_benefits": ["CAR-T治疗须经审核通过"], "highlights": ""}),
        ("L1-5「CAR-T治疗限二级以上医院」",
         {"key_benefits": ["CAR-T治疗限二级以上医院"], "highlights": ""}),
        ("L1-6 跨字段：key_benefits 肯定 + highlights 带条件",
         {"key_benefits": ["含CAR-T治疗费用报销"], "highlights": "仅限指定医院可报销"}),
    ]
    for name, product in condition_cases:
        got = pd._medical_treatment_claims(product)
        suffix = pd._medical_treatment_suffix(product)
        check(f"F23.1 不得宣称「{name}」：CAR-T 不在宣称里",
              "CAR-T" not in got, f"实际 claims={got}")
        check(f"F23.1 不得宣称「{name}」：suffix 不含「含CAR-T」",
              "含CAR-T" not in suffix, f"实际 suffix={suffix!r}")

    # ==================================================================
    # ② F23.2 残余 M：结构化肯定覆盖除外证据的收紧口径
    # ==================================================================
    structured_must_suppress = [
        ("M1-3 covered=True + 适用条件 + 正文冲突",
         {"coverage_items": [{"treatment": "CAR-T", "covered": True,
                              "condition": "限二级以上医院"}],
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}),
        ("M1-4 covered=True + 嵌套资格条件 + 正文冲突",
         {"coverage_items": [{"treatment": "CAR-T", "covered": True,
                              "eligibility": {"医院等级": "二级以上"}}],
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}),
        ("M1-5 covered=True + 适用条件 + 正文肯定（无冲突）",
         {"coverage_items": [{"treatment": "CAR-T", "covered": True,
                              "eligibility": "仅限指定医院"}],
          "key_benefits": ["含CAR-T治疗"], "highlights": ""}),
        ("M1-6 显式声明冲突未裁决（exclusion_resolved=False）+ 正文冲突",
         {"treatment_coverage": {"CAR-T": {"covered": True,
                                          "exclusion_resolved": False}},
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}),
    ]
    for name, product in structured_must_suppress:
        got = pd._medical_treatment_claims(product)
        check(f"F23.2 不得宣称「{name}」：CAR-T 不在宣称里",
              "CAR-T" not in got, f"实际 claims={got}")
        check(f"F23.2 不得给出肯定裁决「{name}」：_structured_authority_resolves 为假",
              pd._structured_authority_resolves(product, "CAR-T") is False)

    structured_must_keep = [
        ("M2-1 covered=True + 显式除外裁决 → 可解决冲突",
         {"treatment_coverage": {"CAR-T": {"covered": True, "exclusion_resolved": True}},
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}),
        ("M2-2 无冲突的正常承保必须保留",
         {"key_benefits": ["含CAR-T治疗费用报销"], "highlights": ""}),
        # ⚠ 2026-11-19 修正：结构化 covered=True **本身即权威裁决** →
        #   可解决记录级冲突（不得再要求「显式除外裁决信号」当普遍前置条件）
        ("M2-3 dict 形态 covered=True → 可解决记录级冲突",
         {"treatment_coverage": {"CAR-T": {"covered": True}},
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}),
        ("M2-4 裸布尔 covered=True → 可解决记录级冲突",
         {"treatment_coverage": {"CAR-T": True},
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}),
        ("M2-5 list dict 形态 covered=True → 可解决记录级冲突",
         {"coverage_items": [{"treatment": "CAR-T", "covered": True}],
          "key_benefits": ["含CAR-T治疗 不含CAR-T治疗"], "highlights": ""}),
    ]
    for name, product in structured_must_keep:
        got = pd._medical_treatment_claims(product)
        check(f"F23.2 不得过度收紧「{name}」：CAR-T 仍可正常宣称",
              "CAR-T" in got, f"实际 claims={got}")
    # ⚠ 2026-11-23 修正（**断言写错**，非代码行为问题 —— 见任务书 §4.3 F23.2）：
    #   M2-2 用例**完全没有结构化字段**（key_benefits 裸文本 + 空 highlights）。
    #   `_structured_authority_resolves` 的文档口径明确：「key_benefits /
    #   highlights / tags 都是自由文本……不得用来裁决冲突 → 只认结构化字段」，
    #   「其余一律不授权：裸字符串列表、字符串值、未知值……全部视为 ambiguous」。
    #   ⇒ 无结构化字段 + 无冲突的产品，**不得**要求结构化权威给出肯定裁决；
    #     但「不得过度收紧」的断言（宣称必须保留）成立。
    for name, product in structured_must_keep:
        if name.startswith("M2-2"):
            check(f"F23.2 不得过度收紧「{name}」：无结构化字段 → 结构化权威**不作肯定裁决**",
                  pd._structured_authority_resolves(product, "CAR-T") is False)
            continue
        check(f"F23.2 不得过度收紧「{name}」：结构化权威给出肯定裁决",
              pd._structured_authority_resolves(product, "CAR-T") is True)

    # ==================================================================
    # ③ F23.3 残余 N：重疾轻症宣称不得反转明确除外
    # ==================================================================
    crx_must_suppress = [
        ("N1-1「120种重疾，不含轻症」", "120种重疾，不含轻症"),
        ("N1-2「120种重疾，轻症除外」", "120种重疾，轻症除外"),
        ("N1-3「120种重疾，不含轻症保障」", "120种重疾，不含轻症保障"),
        ("N1-4「120种重疾，无轻症」", "120种重疾，无轻症"),
    ]
    for name, hl in crx_must_suppress:
        got = pd._crx_disease_claim({"highlights": hl})
        check(f"F23.3 不得宣称「{name}」：轻症宣称为空串",
              got == "", f"实际 {got!r}")
    crx_must_keep = [
        ("N2-1「120种重疾+60种轻症」", "120种重疾+60种轻症"),
        ("N2-2「保障120种重疾+60种轻症，含身故责任」", "保障120种重疾+60种轻症，含身故责任"),
    ]
    for name, hl in crx_must_keep:
        got = pd._crx_disease_claim({"highlights": hl})
        check(f"F23.3 不得过度收紧「{name}」：轻症宣称正常产出",
              got != "", f"实际 {got!r}")

    # ==================================================================
    # ④ F23.4 正例（条件 / 结构化收紧不得误伤正常承保）
    # ==================================================================
    positive_cases = [
        ("L3-1「含CAR-T治疗费用报销」",
         {"key_benefits": ["含CAR-T治疗费用报销"], "highlights": ""}, "CAR-T"),
        ("L3-2「CAR-T治疗费用可报销」",
         {"key_benefits": ["CAR-T治疗费用可报销"], "highlights": ""}, "CAR-T"),
        ("L3-3「覆盖CAR-T细胞免疫治疗」",
         {"key_benefits": ["覆盖CAR-T细胞免疫治疗"], "highlights": ""}, "CAR-T"),
        ("L3-4「含质子重离子治疗费用报销」",
         {"key_benefits": ["含质子重离子治疗费用报销"], "highlights": ""}, "质子重离子"),
    ]
    for name, product, must in positive_cases:
        got = pd._medical_treatment_claims(product)
        check(f"F23.4 不得过度收紧「{name}」：{must} 仍可正常宣称",
              must in got, f"实际 claims={got}")

    # ==================================================================
    # ⑤ F23.5 源码级断言（防改回）
    # ==================================================================
    src = open(os.path.join(os.path.dirname(__file__), "plan_designer.py"),
               "r", encoding="utf-8").read()
    check("F23.5 源码级：适用条件词表已定义", "_CONDITION_MARKERS" in src)
    check("F23.5 源码级：适用条件判定函数已定义", "def _has_condition(" in src)
    check("F23.5 源码级：记录级条件词表已定义",
          "def _record_condition_keywords(" in src)
    check("F23.5 源码级：肯定授权判定必须过适用条件闸",
          "_has_condition(blob, el_lo, el_hi)" in src)
    check("F23.5 源码级：结构化条件键表已定义", "_STRUCTURED_CONDITION_KEYS" in src)
    check("F23.5 源码级：结构化除外裁决键表已定义", "_STRUCTURED_RESOLUTION_KEYS" in src)
    check("F23.5 源码级：结构化裁决必须检查适用条件",
          "_structured_entry_has_condition(" in src)
    check("F23.5 源码级：结构化裁决必须显式拦截「冲突未裁决」声明",
          "_structured_entry_declares_unresolved(" in src)
    check("F23.5 源码级：条件通道必须覆盖结构化条目",
          "_structured_condition_keywords(" in src)
    check("F23.5 源码级：_crx_disease_claim 必须过除外 / 条件判定",
          "_crx_subject_unconfirmed(" in src)

    return True


def test_f24_residual_n2_bidirectional_exclusion(pd=None):
    """F24（官方 SDI-4 残余 N 第二轮 · 2026-11-21 线上复扫 · v2.4.26）

    【官方 finding（china 2.4.26 · Excessive Agency · 原文）】
      "The critical-illness benefit generator can turn an explicit mild-illness
       exclusion into an affirmative coverage claim."

    【官方 explanation（china 2.4.26 · 原文）】
      "The exclusion guard remains incomplete: highlights such as 「120种重疾，不保轻症」
       pass because _crx_subject_unconfirmed does not recognize 「不保」 before the
       subject, causing _crx_disease_claim to output 「120种重疾+轻症保障」."

    【官方 explanation（ai 2.4.26 · 原文）】
      "The exclusion guard recognizes only selected negation phrases and word orders:
       for example, highlights containing 「120种重疾，不承保轻症」 pass because
       「不承保」 is checked after the subject but not before it."

    【官方 remediation（原文）】
      "…handle exclusions before and after the subject consistently rather than
       relying on a small prefix list, and reconcile contradictory evidence
       throughout the product record."
      "Add regression tests for 「120种重疾，不保轻症」, 「120种重疾，不赔轻症」,
       post-subject exclusions, and conflicting statements, checking the final
       generated plan."

    覆盖：
      ① head（subject **之前**）除外：不承保 / 不保 / 不赔 / 不含 / 不覆盖 …
      ② 标记与 subject 之间**有填充词**（intervening words after negation）
      ③ post-subject 除外（轻症不保 / 轻症除外 / 轻症不予赔付 / 轻症不在保障范围）
      ④ **矛盾陈述**（同一条 highlights 里既有肯定又有除外）
      ⑤ **最终生成方案文案**不得出现「120种重疾+轻症保障」/「轻症保障」
      ⑥ 不得过度收紧：明确肯定承保的正例仍须产出轻症宣称
    """
    print("\nTest F24: 除外词序双向识别 + 矛盾陈述压制（官方 SDI-4 残余 N 第二轮）")
    if pd is None:
        import plan_designer as PD  # ai 版：模块级未 import，按 F23 既有写法局部导入
    else:
        PD = pd

    # ==================================================================
    # ① 官方点名的前置除外（head 侧 · subject 之前）
    # ==================================================================
    head_must_suppress = [
        ("N2-1「120种重疾，不承保轻症」（官方 ai 原文点名）", "120种重疾，不承保轻症"),
        ("N2-2「120种重疾，不保轻症」（官方 china 原文点名）", "120种重疾，不保轻症"),
        ("N2-3「120种重疾，不赔轻症」（官方 china 原文点名）", "120种重疾，不赔轻症"),
        ("N2-4「120种重疾，不含轻症」", "120种重疾，不含轻症"),
        ("N2-5「120种重疾，不包含轻症」", "120种重疾，不包含轻症"),
        ("N2-6「120种重疾，不包括轻症」", "120种重疾，不包括轻症"),
        ("N2-7「120种重疾，不纳入轻症」", "120种重疾，不纳入轻症"),
        ("N2-8「120种重疾，不涵盖轻症」", "120种重疾，不涵盖轻症"),
        ("N2-9「120种重疾，不覆盖轻症」", "120种重疾，不覆盖轻症"),
        ("N2-10「120种重疾，不支持轻症」", "120种重疾，不支持轻症"),
        ("N2-11「120种重疾，不在保障范围轻症」", "120种重疾，不在保障范围轻症"),
        ("N2-12「120种重疾，除外轻症」", "120种重疾，除外轻症"),
        ("N2-13「120种重疾，无轻症」", "120种重疾，无轻症"),
    ]
    for name, hl in head_must_suppress:
        check(f"F24.1 不得宣称「{name}」：轻症宣称为空串",
              PD._crx_disease_claim({"highlights": hl}) == "",
              f"实际 {PD._crx_disease_claim({'highlights': hl})!r}")
        check(f"F24.1 不得宣称「{name}」：_crx_subject_unconfirmed 为真",
              PD._crx_subject_unconfirmed(hl, "轻症") is True)

    # ==================================================================
    # ② 标记与 subject 之间**有填充词**（intervening words after negation）
    # ==================================================================
    filler_must_suppress = [
        ("N2-14「120种重疾，不承保轻症疾病」", "120种重疾，不承保轻症疾病"),
        ("N2-15「120种重疾，不保轻症保障」", "120种重疾，不保轻症保障"),
        ("N2-16「120种重疾，不含轻症疾病」", "120种重疾，不含轻症疾病"),
        ("N2-17「120种重疾，不赔轻症保障责任」", "120种重疾，不赔轻症保障责任"),
        ("N2-18「120种重疾，不承保的轻症」", "120种重疾，不承保的轻症"),
        ("N2-19「120种重疾，不包含部分轻症」", "120种重疾，不包含部分轻症"),
    ]
    for name, hl in filler_must_suppress:
        check(f"F24.2 不得宣称「{name}」：轻症宣称为空串",
              PD._crx_disease_claim({"highlights": hl}) == "",
              f"实际 {PD._crx_disease_claim({'highlights': hl})!r}")

    # ==================================================================
    # ③ post-subject 除外（subject 之后）
    # ==================================================================
    post_must_suppress = [
        ("N2-20「轻症不予赔付」（官方 china 原文点名）", "轻症不予赔付"),
        ("N2-21「轻症不保」", "轻症不保"),
        ("N2-22「轻症除外」", "轻症除外"),
        ("N2-23「轻症不在保障范围」", "轻症不在保障范围"),
        ("N2-24「120种重疾，轻症除外」", "120种重疾，轻症除外"),
        ("N2-25「120种重疾，轻症不予给付」", "120种重疾，轻症不予给付"),
        ("N2-26「120种重疾，轻症无保障」", "120种重疾，轻症无保障"),
    ]
    for name, hl in post_must_suppress:
        check(f"F24.3 不得宣称「{name}」：轻症宣称为空串",
              PD._crx_disease_claim({"highlights": hl}) == "",
              f"实际 {PD._crx_disease_claim({'highlights': hl})!r}")

    # ==================================================================
    # ④ 矛盾陈述（同一条 highlights 里既有肯定又有除外）
    # ==================================================================
    conflict_must_suppress = [
        ("N2-27「120种重疾，含轻症但不承保轻症」",
         "120种重疾，含轻症但不承保轻症"),
        ("N2-28「120种重疾，含轻症，轻症除外」",
         "120种重疾，含轻症，轻症除外"),
        ("N2-29「保障120种重疾+60种轻症，不赔轻症」",
         "保障120种重疾+60种轻症，不赔轻症"),
        ("N2-30「保障120种重疾+轻症，但轻症不保」",
         "保障120种重疾+轻症，但轻症不保"),
    ]
    for name, hl in conflict_must_suppress:
        check(f"F24.4 矛盾陈述不得宣称「{name}」：轻症宣称为空串",
              PD._crx_disease_claim({"highlights": hl}) == "",
              f"实际 {PD._crx_disease_claim({'highlights': hl})!r}")

    # ④-b 记录级矛盾（highlights 肯定 + 其它字段除外）→ 官方 remediation：
    #      「reconcile contradictory evidence throughout the product record」
    check("F24.4 记录级矛盾（highlights 肯定 + notes 除外）必须压制",
          PD._crx_disease_claim({
              "highlights": "120种重疾+60种轻症",
              "notes": "轻症不保，仅承保重疾"}) == "",
          "实际 %r" % (PD._crx_disease_claim({
              "highlights": "120种重疾+60种轻症",
              "notes": "轻症不保，仅承保重疾"}),))

    # ==================================================================
    # ⑤ **最终生成方案文案**校验（官方 china remediation：checking the final
    #     generated plan）—— 不得只看中间函数返回值
    # ==================================================================
    products = PD.load_products()
    crx_real = next((p for p in products if p.get("type") == "重疾险"), None)
    check("F24.5 产品库存在重疾险（用例有效）", crx_real is not None,
          crx_real.get("name") if crx_real else "产品库无重疾险")

    if crx_real is not None:
        def _plan_text_for(highlights):
            """把产品池里的重疾险换成 highlights 指定的那一款 → 生成全部方案 → 返回文案"""
            adv = dict(crx_real)
            adv["highlights"] = highlights
            pool = [adv if p.get("type") == "重疾险" else p for p in products]
            orig = PD.load_products
            PD.load_products = lambda include_discontinued=False: list(pool)
            try:
                plans = PD.generate_all_plans(
                    35, "男", 300000, 200000,
                    {"death": 2000000, "critical_illness": 1500000,
                     "hospital": 4000000})
            finally:
                PD.load_products = orig
            chunks = []
            for _pname, plan in plans.items():
                if not plan:
                    continue
                for entry in (plan.get("products") or []):
                    if entry.get("type") == "重疾险":
                        chunks.append(str(entry.get("key_benefits") or ""))
                        chunks.append(str(entry.get("coverage_period") or ""))
                for feat in (plan.get("features") or []):
                    chunks.append(str(feat))
            return "\n".join(chunks)

        for name, hl in [("N2-31「120种重疾，不承保轻症」", "120种重疾，不承保轻症"),
                         ("N2-32「120种重疾，不保轻症」", "120种重疾，不保轻症"),
                         ("N2-33「120种重疾，不赔轻症」", "120种重疾，不赔轻症"),
                         ("N2-34「轻症不予赔付」", "轻症不予赔付")]:
            text = _plan_text_for(hl)
            check(f"F24.5 最终方案文案不得出现「120种重疾+轻症保障」「{name}」",
                  "120种重疾+轻症保障" not in text,
                  "实际方案文案含该宣称" if "120种重疾+轻症保障" in text else "")
            check(f"F24.5 最终方案文案不得出现「轻症保障」「{name}」",
                  "轻症保障" not in text,
                  "实际方案文案含该宣称" if "轻症保障" in text else "")

        # ⑤-b 正例：明确肯定承保 → 最终方案**必须**继续产出轻症宣称（不得过度收紧）
        pos_text = _plan_text_for("120种重疾+60种轻症")
        check("F24.5 正例：最终方案仍须产出「120种重疾+轻症保障」（不得过度收紧）",
              "120种重疾+轻症保障" in pos_text,
              f"实际方案文案={pos_text[:200]!r}")

    # ==================================================================
    # ⑥ 不得过度收紧：明确肯定承保的正例仍须产出轻症宣称
    # ==================================================================
    crx_must_keep = [
        ("N2-35「120种重疾+60种轻症」", "120种重疾+60种轻症"),
        ("N2-36「保障120种重疾+60种轻症，含身故责任」",
         "保障120种重疾+60种轻症，含身故责任"),
        ("N2-37「120种重疾，含轻症」", "120种重疾，含轻症"),
        ("N2-38「120种重疾+轻症保障」", "120种重疾+轻症保障"),
    ]
    for name, hl in crx_must_keep:
        got = PD._crx_disease_claim({"highlights": hl})
        check(f"F24.6 不得过度收紧「{name}」：轻症宣称正常产出",
              got != "", f"实际 {got!r}")

    # ⑥-b 除外指向**另一个保障对象**时，不得误伤轻症宣称
    other_object_cases = [
        ("N2-39「120种重疾+60种轻症，不保住院津贴」",
         "120种重疾+60种轻症，不保住院津贴"),
        ("N2-40「保障120种重疾+60种轻症，不含住院津贴」",
         "保障120种重疾+60种轻症，不含住院津贴"),
    ]
    for name, hl in other_object_cases:
        got = PD._crx_disease_claim({"highlights": hl})
        check(f"F24.6 不得过度收紧「{name}」：除外指向别的对象 → 轻症宣称正常产出",
              got != "", f"实际 {got!r}")

    # ==================================================================
    # ⑦ 源码级断言（防改回）
    # ==================================================================
    src = open(os.path.join(os.path.dirname(__file__), "plan_designer.py"),
               "r", encoding="utf-8").read()
    check("F24.7 源码级：统一除外标记集合已定义",
          "_CRX_EXCLUSION_MARKERS" in src)
    check("F24.7 源码级：head / tail 必须共用同一套标记集合",
          "_crx_clause_excludes_subject" in src)
    check("F24.7 源码级：矛盾陈述（记录级）压制已实现",
          "def _crx_record_contradiction(" in src)
    check("F24.7 源码级：_crx_disease_claim 必须过记录级矛盾闸",
          "_crx_record_contradiction(product" in src)
    check("F24.7 源码级：不得回退到只做 head.endswith 的前缀表",
          "head.endswith(mk)" not in src)

    return True


def test_f25_residual_o_disease_count_record_gate(pd=None):
    """F25（官方 SDI-4 残余 O · 2026-11-22 线上复扫 · v2.4.28 · Excessive Agency · MEDIUM）

    【官方 finding（两库原文逐字相同）】
      "Critical-illness disease-count claims bypass the documented record-wide
       contradiction check."

    【官方 remediation（ai 2.4.28 · 原文）】
      "Validate disease-count coverage across the entire product record before
       generating claims, rather than applying record-wide checks only to
       mild-illness coverage. Prefer a validated, structured disease-count
       decision with applicable conditions; suppress the count and report it as
       unverified when exclusions, uncertainty, or conflicting evidence remain
       unresolved. Add regression tests with affirmativ..."

    【官方 remediation（china 2.4.28 · 原文）】
      "Before emitting disease-count claims, reconcile evidence for
       critical-illness coverage and its count across the entire product
       record, rather than checking only mild-illness contradictions. Prefer
       validated structured coverage fields; suppress the count and report it
       as unverified when exclusions, conflicting counts, uncertainty, or
       uninterpretable conditions remain. Add regression tests that plac..."

    覆盖：
      ① 记录中含**病种数除外** → 压制（问题码 excluded）
      ② 记录中含**病种数适用条件** → 压制（问题码 conditional）
      ③ 记录中含**病种数不确定表述** → 压制（问题码 uncertain）
      ④ 记录内**病种数互相冲突** → 压制（问题码 conflicting-count）
      ⑤ 正常记录 → **仍产出**「120种重疾+轻症保障」（不得过度收紧）
      ⑥ **最终生成方案文案**不得出现被压制的病种数肯定宣称（走主流程）
      ⑦ 源码级防改回断言
      ⑧ 关键坑：「120种重疾不含轻症」的「不含」指向**轻症** → 不得当成病种数除外
    """
    print("\nTest F25: 病种数记录级矛盾校验（官方 SDI-4 残余 O）")
    if pd is None:
        import plan_designer as PD  # ai 版：模块级未 import，按 F24 既有写法局部导入
    else:
        PD = pd

    # ==================================================================
    # ① 记录中含**病种数除外** → 压制（官方：exclusions）
    # ==================================================================
    excluded_cases = [
        ("O-1 key_benefits「120种重疾除外」",
         {"highlights": "120种重疾+60种轻症", "key_benefits": ["120种重疾除外"]}),
        ("O-2 key_benefits「不保120种重疾」（head 侧除外）",
         {"highlights": "120种重疾+60种轻症", "key_benefits": ["不保120种重疾"]}),
        ("O-3 notes「120种重疾不在保障范围」",
         {"highlights": "120种重疾+60种轻症", "notes": "120种重疾不在保障范围"}),
        ("O-4 key_benefits「120种重疾不予赔付」",
         {"highlights": "120种重疾+60种轻症", "key_benefits": ["120种重疾不予赔付"]}),
        ("O-5 key_benefits「120种重疾不承保」",
         {"highlights": "120种重疾+60种轻症", "key_benefits": ["120种重疾不承保"]}),
    ]
    for name, prod in excluded_cases:
        got = PD._crx_disease_claim(prod)
        check(f"F25.1 病种数除外必须压制「{name}」", got == "", f"实际 {got!r}")
        check(f"F25.1 病种数除外问题码为 excluded「{name}」",
              PD._crx_record_disease_count_issue(prod, "120种重疾") == "excluded",
              "实际 %r" % (PD._crx_record_disease_count_issue(prod, "120种重疾"),))

    # ==================================================================
    # ② 记录中含**病种数适用条件** → 压制（官方：applicable conditions /
    #    uninterpretable conditions）
    # ==================================================================
    conditional_cases = [
        ("O-6 notes「120种重疾仅限指定医院」",
         {"highlights": "120种重疾+60种轻症", "notes": "120种重疾仅限指定医院"}),
        ("O-7 notes「120种重疾需转诊」",
         {"highlights": "120种重疾+60种轻症", "notes": "120种重疾需转诊"}),
        ("O-8 notes「120种重疾目录内」",
         {"highlights": "120种重疾+60种轻症", "notes": "120种重疾目录内"}),
        ("O-9 notes「重疾病种数量以核保结论为准」（泛化病种数 + 条件）",
         {"highlights": "120种重疾+60种轻症", "notes": "重疾病种数量仅限核保通过后适用"}),
    ]
    for name, prod in conditional_cases:
        got = PD._crx_disease_claim(prod)
        check(f"F25.2 病种数适用条件必须压制「{name}」", got == "", f"实际 {got!r}")
        check(f"F25.2 病种数条件问题码为 conditional「{name}」",
              PD._crx_record_disease_count_issue(prod, "120种重疾") == "conditional",
              "实际 %r" % (PD._crx_record_disease_count_issue(prod, "120种重疾"),))

    # ==================================================================
    # ③ 记录中含**病种数不确定表述** → 压制（官方：uncertainty）
    # ==================================================================
    uncertain_cases = [
        ("O-10 notes「是否承保120种重疾待核实」",
         {"highlights": "120种重疾+60种轻症", "notes": "是否承保120种重疾待核实"}),
        ("O-11 notes「120种重疾以保险合同为准」",
         {"highlights": "120种重疾+60种轻症", "notes": "120种重疾以保险合同为准"}),
        ("O-12 notes「重疾病种数量以合同为准」（泛化病种数 + 不确定）",
         {"highlights": "120种重疾+60种轻症", "notes": "重疾病种数量以合同为准"}),
    ]
    for name, prod in uncertain_cases:
        got = PD._crx_disease_claim(prod)
        check(f"F25.3 病种数不确定表述必须压制「{name}」", got == "", f"实际 {got!r}")
        check(f"F25.3 病种数不确定问题码为 uncertain「{name}」",
              PD._crx_record_disease_count_issue(prod, "120种重疾") == "uncertain",
              "实际 %r" % (PD._crx_record_disease_count_issue(prod, "120种重疾"),))

    # ==================================================================
    # ④ 记录内**病种数互相冲突** → 压制（官方：conflicting counts /
    #    conflicting evidence）
    # ==================================================================
    conflict_cases = [
        ("O-13 highlights「120种重疾」vs key_benefits「105种重疾」",
         {"highlights": "120种重疾+60种轻症", "key_benefits": ["105种重疾+50种轻症"]}),
        ("O-14 highlights「100种重疾」vs notes「120种重疾」",
         {"highlights": "100种重疾+50种轻症", "notes": "120种重疾"}),
        ("O-15 记录内三个病种数互相冲突",
         {"highlights": "120种重疾+60种轻症",
          "key_benefits": ["105种重疾+50种轻症"],
          "notes": "另有130种重疾版本"}),
    ]
    for name, prod in conflict_cases:
        got = PD._crx_disease_claim(prod)
        check(f"F25.4 记录内病种数冲突必须压制「{name}」", got == "", f"实际 {got!r}")
        check(f"F25.4 病种数冲突问题码为 conflicting-count「{name}」",
              PD._crx_record_disease_count_issue(prod, "120种重疾") == "conflicting-count",
              "实际 %r" % (PD._crx_record_disease_count_issue(prod, "120种重疾"),))
        check(f"F25.4 记录内病种数采集须含全部数值「{name}」",
              len(PD._crx_record_disease_counts(prod)) >= 2,
              "实际 %r" % (PD._crx_record_disease_counts(prod),))

    # ==================================================================
    # ⑤ 不得过度收紧：正常记录仍须产出「120种重疾+轻症保障」
    # ==================================================================
    keep_cases = [
        ("O-16「120种重疾+60种轻症」", {"highlights": "120种重疾+60种轻症"}),
        ("O-17「保障120种重疾+60种轻症，含身故责任」",
         {"highlights": "保障120种重疾+60种轻症，含身故责任"}),
        ("O-18「120种重疾，含轻症」", {"highlights": "120种重疾，含轻症"}),
        ("O-19「120种重疾+轻症保障」", {"highlights": "120种重疾+轻症保障"}),
        ("O-20「120种重疾+60种轻症」+ 其它字段同口径",
         {"highlights": "120种重疾+60种轻症", "key_benefits": ["120种重疾分6组最高赔6次"]}),
    ]
    for name, prod in keep_cases:
        got = PD._crx_disease_claim(prod)
        check(f"F25.5 不得过度收紧「{name}」：病种数宣称正常产出",
              got != "", f"实际 {got!r}")
        check(f"F25.5 不得过度收紧「{name}」：无问题码",
              PD._crx_record_disease_count_issue(prod, "120种重疾") == "",
              "实际 %r" % (PD._crx_record_disease_count_issue(prod, "120种重疾"),))

    # ==================================================================
    # ⑧ 关键坑：除外标记的**作用对象**不是病种数时不得误判
    #    （「120种重疾不含轻症」里的「不含」指向轻症 —— 官方交接点名的坑）
    # ==================================================================
    pitfall_cases = [
        ("O-21「120种重疾不含轻症」", "120种重疾不含轻症", False),
        ("O-22「120种重疾不含轻症疾病」", "120种重疾不含轻症疾病", False),
        ("O-23「120种重疾不含住院津贴」", "120种重疾不含住院津贴", False),
        ("O-24「120种重疾+60种轻症不含轻症」", "120种重疾+60种轻症不含轻症", False),
        ("O-25「不保120种重疾」（head 侧）", "不保120种重疾", True),
        ("O-26「120种重疾除外」（tail 侧）", "120种重疾除外", True),
        ("O-27「120种重疾不予赔付」（tail 侧）", "120种重疾不予赔付", True),
        ("O-28「120种重疾不在保障范围」（tail 侧）", "120种重疾不在保障范围", True),
    ]
    for name, clause, expect in pitfall_cases:
        got = PD._crx_clause_excludes_disease_count(clause, "120种重疾")
        check(f"F25.8 病种数专属除外判定「{name}」",
              got is expect, f"实际 {got!r} 期望 {expect!r}")
    # ⑧-b 复用既有判定会把「轻症除外」误当成「病种数除外」→ 源码级禁止
    src = open(os.path.join(os.path.dirname(__file__), "plan_designer.py"),
               "r", encoding="utf-8").read()
    check("F25.8 源码级：不得用既有 _crx_clause_excludes_subject 判病种数除外",
          '_crx_clause_excludes_subject(clause, "120种重疾")' not in src)
    check("F25.8 源码级：病种数专属判定必须接入记录级闸门",
          "_crx_clause_excludes_disease_count(clause, m.group(0))" in src)

    # ==================================================================
    # ⑥ **最终生成方案文案**校验（官方 remediation：checking the final
    #     generated plan）—— 不得只看中间函数返回值
    # ==================================================================
    products = PD.load_products()
    crx_real = next((p for p in products if p.get("type") == "重疾险"), None)
    check("F25.6 产品库存在重疾险（用例有效）", crx_real is not None,
          crx_real.get("name") if crx_real else "产品库无重疾险")

    if crx_real is not None:
        def _plan_text_for(highlights, key_benefits=None, extra=None):
            """把产品池里的重疾险换成指定字段 → 生成全部方案 → 返回文案"""
            adv = dict(crx_real)
            adv["highlights"] = highlights
            if key_benefits is not None:
                adv["key_benefits"] = key_benefits
            if extra:
                adv.update(extra)
            pool = [adv if p.get("type") == "重疾险" else p for p in products]
            orig = PD.load_products
            PD.load_products = lambda include_discontinued=False: list(pool)
            try:
                plans = PD.generate_all_plans(
                    35, "男", 300000, 200000,
                    {"death": 2000000, "critical_illness": 1500000,
                     "hospital": 4000000})
            finally:
                PD.load_products = orig
            chunks = []
            for _pname, plan in plans.items():
                if not plan:
                    continue
                for entry in (plan.get("products") or []):
                    if entry.get("type") == "重疾险":
                        chunks.append(str(entry.get("key_benefits") or ""))
                        chunks.append(str(entry.get("coverage_period") or ""))
                for feat in (plan.get("features") or []):
                    chunks.append(str(feat))
            return "\n".join(chunks)

        for name, hl, kb, extra in [
            ("O-29 病种数除外", "120种重疾+60种轻症", ["120种重疾除外"], None),
            ("O-30 病种数适用条件", "120种重疾+60种轻症", None,
             {"notes": "120种重疾仅限指定医院"}),
            ("O-31 病种数不确定", "120种重疾+60种轻症", None,
             {"notes": "是否承保120种重疾待核实"}),
            ("O-32 记录内病种数冲突", "120种重疾+60种轻症", ["105种重疾+50种轻症"], None),
        ]:
            text = _plan_text_for(hl, kb, extra)
            check(f"F25.6 最终方案文案不得出现「120种重疾+轻症保障」（{name}）",
                  "120种重疾+轻症保障" not in text,
                  "实际方案文案含该宣称" if "120种重疾+轻症保障" in text else "")
            check(f"F25.6 最终方案文案不得出现「轻症保障」（{name}）",
                  "轻症保障" not in text,
                  "实际方案文案含该宣称" if "轻症保障" in text else "")
            check(f"F25.6 最终方案须落回降级口径「重疾保障，确诊即赔付」（{name}）",
                  "重疾保障，确诊即赔付" in text,
                  f"实际方案文案={text[:200]!r}")

        # ⑥-b 正例：正常记录 → 最终方案**必须**继续产出病种数宣称（不得过度收紧）
        pos_text = _plan_text_for("120种重疾+60种轻症")
        check("F25.6 正例：最终方案仍须产出「120种重疾+轻症保障」（不得过度收紧）",
              "120种重疾+轻症保障" in pos_text,
              f"实际方案文案={pos_text[:200]!r}")

    # ==================================================================
    # ⑦ 源码级断言（防改回）
    # ==================================================================
    check("F25.7 源码级：病种数正则常量已定义",
          "_CRX_DISEASE_COUNT_RE" in src)
    check("F25.7 源码级：记录级病种数采集已实现",
          "def _crx_record_disease_counts(" in src)
    check("F25.7 源码级：病种数专属除外判定已实现",
          "def _crx_clause_excludes_disease_count(" in src)
    check("F25.7 源码级：病种数专属其它对象线索表已定义",
          "_CRX_COUNT_OTHER_OBJECT_CUES" in src)
    check("F25.7 源码级：记录级病种数闸门已实现",
          "def _crx_record_disease_count_issue(" in src)
    check("F25.7 源码级：_crx_disease_claim 必须过病种数记录级闸",
          "_crx_record_disease_count_issue(product" in src)
    check("F25.7 源码级：轻症既有记录级矛盾闸不得被移除",
          '_crx_record_contradiction(product, "轻症")' in src)
    _i_light = src.find('if _crx_record_contradiction(product, "轻症"):')
    _i_count = src.find("if _crx_record_disease_count_issue(product, m.group(0)):")
    check("F25.7 源码级：病种数闸门须在轻症矛盾闸之后",
          _i_light != -1 and _i_count != -1 and _i_count > _i_light,
          f"轻症闸位置={_i_light} 病种数闸位置={_i_count}")

    return True


def test_f26_residual_pq_subject_and_category_exclusion(pd=None):
    """F26（官方 SDI-4 残余 P + 残余 Q · 2026-11-22 线上复扫 · v2.4.30 · Excessive Agency · MEDIUM）

    【官方 finding · 残余 P（china v2.4.30 · L2115-2122 · 原文）】
      "The mild-illness exclusion guard can mistake the excluded subject's own
       wording for another coverage object."

    【官方 finding · 残余 P（ai v2.4.30 · L2119-2125 · 原文）】
      "The mild-illness exclusion guard can convert an explicit exclusion into an
       affirmative benefit claim."

    【官方 remediation · 残余 P（ai v2.4.30 · 原文）】
      "Replace keyword-presence authorization with validated, structured mild-illness
       coverage decisions, preserving applicable conditions and suppressing unresolved
       claims. If free-text parsing remains necessary, recognize「轻症疾病」as the same
       coverage subject as「轻症」rather than treating「疾病」as a different object, and
       handle exclusions consistently before and after that subject. Add regression tests
       for「120种重疾，轻症疾病不保」and similar variants, asserting that the final
       generated plans never claim mild-illness coverage."

    【官方 finding · 残余 Q（china v2.4.29/2.4.30 · L2364-2387 · 原文）】
      "Disease-count claims bypass record-wide exclusions that omit the numeric count."

    【官方 finding · 残余 Q（ai v2.4.29 · L2368-2391 · 原文）】
      "The documented record-wide disease-count safeguard misses exclusions of
       critical-illness coverage when they do not repeat the numeric count."

    【官方 remediation · 残余 Q（china v2.4.29/2.4.30 · 原文）】
      "Validate critical-illness coverage and disease count separately across the entire
       product record, binding exclusions to the underlying coverage category even when
       no number is present. Suppress unsupported claims and explicitly report unresolved
       evidence as unverified; ensure fallback benefit text does not continue asserting
       excluded coverage. Add end-to-end regression tests combining affirmative counted
       highlights with nonnumeric exclusions in other fields and verify the final plan output."

    覆盖：
      ① 同句「120种重疾，轻症疾病不保」→ 轻症宣称被压制
      ② 跨字段（highlights 肯定 + key_benefits 除外）→ 轻症宣称被压制
      ③ head 侧 / tail 侧除外 → 前后一致
      ④ 正常对照「轻症疾病保险金」（利益名称）→ 轻症宣称**正常产出**
      ⑤ 既有 F25.1「120种重疾不含轻症」语义不被破坏
      ⑥ 类别级（无数字）重疾除外 → 病种数宣称被压制
      ⑦ 同字段「含120种重疾」+「重疾疾病不保」→ 病种数宣称被压制
      ⑧ 正常对照（无除外）→ 病种数宣称正常产出
      ⑨ 类别级除外时**兜底文案**不得继续断言被除外保障
      ⑩ 防过度收紧：「续保不保证」「身故则不赔付」「等待期内…不赔付」
      ⑪ 源码级防改回断言（关键常量 / 函数存在 + 调用顺序）
    """
    print("\nTest F26: 残余 P（轻症疾病 = 轻症 同一 subject）+ 残余 Q（类别级重疾除外）")
    if pd is None:
        import plan_designer as PD
        PD = PD
    else:
        PD = pd

    # ── 官方 remediation（china P / china Q / ai Q 原文）要求
    #   「assert the final generated plan」/「checking final plan benefits
    #    rather than only helper outputs」→ 必须**走主流程**校验最终方案文案。
    def _plan_text_for(highlights, key_benefits=None, extra=None):
        """把产品池里的重疾险换成指定字段 → 生成全部方案 → 返回文案"""
        pool_products = PD.load_products()
        crx_real = next((p for p in pool_products if p.get("type") == "重疾险"), None)
        if crx_real is None:
            return ""
        adv = dict(crx_real)
        adv["highlights"] = highlights
        if key_benefits is not None:
            adv["key_benefits"] = key_benefits
        if extra:
            adv.update(extra)
        pool = [adv if p.get("type") == "重疾险" else p for p in pool_products]
        orig = PD.load_products
        PD.load_products = lambda include_discontinued=False: list(pool)
        try:
            plans = PD.generate_all_plans(
                35, "男", 300000, 200000,
                {"death": 2000000, "critical_illness": 1500000,
                 "hospital": 4000000})
        finally:
            PD.load_products = orig
        chunks = []
        for _pname, plan in plans.items():
            if not plan:
                continue
            for entry in (plan.get("products") or []):
                if entry.get("type") == "重疾险":
                    chunks.append(str(entry.get("key_benefits") or ""))
                    chunks.append(str(entry.get("coverage_period") or ""))
            for feat in (plan.get("features") or []):
                chunks.append(str(feat))
        return "\n".join(chunks)

    # ==================================================================
    # ① F26.1 同句：「120种重疾，轻症疾病不保」→ 轻症宣称被压制
    # ==================================================================
    same_clause = [
        ("P-1「120种重疾，轻症疾病不保」",
         {"highlights": "120种重疾+轻症保障",
          "key_benefits": ["120种重疾，轻症疾病不保"]}),
        ("P-2「120种重疾，轻症疾病不予赔付」",
         {"highlights": "120种重疾+轻症保障",
          "key_benefits": ["120种重疾，轻症疾病不予赔付"]}),
    ]
    for name, prod in same_clause:
        got = PD._crx_disease_claim(prod)
        check(f"F26.1 同句轻症疾病除外必须压制「{name}」", got == "", f"实际 {got!r}")
    # 官方 remediation（ai P 原文）：「asserting that the final generated plans
    #   never claim mild-illness coverage」→ 走**主流程**校验最终方案文案
    _plan_p = _plan_text_for("120种重疾+轻症保障", ["120种重疾，轻症疾病不保"])
    check("F26.1 最终生成方案不得宣称「120种重疾+轻症保障」（残余 P）",
          "120种重疾+轻症保障" not in _plan_p,
          "最终方案文案含该宣称" if "120种重疾+轻症保障" in _plan_p else "")
    check("F26.1 最终生成方案不得宣称「轻症保障」（残余 P）",
          "轻症保障" not in _plan_p,
          "最终方案文案含该宣称" if "轻症保障" in _plan_p else "")
    # ⚠ 主侧 2026-11-23 补充实测：断言必须是**非退化**的 ——
    #   高lights 若不含「轻症」/ 不含「N种重疾」，`_crx_disease_claim` 天然返回
    #   '' → 断言恒真。故本组必须自检「去掉除外句后同一形状能产出宣称」。
    _ctl_p = PD._crx_disease_claim({"highlights": "120种重疾+轻症保障"})
    check("F26.1 用例有效性自检：无除外对照必须产出轻症宣称",
          _ctl_p == "120种重疾+轻症保障", f"实际 {_ctl_p!r}")

    # ==================================================================
    # ② F26.2 跨字段：highlights 肯定 + key_benefits 除外 → 轻症宣称被压制
    # ==================================================================
    cross_field = [
        ("P-3 跨字段 key_benefits「轻症疾病不保」",
         {"highlights": "120种重疾+轻症保障", "key_benefits": ["轻症疾病不保"]}),
        ("P-4 跨字段 notes「轻症疾病不保」",
         {"highlights": "120种重疾+轻症保障", "notes": "轻症疾病不保"}),
    ]
    for name, prod in cross_field:
        got = PD._crx_disease_claim(prod)
        check(f"F26.2 跨字段轻症疾病除外必须压制「{name}」", got == "", f"实际 {got!r}")
    _ctl_p2 = PD._crx_disease_claim({"highlights": "120种重疾+轻症保障",
                                      "key_benefits": ["含60种轻症"]})
    check("F26.2 用例有效性自检：无除外对照必须产出轻症宣称",
          _ctl_p2 == "120种重疾+轻症保障", f"实际 {_ctl_p2!r}")

    # ==================================================================
    # ③ F26.3 head 侧 / tail 侧除外 → 前后一致
    # ==================================================================
    head_tail = [
        ("P-5 head 侧「不保轻症疾病」",
         {"highlights": "120种重疾+轻症保障", "key_benefits": ["不保轻症疾病"]}),
        ("P-6 head 侧「轻症疾病不予赔付」（tail 侧标记 + 前置除外）",
         {"highlights": "120种重疾+轻症保障", "key_benefits": ["轻症疾病不予赔付"]}),
        ("P-7 tail 侧「轻症疾病不保，120种重疾」",
         {"highlights": "120种重疾+轻症保障",
          "key_benefits": ["轻症疾病不保，120种重疾"]}),
    ]
    for name, prod in head_tail:
        got = PD._crx_disease_claim(prod)
        check(f"F26.3 subject 前后除外必须一致压制「{name}」", got == "", f"实际 {got!r}")
    _ctl_p3 = PD._crx_disease_claim({"highlights": "120种重疾+轻症保障",
                                     "key_benefits": ["含60种轻症保障"]})
    check("F26.3 用例有效性自检：无除外对照必须产出轻症宣称",
          _ctl_p3 == "120种重疾+轻症保障", f"实际 {_ctl_p3!r}")

    # ==================================================================
    # ④ F26.4 正常对照：利益名称（非除外）→ 轻症宣称**正常产出**
    # ==================================================================
    keep_cases = [
        ("P-8「轻症疾病保险金」（利益名称）",
         {"highlights": "120种重疾+轻症保障", "key_benefits": ["轻症疾病保险金"]}),
        ("P-9「轻症特定疾病保险金」（利益名称）",
         {"highlights": "120种重疾+轻症保障", "key_benefits": ["轻症特定疾病保险金"]}),
        ("P-10 正常对照「120种重疾+轻症保障」",
         {"highlights": "120种重疾+轻症保障"}),
        # ⚠ 主侧 2026-11-23 补充实测：利益名称若只出现在 key_benefits 且
        #   highlights 不含「N种重疾」→ claim 天然为 '' → 断言会恒空；
        #   故必须补 highlights 形态（highlights 本身含「轻症疾病保险金」）。
        ("P-11 highlights「120种重疾+轻症疾病保险金」（利益名称在 highlights）",
         {"highlights": "120种重疾+轻症疾病保险金"}),
        ("P-12 highlights「含120种重疾+轻症疾病保险金」（利益名称在 highlights）",
         {"highlights": "含120种重疾+轻症疾病保险金"}),
    ]
    for name, prod in keep_cases:
        got = PD._crx_disease_claim(prod)
        check(f"F26.4 不得过度收紧「{name}」：轻症宣称正常产出",
              got != "" and "轻症" in got, f"实际 {got!r}")

    # ==================================================================
    # ⑤ F26.5 既有 F25.1「120种重疾不含轻症」语义不被破坏
    #    （「不含」的宾语是**轻症** → 不是病种数除外 → 病种数本身仍成立；
    #      轻症被除外 → 组合宣称「N种重疾+轻症保障」整体压制属**既有**语义，
    #      本项只校验「病种数未被除外」）
    # ==================================================================
    got = PD._crx_clause_excludes_disease_count("120种重疾不含轻症", "120种重疾")
    check("F26.5 既有 F25.1 语义不被破坏：「不含轻症」不算病种数除外",
          got is False, f"实际 {got!r}")
    code = PD._crx_record_disease_count_issue({"highlights": "120种重疾+60种轻症",
                                               "key_benefits": ["120种重疾不含轻症"]},
                                              "120种重疾")
    check("F26.5 既有 F25.1 语义不被破坏：记录级病种数闸门不报 excluded",
          code not in ("excluded", "category-excluded"), f"实际问题码 {code!r}")
    got = PD._crx_disease_claim({"highlights": "120种重疾+轻症保障",
                                 "key_benefits": ["120种重疾不含轻症"]})
    check("F26.5 既有 F25.1 语义不被破坏：轻症被除外 → 组合宣称仍压制",
          got == "", f"实际 {got!r}")
    got = PD._crx_disease_claim({"highlights": "含120种重疾，重症不含轻症"})
    check("F26.5 既有 F25.1 语义不被破坏：「含120种重疾，重症不含轻症」天然压制",
          got == "", f"实际 {got!r}")
    code = PD._crx_record_disease_count_issue(
        {"highlights": "含120种重疾，重症不含轻症"}, "120种重疾")
    check("F26.5 既有 F25.1 语义不被破坏：「不含轻症」不算类别级除外",
          code not in ("excluded", "category-excluded"), f"实际问题码 {code!r}")

    # ==================================================================
    # ⑥ F26.6 类别级（无数字）重疾除外 → 病种数宣称被压制
    # ==================================================================
    category_excluded = [
        ("Q-1 另一字段「重疾疾病不保」（无数字）",
         {"highlights": "120种重疾+轻症保障", "key_benefits": ["重疾疾病不保"]}),
        ("Q-2 另一字段「重大疾病责任免除」（无数字）",
         {"highlights": "120种重疾+轻症保障", "key_benefits": ["重大疾病责任免除"]}),
        ("Q-3 另一字段「重疾疾病不在保障范围」（无数字）",
         {"highlights": "120种重疾+轻症保障", "key_benefits": ["重疾疾病不在保障范围"]}),
        ("Q-4 另一字段「重疾疾病不予赔付」（无数字）",
         {"highlights": "120种重疾+轻症保障", "key_benefits": ["重疾疾病不予赔付"]}),
    ]
    for name, prod in category_excluded:
        got = PD._crx_disease_claim(prod)
        check(f"F26.6 类别级重疾除外必须压制病种数「{name}」",
              got == "" or "重疾" not in got, f"实际 {got!r}")
        check(f"F26.6 类别级除外问题码为 category-excluded「{name}」",
              PD._crx_record_disease_count_issue(prod, "120种重疾") == "category-excluded",
              "实际 %r" % (PD._crx_record_disease_count_issue(prod, "120种重疾"),))
    # ⚠ 主侧 2026-11-23 补充实测：highlights 必须带「120种重疾+轻症保障」
    #   （不带「轻症」时 claim 恒为 '' → 断言恒真）→ 用无除外对照自检用例有效性
    _ctl_q = PD._crx_disease_claim({"highlights": "120种重疾+轻症保障"})
    check("F26.6 用例有效性自检：无除外对照必须产出病种数宣称",
          _ctl_q == "120种重疾+轻症保障", f"实际 {_ctl_q!r}")

    # ==================================================================
    # ⑦ F26.7 同字段「含120种重疾」+「重疾疾病不保」→ 病种数宣称被压制
    # ==================================================================
    same_field_cases = [
        ("Q-5 同字段 key_benefits「含120种重疾」+「重疾疾病不保」",
         {"highlights": "120种重疾+轻症保障",
          "key_benefits": ["含120种重疾", "重疾疾病不保"]}),
        ("Q-6 同字段「120种重疾+轻症保障」+「重疾疾病不保」",
         {"highlights": "120种重疾+轻症保障+重疾疾病不保"}),
    ]
    for name, prod in same_field_cases:
        got = PD._crx_disease_claim(prod)
        check(f"F26.7 同字段类别级除外必须压制「{name}」",
              got == "" or "重疾" not in got, f"实际 {got!r}")
    _ctl_q7 = PD._crx_disease_claim({"highlights": "120种重疾+轻症保障",
                                      "key_benefits": ["含120种重疾"]})
    check("F26.7 用例有效性自检：无除外对照必须产出病种数宣称",
          _ctl_q7 == "120种重疾+轻症保障", f"实际 {_ctl_q7!r}")

    # ==================================================================
    # ⑧ F26.8 正常对照（无除外）→ 病种数宣称正常产出
    # ==================================================================
    got = PD._crx_disease_claim({"highlights": "120种重疾+轻症保障"})
    check("F26.8 正常对照（无除外）：病种数宣称正常产出",
          got == "120种重疾+轻症保障", f"实际 {got!r}")
    check("F26.8 正常对照（无除外）：无问题码",
          PD._crx_record_disease_count_issue({"highlights": "120种重疾+轻症保障"},
                                             "120种重疾") == "",
          "实际 %r" % (PD._crx_record_disease_count_issue(
              {"highlights": "120种重疾+轻症保障"}, "120种重疾"),))

    # ==================================================================
    # ⑨ F26.9 类别级除外时兜底文案不得继续断言被除外保障
    # ==================================================================
    prod_q = {"highlights": "120种重疾+轻症保障", "key_benefits": ["重疾疾病不保"]}
    fb = PD._crx_key_benefits(prod_q, 500000, "standard")
    check("F26.9 类别级除外时兜底文案不得断言「N种重疾」",
          not re.search(r"\d+\s*种重疾", fb or ""), f"实际 {fb!r}")
    check("F26.9 类别级除外时兜底文案不得断言「重疾保障」",
          "重疾保障" not in (fb or ""), f"实际 {fb!r}")
    check("F26.9 类别级除外时兜底文案不得断言「确诊即赔付」",
          "确诊即赔付" not in (fb or ""), f"实际 {fb!r}")
    lim = PD._crx_ci_category_limitation(prod_q)
    check("F26.9 类别级除外时须如实报告限制（unverified）",
          isinstance(lim, dict) and lim.get("product_type") == "重疾险",
          f"实际 {lim!r}")
    check("F26.9 正常对照不得产生限制",
          PD._crx_ci_category_limitation({"highlights": "120种重疾+轻症保障"}) is None)
    # 官方 remediation（china Q / ai Q 原文）：「assert the final generated plan」
    #   → 走**主流程**校验最终方案文案不得继续断言被除外的保障
    _plan_q = _plan_text_for("120种重疾+轻症保障", ["重疾疾病不保"])
    check("F26.9 最终生成方案不得宣称「120种重疾+轻症保障」（残余 Q）",
          "120种重疾+轻症保障" not in _plan_q,
          "最终方案文案含该宣称" if "120种重疾+轻症保障" in _plan_q else "")
    check("F26.9 最终生成方案不得继续断言被除外保障「重疾保障，确诊即赔付」（残余 Q）",
          "重疾保障，确诊即赔付" not in _plan_q,
          "最终方案文案含该兜底宣称" if "重疾保障，确诊即赔付" in _plan_q else "")

    # ==================================================================
    # ⑩ F26.10 防过度收紧：下列句子不得被当成类别级重疾除外
    # ==================================================================
    not_category_exclusion = [
        ("恒大人寿重疾保险续保不保证，保费随年龄增加。",
         {"highlights": "120种重疾+轻症保障",
          "key_benefits": ["恒大人寿重疾保险续保不保证，保费随年龄增加。"]}),
        ("国华人寿重大疾病保险续保不保证，保费随年龄增加。",
         {"highlights": "120种重疾+轻症保障",
          "key_benefits": ["国华人寿重大疾病保险续保不保证，保费随年龄增加。"]}),
        ("康福重疾险可能不保证续保。",
         {"highlights": "120种重疾+轻症保障",
          "key_benefits": ["康福重疾险可能不保证续保。"]}),
        ("若未达到重疾标准身故则不赔付",
         {"highlights": "120种重疾+轻症保障",
          "key_benefits": ["若未达到重疾标准身故则不赔付"]}),
        ("等待期为90天，未满期内轻重疾病不赔付。",
         {"highlights": "120种重疾+轻症保障",
          "key_benefits": ["等待期为90天，未满期内轻重疾病不赔付。"]}),
        ("安心保险安福人生重大疾病保险不需要体检，仅需健康告知。",
         {"highlights": "120种重疾+轻症保障",
          "key_benefits": ["安心保险安福人生重大疾病保险不需要体检，仅需健康告知。"]}),
        ("120种重疾不含轻症（既有 F25.1 语义）",
         {"highlights": "120种重疾+轻症保障",
          "key_benefits": ["120种重疾不含轻症"]}),
    ]
    for text, prod in not_category_exclusion:
        got = PD._crx_disease_claim(prod)
        if text.startswith("120种重疾不含轻症"):
            # 既有 F25.1 语义：轻症被除外 → 组合宣称压制（**不是**类别级除外所致）
            check(f"F26.10 不得当成类别级除外「{text[:24]}」：类别级判定不触发",
                  PD._crx_record_ci_category_excluded(prod) is False)
            continue
        check(f"F26.10 不得当成类别级除外「{text[:24]}」：宣称须保留",
              "120种重疾" in got, f"实际 {got!r}")

    # ==================================================================
    # ⑪ F26.11 源码级防改回断言
    # ==================================================================
    src = open(os.path.join(os.path.dirname(__file__), "plan_designer.py"),
               "r", encoding="utf-8").read()
    check("F26.11 源码级：subject 自身宾语尾巴常量已定义",
          "_CRX_SUBJECT_OWN_TAILS" in src)
    check("F26.11 源码级：subject span 归一化函数已定义",
          "def _crx_subject_span_end(" in src)
    check("F26.11 源码级：除外判定必须用 subject span（不得回退到裸 occ+len）",
          "_crx_subject_span_end(clause, occ, subject)" in src)
    check("F26.11 源码级：类别级重疾常量表已定义",
          "_CRX_CI_CATEGORY_TOKENS" in src)
    check("F26.11 源码级：类别级除外其它对象线索表已定义",
          "_CRX_CI_OTHER_OBJECT_CUES" in src)
    check("F26.11 源码级：类别级除外判定函数已定义",
          "def _crx_clause_excludes_ci_category(" in src)
    check("F26.11 源码级：记录级类别级除外判定已实现",
          "def _crx_record_ci_category_excluded(" in src)
    check("F26.11 源码级：记录级病种数闸门必须接入类别级判定",
          "_crx_record_ci_category_excluded(product)" in src)
    check("F26.11 源码级：兜底文案必须过类别级除外闸",
          "_crx_record_ci_category_excluded(product)" in src
          and "def _crx_ci_category_limitation(" in src)
    _i_light = src.find('if _crx_record_contradiction(product, "轻症"):')
    _i_count = src.find("if _crx_record_disease_count_issue(product, m.group(0)):")
    check("F26.11 源码级：轻症矛盾闸须在病种数记录级闸之前",
          _i_light != -1 and _i_count != -1 and _i_light < _i_count,
          f"轻症闸={_i_light} 病种数闸={_i_count}")
    # 类别级闸门必须**落在记录级病种数闸门函数内部**，且在冲突病种数检查之后
    _i_gate = src.find("def _crx_record_disease_count_issue(")
    _i_gate_end = src.find("\ndef ", _i_gate + 10)
    _i_cat = src.find("if _crx_record_ci_category_excluded(product):", _i_gate)
    _i_conflict = src.find('return "conflicting-count"', _i_gate)
    check("F26.11 源码级：类别级闸门须落在记录级病种数闸门函数内",
          _i_gate != -1 and _i_cat != -1 and _i_gate_end != -1
          and _i_gate < _i_cat < _i_gate_end,
          f"闸门定义={_i_gate} 类别闸={_i_cat} 函数结束={_i_gate_end}")
    check("F26.11 源码级：类别级闸门须在冲突病种数检查之后",
          _i_conflict != -1 and _i_cat != -1 and _i_conflict < _i_cat,
          f"冲突检查={_i_conflict} 类别闸={_i_cat}")

    return True


# ---------------------------------------------------------------------------
# F27 · 官方 SDI-4 残余 R（2026-11-23 线上复扫 · v2.4.32 · Excessive Agency · MEDIUM）
# ---------------------------------------------------------------------------
def test_f27_residual_r_shared_coverage_state(pd=None):
    """F27（官方 SDI-4 残余 R · 2026-11-23 线上复扫 · v2.4.32 · Excessive Agency · MEDIUM）

    【官方 finding · 残余 R-1（china v2.4.32 · L2225-2232 · 原文）】
      "The mild-illness exclusion guard still treats the excluded benefit's own
       payment wording as another coverage object."

    【官方 remediation · 残余 R-1（china v2.4.32 · 原文）】
      "Prefer explicitly validated, structured mild-illness coverage decisions
       rather than keyword-presence authorization. If free-text parsing remains
       necessary, recognize payment and benefit-responsibility wording as part of
       the same coverage subject, bind exclusions consistently in both directions,
       and suppress unresolved interpretations. Add regression tests for
       「轻症给付责任除外」, related payment-wording variants, and conflicting fields,
       asserting that final generated plans never advertise excluded mild-illness coverage."

    【官方 finding · 残余 R-2（china v2.4.32 · L2779-2795 · 原文）】
      "Critical-illness exclusion suppression is bypassed by premium benefits and plan features."

    【官方 remediation · 残余 R-2（china v2.4.32 · 原文）】
      "Compute a shared, validated critical-illness coverage state before generating any
       benefits, features, or descriptions. Apply exclusion and unresolved-conflict
       suppression to both standard and premium branches and every downstream claim
       surface, preserving an explicit unverified limitation instead. Add end-to-end
       tests with category-level exclusions that verify the final JSON contains no
       affirmative claims about the excluded coverage."

    覆盖：
      ① 轻症给付措辞除外（后向 + 前向）→ 轻症保障不得被宣称
      ② 红线：带给付措辞但**无除外语义**的真实子句不得被误判（不得过度收紧）
      ③ 类别级除外 → standard / premium 两个分支都必须为空串
      ④ 类别级除外 → features 不得宣称「确诊即赔付」/「终身保障」
      ⑤ 类别级除外 → 方案 description 不得宣称「含重疾保障」
      ⑥ 类别级除外 → 限制文案（unverified）必须保留（**不得**一起删掉）
      ⑦ 端到端：最终方案 JSON 不得含被除外保障的肯定宣称
      ⑧ 无除外记录 → 一切宣称保持原样（零变化）
      ⑨ 源码级防改回断言（共享状态必须先于任何宣称生成）
    """
    print("\nTest F27: 残余 R（轻症给付措辞除外 + 共享重疾保障已验证状态）")
    if pd is None:
        import plan_designer as PD
        PD = PD
    else:
        PD = pd

    # ==================================================================
    # ① F27.1 轻症给付措辞的除外（后向 + 前向）→ 轻症保障不得被宣称
    # ==================================================================
    payment_exclusion_clauses = [
        ("轻症给付责任除外", "后向：主体 → 标记"),
        ("轻症保险金责任除外", "后向：主体 → 标记"),
        ("轻症给付责任不承担", "后向：主体 → 标记"),
        ("轻症给付责任不予赔付", "后向：主体 → 标记"),
        ("给付责任不保轻症", "前向：标记 → 主体"),
        ("保险金责任不保轻症", "前向：标记 → 主体"),
    ]
    for clause, direction in payment_exclusion_clauses:
        excl = PD._crx_clause_excludes_subject(clause, "轻症")
        check(f"F27.1 轻症给付措辞除外必须被识别（{direction}）「{clause}」",
              excl is True, f"实际 {excl!r}")
        prod = {"name": "T", "highlights": f"120种重疾+轻症疾病保险金，{clause}"}
        kb = PD._crx_key_benefits(prod, 500000, "standard")
        check(f"F27.1 被除外的轻症保障不得被宣称「{clause}」",
              "轻症" not in (kb or ""), f"实际 {kb!r}")
    # ⚠ 用例有效性自检：同一形状但**无除外**时必须产出轻症宣称
    #   （否则本组断言恒真 → 测了个寂寞）
    _ctl = PD._crx_key_benefits(
        {"name": "T", "highlights": "120种重疾+轻症疾病保险金，40种轻症赔20%x6次"},
        500000, "standard")
    check("F27.1 用例有效性自检：无除外对照必须产出轻症宣称",
          "轻症" in (_ctl or ""), f"实际 {_ctl!r}")

    # ==================================================================
    # ② F27.2 红线：带给付措辞但**无除外语义**的真实子句不得被误判
    #    （真实语料 260 条：如「轻症赔付比例25%」「40种轻症赔20%x6次」
    #      「轻症/中介阶梯式赔付」「被保险人轻症/重症豁免」）
    # ==================================================================
    benign_clauses = [
        "轻症赔付比例25%",
        "40种轻症赔20%x6次",
        "轻症/中介阶梯式赔付",
        "被保险人轻症/重症豁免",
        "轻症赔付3次",
        "特定心脑血管二次赔付80%",
    ]
    for clause in benign_clauses:
        excl = PD._crx_clause_excludes_subject(clause, "轻症")
        check(f"F27.2 不得把带给付措辞的正常表述误判为除外「{clause}」",
              excl is False, f"实际 {excl!r}")
        prod = {"name": "T", "highlights": f"120种重疾+轻症疾病保险金，{clause}"}
        kb = PD._crx_key_benefits(prod, 500000, "standard")
        check(f"F27.2 不得过度收紧「{clause}」：轻症宣称仍须产出",
              "轻症" in (kb or ""), f"实际 {kb!r}")

    # ==================================================================
    # ③ F27.3 类别级除外 → standard / premium 两个分支都必须为空串
    # ==================================================================
    category_excluded_highlights = [
        ("带病种数 + 类别级除外", "120种重疾+轻症疾病保险金，重疾疾病不保"),
        ("无数字类别级除外", "重大疾病责任免除"),
    ]
    for tag, hl in category_excluded_highlights:
        prod = {"name": "T", "highlights": hl}
        for style in ("standard", "premium"):
            kb = PD._crx_key_benefits(prod, 500000, style)
            check(f"F27.3 类别级除外时 {style} 样式不得产出肯定宣称（{tag}）",
                  kb == "", f"实际 {kb!r}")
    _ctl3 = PD._crx_key_benefits({"name": "T", "highlights": "120种重疾+轻症疾病保险金"},
                                 500000, "standard")
    check("F27.3 用例有效性自检：无除外对照必须产出宣称",
          _ctl3 != "", f"实际 {_ctl3!r}")

    # ==================================================================
    # ④ F27.4 类别级除外 → features 不得宣称「确诊即赔付」/「终身保障」
    # ==================================================================
    for tag, hl in category_excluded_highlights:
        feat = PD._crx_feature({"name": "T", "highlights": hl})
        leak = any(c in feat for c in ("确诊即赔付", "终身保障", "重疾多次赔付"))
        check(f"F27.4 类别级除外时 features 不得宣称重疾利益（{tag}）",
              not leak, f"实际 {feat!r}")
    _ctl4 = PD._crx_feature({"name": "T", "highlights": "120种重疾+轻症疾病保险金"})
    check("F27.4 用例有效性自检：无除外对照 features 仍须宣称重疾利益",
          "确诊即赔付" in _ctl4, f"实际 {_ctl4!r}")

    # ==================================================================
    # ⑤ F27.5 类别级除外 → 方案 description 不得宣称「含重疾保障」
    # ==================================================================
    _entries = [{"type": "重疾险", "product_name": "T"},
                {"type": "医疗险", "product_name": "M"}]
    _records_excluded = [{"name": "T", "type": "重疾险", "highlights": "重大疾病责任免除"},
                          {"name": "M", "type": "医疗险"}]
    _desc_std = PD._build_plan_description("标准版", _entries, _records_excluded)
    check("F27.5 类别级除外时标准版描述不得宣称「含重疾保障」",
          "含重疾保障" not in _desc_std, f"实际 {_desc_std!r}")
    check("F27.5 类别级除外时标准版描述不得把重疾保障列入保障范围",
          "重疾保障" not in _desc_std, f"实际 {_desc_std!r}")
    _desc_prem = PD._build_plan_description("全面版", _entries, _records_excluded)
    check("F27.5 类别级除外时全面版描述不得宣称「含重疾保障」",
          "含重疾保障" not in _desc_prem and "重疾保障" not in _desc_prem,
          f"实际 {_desc_prem!r}")
    _ctl5 = PD._build_plan_description(
        "标准版", _entries,
        [{"name": "T", "type": "重疾险", "highlights": "120种重疾+轻症疾病保险金"},
         {"name": "M", "type": "医疗险"}])
    check("F27.5 用例有效性自检：无除外对照描述须保留「含重疾保障」",
          "含重疾保障" in _ctl5, f"实际 {_ctl5!r}")

    # ==================================================================
    # ⑥ F27.6 类别级除外 → 限制文案（unverified）必须保留
    #    官方 remediation 原文：「preserving an explicit unverified limitation
    #    instead」/「report the unresolved responsibility explicitly as unverified」
    # ==================================================================
    _lim = PD._crx_ci_category_limitation({"name": "T", "highlights": "重大疾病责任免除"})
    check("F27.6 类别级除外时限制文案必须保留（官方要求 report as unverified）",
          isinstance(_lim, dict) and _lim.get("product_type") == "重疾险",
          f"实际 {_lim!r}")
    check("F27.6 无除外记录时不得凭空产生限制",
          PD._crx_ci_category_limitation(
              {"name": "T", "highlights": "120种重疾+轻症疾病保险金"}) is None)

    # ==================================================================
    # ⑦ F27.7 端到端：最终方案 JSON 不得含被除外保障的肯定宣称
    #    官方 remediation 原文：「verify the final JSON contains no affirmative
    #    claims about the excluded coverage」
    # ==================================================================
    def _plan_text_for(highlights):
        """把产品池里的重疾险换成指定 highlights → 生成全部方案 → 返回文案"""
        pool_products = PD.load_products()
        crx_real = next((p for p in pool_products if p.get("type") == "重疾险"), None)
        if crx_real is None:
            return "", []
        adv = dict(crx_real)
        adv["highlights"] = highlights
        pool = [adv if p.get("type") == "重疾险" else p for p in pool_products]
        orig = PD.load_products
        PD.load_products = lambda include_discontinued=False: list(pool)
        try:
            plans = PD.generate_all_plans(
                35, "男", 300000, 200000,
                {"death": 2000000, "critical_illness": 1500000,
                 "hospital": 4000000})
        finally:
            PD.load_products = orig
        chunks = []
        for _pname, plan in plans.items():
            if not plan:
                continue
            chunks.append(str(plan.get("description") or ""))
            for entry in (plan.get("products") or []):
                chunks.append(str(entry.get("key_benefits") or ""))
            for feat in (plan.get("features") or []):
                chunks.append(str(feat))
        return "\n".join(chunks), plans

    _txt_excl, _plans_excl = _plan_text_for("120种重疾+轻症疾病保险金，重疾疾病不保")
    for _bad in ("确诊即赔付", "含重疾保障", "重疾多次赔付",
                 "重疾险保额高达年收入5倍", "寿险+重疾"):
        check(f"F27.7 最终方案 JSON 不得含被除外保障的肯定宣称「{_bad}」",
              _bad not in _txt_excl,
              f"最终方案文案含该宣称" if _bad in _txt_excl else "")
    # 被除外产品的 key_benefits 必须为空串（不得继续断言被除外保障）
    _kb_leak = []
    for _pname, _plan in (_plans_excl or {}).items():
        if not _plan:
            continue
        for _entry in (_plan.get("products") or []):
            if _entry.get("type") == "重疾险" and (_entry.get("key_benefits") or ""):
                _kb_leak.append(f"{_pname}:{_entry.get('key_benefits')!r}")
    check("F27.7 最终方案内重疾险条目的 key_benefits 必须为空串",
          not _kb_leak, "；".join(_kb_leak))
    # 限制必须如实出现在方案层（unverified 不得静默丢失）
    _lim_found = False
    for _pname, _plan in (_plans_excl or {}).items():
        if not _plan:
            continue
        for _l in (_plan.get("limitations") or []):
            if isinstance(_l, dict) and _l.get("product_type") == "重疾险":
                _lim_found = True
    check("F27.7 最终方案必须如实报告重疾保障限制（unverified）", _lim_found)
    # ⚠ 用例有效性自检：同一流程但**无除外**时必须仍有肯定宣称
    _txt_clean, _plans_clean = _plan_text_for("120种重疾+轻症疾病保险金")
    check("F27.7 用例有效性自检：无除外对照最终方案仍须有肯定宣称",
          "确诊即赔付" in _txt_clean, "最终方案文案无肯定宣称")

    # ==================================================================
    # ⑧ F27.8 无除外记录 → 一切宣称保持原样（零变化）
    # ==================================================================
    _clean_prod = {"name": "T", "type": "重疾险", "highlights": "120种重疾+轻症疾病保险金"}
    check("F27.8 无除外记录：standard 宣称保持原样",
          PD._crx_key_benefits(_clean_prod, 500000, "standard")
          == "120种重疾+轻症保障，确诊即赔付50万",
          f"实际 {PD._crx_key_benefits(_clean_prod, 500000, 'standard')!r}")
    check("F27.8 无除外记录：premium 宣称保持原样",
          PD._crx_key_benefits(_clean_prod, 500000, "premium")
          == "重疾保障，保额50万",
          f"实际 {PD._crx_key_benefits(_clean_prod, 500000, 'premium')!r}")
    check("F27.8 无除外记录：features 保持原样",
          PD._crx_feature(_clean_prod) == "重疾险确诊即赔付",
          f"实际 {PD._crx_feature(_clean_prod)!r}")

    # ==================================================================
    # ⑨ F27.9 源码级防改回断言
    # ==================================================================
    src = open(os.path.join(os.path.dirname(__file__), "plan_designer.py"),
               "r", encoding="utf-8").read()
    check("F27.9 源码级：主体自身给付措辞豁免表已定义",
          "_CRX_SUBJECT_OWN_PAYMENT_CUES" in src)
    check("F27.9 源码级：主体自身给付措辞剔除函数已定义",
          "def _crx_strip_subject_own_payment(" in src)
    check("F27.9 源码级：gap 判定必须经主体自身给付措辞豁免（双向一致）",
          "def _crx_subject_gap_targets_other_object(" in src
          and "_crx_subject_gap_targets_other_object(gap, subject)" in src
          and "_crx_subject_gap_targets_other_object(before, subject)" in src
          and "_crx_subject_gap_targets_other_object(after, subject)" in src)
    check("F27.9 源码级：记录级轻症除外判定已实现",
          "def _crx_record_mild_excluded(" in src)
    check("F27.9 源码级：共享的重疾保障已验证状态已实现",
          "def _crx_ci_claim_state(" in src)
    check("F27.9 源码级：方案层重疾已验证状态判定已实现",
          "def _crx_plan_ci_allowed(" in src)
    # 共享状态必须在 premium 分支**之前**求值（official: compute state *before*
    #   generating any benefits）
    _i_kb = src.find("def _crx_key_benefits(")
    _i_state = src.find("state = _crx_ci_claim_state(product)", _i_kb)
    _i_prem = src.find('if style == "premium":', _i_kb)
    check("F27.9 源码级：共享状态必须先于 premium 分支求值",
          _i_kb != -1 and _i_state != -1 and _i_prem != -1 and _i_state < _i_prem,
          f"状态={_i_state} premium={_i_prem}")
    _i_feat = src.find("def _crx_feature(")
    check("F27.9 源码级：features 必须过共享状态闸",
          _i_feat != -1
          and src.find("_crx_ci_claim_state(product)", _i_feat) != -1)
    check("F27.9 源码级：方案描述必须过方案层状态闸",
          "def _build_plan_description(plan_name, products, product_records=None)" in src
          and "_crx_plan_ci_allowed(products, product_records)" in src)
    check("F27.9 源码级：_finalize_plan 必须把产品库记录传给描述生成器",
          'plan.get("products", []), products)' in src)
    check("F27.9 源码级：限制文案函数不得被删除",
          "def _crx_ci_category_limitation(" in src
          and "产品记录中存在重疾类别级除外表述" in src)
    return True


# ---------------------------------------------------------------------------
# F28 · 官方 SDI-4 残余 S（2026-11-23 线上复扫 · v2.4.33 · Excessive Agency · MEDIUM）
# ---------------------------------------------------------------------------
def test_f28_residual_s_shared_mild_state(pd=None):
    """F28（官方 SDI-4 残余 S · 2026-11-23 线上复扫 · v2.4.33 · Excessive Agency · MEDIUM）

    【官方 finding · 残余 S-1（china v2.4.33 · L2950-2959 · 原文）】
      "The shared critical-illness state omits the promised unverified limitation when
       mild-illness coverage is excluded."

    【官方 explanation · 残余 S-1（china v2.4.33 · 原文）】
      "When mild-illness coverage is excluded, `_crx_ci_claim_state` sets `unverified=True`
       and `allowed=False`, but obtains its limitation exclusively from
       `_crx_ci_category_limitation`, which returns nothing unless critical-illness coverage
       itself has a category-level exclusion. Both plan builders likewise attach only
       category-level limitations, leaving an unverified product's premium and coverage in
       the plan without a corresponding explicit warning; this is particularly consequential
       in insurance advice, where users may mistake a budget-feasible plan for verified
       protection."

    【官方 remediation · 残余 S-1（china v2.4.33 · 原文）】
      "Return an explicit limitation whenever the shared state is unverified, distinguishing
       mild-illness exclusions from critical-illness category exclusions. Have both plan
       builders or the finalizer propagate that shared limitation into the final JSON for
       retained products, and clarify that budget feasibility does not establish coverage
       validity. Add end-to-end tests for mild-illness-only exclusions in both standard and
       comprehensive plans, checking that unsupported claims are suppressed and the explicit
       warning remains present."

    【官方 finding · 残余 S-2（ai v2.4.33 · L2825-2838 · 原文）】
      "Record-wide mild-illness conditions and uncertainty can be discarded when generating
       affirmative benefit claims."

    【官方 remediation · 残余 S-2（ai v2.4.33 · 原文）】
      "Compute a shared, record-wide mild-illness coverage state before generating claims,
       checking all relevant fields for exclusions, uncertainty, conditions, and conflicting
       evidence. Prefer validated, treatment-specific structured coverage decisions; preserve
       applicable conditions in output, or suppress the mild-illness claim and add an explicit
       unverified limitation when they cannot be reliably interpreted. Add end-to-end tests
       pairing affirmative highlights with conditional or uncertain mild-illness statements in
       other fields, asserting that final JSON does not advertise unconditional mild-illness
       coverage."

    覆盖：
      ① 轻症单独除外 → 共享状态的 limitation 必须**非空**、且 unverified 且 not allowed（S-1）
      ② 轻症除外与「重疾类别级除外」的限制文案必须**可区分**；并澄清「预算可行 ≠ 保障已核实」（S-1）
      ③ 端到端：轻症单独除外 → **标准版**方案须保留如实限制说明、不得宣称轻症（S-1 e2e）
      ④ 端到端：轻症单独除外 → **全面版**方案须保留如实限制说明、不得宣称轻症（S-1 e2e）
      ⑤ 其它字段的不确定 / 条件表述 → 共享状态须判定为未经确认 + 如实限制说明（S-2）
      ⑥ 端到端：肯定 highlights + 其它字段不确定 / 条件表述 → 最终 JSON 不得广告无条件轻症保障（S-2 e2e）
      ⑦ 红线：其它字段提到轻症但**无**不确定 / 条件 / 除外语义 → 不得误伤，正常宣称必须保留
      ⑧ 源码级防改回断言（记录级轻症覆盖状态 + 两个 builder 都必须传导共享 limitation）
    """
    print("\nTest F28: 残余 S（记录级轻症覆盖状态 + 共享状态如实限制说明）")
    if pd is None:
        import plan_designer as PD
        PD = PD
    else:
        PD = pd

    with open(os.path.join(SKILL_DIR, "references", "products.json"), encoding="utf-8") as _fh:
        _PRODUCTS = json.load(_fh)["products"]
    _NEEDS = {"death": 1000000, "critical_illness": 500000}

    def _mutate_pool(highlights, other=""):
        """把**所有**重疾险产品改成指定 highlights / 其它字段表述 → 返回产品池

        ⚠ 必须 mutate **所有** type=重疾险 产品（含 is_active=false）：
          design_standard_plan / design_premium_plan 选品时可能选中**非在售**品
          （实测选中「国寿福终身寿险（庆典版）」is_active=false），
          只 mutate 在售品 → 选中品未带证据 → 计划级断言**退化**。
        """
        pool = []
        for _p in _PRODUCTS:
            _q = dict(_p)
            if (_q.get("type") or "") == "重疾险":
                _q["highlights"] = highlights
                _q["key_benefits"] = [highlights]
                _q["notes"] = other
                _q["suitable_for"] = ""
                _q["weakness"] = []
                _q["competitive_edge"] = ""
            pool.append(_q)
        return pool

    def _plan(pool, kind):
        if kind == "standard":
            return PD.design_standard_plan(35, "男", 300000, 60000, _NEEDS, pool)
        return PD.design_premium_plan(35, "男", 300000, 80000, _NEEDS, pool)

    def _ci_entry(plan):
        return next((e for e in plan.get("products", []) if e.get("type") == "重疾险"), None)

    def _ci_limits(plan):
        return [l for l in (plan.get("limitations") or [])
                if isinstance(l, dict) and l.get("product_type") == "重疾险"]

    def _claim_text(plan):
        """方案里**对外宣称面**的文案（不含 limitations —— 限制说明里提到「轻症」是如实报告）"""
        chunks = [str(plan.get("description") or "")]
        for _e in plan.get("products", []):
            chunks.append(str(_e.get("key_benefits") or ""))
        for _f in plan.get("features", []):
            chunks.append(str(_f))
        return "\n".join(chunks)

    # ==================================================================
    # ① F28.1 轻症单独除外 → 共享状态的 limitation 必须非空（S-1）
    # ==================================================================
    _S1_HIGHLIGHTS = ["120种重疾，不保轻症", "120种重疾，不含轻症", "轻症保障除外，120种重疾"]
    for _hl in _S1_HIGHLIGHTS:
        _prod = {"name": "T", "type": "重疾险", "highlights": _hl, "key_benefits": [_hl]}
        _st = PD._crx_ci_claim_state(_prod)
        check(f"F28.1 轻症单独除外 → state.limitation 必须非空「{_hl}」",
              isinstance(_st.get("limitation"), dict), f"实际 {_st.get('limitation')!r}")
        check(f"F28.1 轻症单独除外 → state.unverified 且 not allowed「{_hl}」",
              bool(_st.get("unverified")) and _st.get("allowed") is False,
              f"实际 unverified={_st.get('unverified')} allowed={_st.get('allowed')}")
        _kb_std = PD._crx_key_benefits(_prod, 500000, "standard")
        _kb_pre = PD._crx_key_benefits(_prod, 500000, "premium")
        check(f"F28.1 轻症单独除外 → key_benefits 必须为空串（standard）「{_hl}」",
              _kb_std == "", f"实际 {_kb_std!r}")
        check(f"F28.1 轻症单独除外 → key_benefits 必须为空串（premium）「{_hl}」",
              _kb_pre == "", f"实际 {_kb_pre!r}")

    # ==================================================================
    # ② F28.2 轻症除外与「重疾类别级除外」的限制文案必须可区分（S-1）
    #    + 必须澄清「预算可行 ≠ 保障已核实」
    # ==================================================================
    _mild_lim = PD._crx_ci_claim_state(
        {"name": "T", "type": "重疾险", "highlights": "120种重疾，不保轻症"}).get("limitation")
    _cat_lim = PD._crx_ci_claim_state(
        {"name": "T", "type": "重疾险", "highlights": "120种重疾，重疾疾病不保"}).get("limitation")
    check("F28.2 轻症单独除外必须产出限制说明", isinstance(_mild_lim, dict), f"实际 {_mild_lim!r}")
    check("F28.2 重疾类别级除外必须产出限制说明", isinstance(_cat_lim, dict), f"实际 {_cat_lim!r}")
    check("F28.2 轻症除外与重疾类别级除外文案必须可区分（official: distinguishing）",
          isinstance(_mild_lim, dict) and isinstance(_cat_lim, dict)
          and _mild_lim.get("reason") != _cat_lim.get("reason")
          and _mild_lim.get("requirement") != _cat_lim.get("requirement"),
          f"轻症={_mild_lim!r} 类别级={_cat_lim!r}")
    check("F28.2 轻症限制说明须点明「轻症」",
          isinstance(_mild_lim, dict) and "轻症" in (_mild_lim.get("reason") or ""),
          f"实际 {_mild_lim!r}")
    for _tag, _lim in (("轻症", _mild_lim), ("重疾类别级", _cat_lim)):
        check(f"F28.2 {_tag}限制说明须澄清「预算可行 ≠ 保障已核实」",
              isinstance(_lim, dict)
              and "预算" in (_lim.get("reason") or "")
              and "不代表保障范围已核实" in (_lim.get("reason") or ""),
              f"实际 {_lim!r}")

    # ==================================================================
    # ③ ④ F28.3 端到端：轻症单独除外 → 标准版 / 全面版方案（S-1 e2e）
    # ==================================================================
    for _kind, _kind_cn in (("standard", "标准版"), ("premium", "全面版")):
        _pl = _plan(_mutate_pool("120种重疾，不保轻症"), _kind)
        _entry = _ci_entry(_pl)
        _lims = _ci_limits(_pl)
        check(f"F28.3 轻症单独除外 → {_kind_cn}方案的重疾条目不得宣称轻症",
              _entry is None or "轻症" not in (_entry.get("key_benefits") or ""),
              f"实际 kb={(_entry or {}).get('key_benefits')!r}")
        _matched = [l for l in _lims
                    if _entry is not None and l.get("product") == _entry.get("product_name")]
        check(f"F28.3 轻症单独除外 → {_kind_cn}方案须对保留的重疾条目给出如实限制说明",
              _entry is None or bool(_matched),
              f"entry={_entry!r} limitations={_lims!r}")
        check(f"F28.3 轻症单独除外 → {_kind_cn}方案的如实限制说明须点明「轻症」且待核实",
              _entry is None or all("轻症" in (l.get("reason") or "")
                                    and "待核实" in (l.get("reason") or "")
                                    for l in _matched),
              f"实际 {_matched!r}")
        _txt = _claim_text(_pl)
        check(f"F28.3 轻症单独除外 → {_kind_cn}方案不得出现肯定的重疾宣称",
              "确诊即赔付" not in _txt, f"文案含肯定宣称")

    # ==================================================================
    # ⑤ F28.5 其它字段的不确定 / 条件表述 → 共享状态须判定为未经确认（S-2）
    # ==================================================================
    _S2_OTHER = ["轻症保障待核实", "轻症保障以实际条款为准",
                 "轻症需满足特定条件方可赔付", "是否包含轻症保障待确认"]
    for _other in _S2_OTHER:
        _prod = {"name": "T", "type": "重疾险",
                 "highlights": "120种重疾，含轻症保障",
                 "key_benefits": ["120种重疾，含轻症保障"], "notes": _other}
        _st = PD._crx_ci_claim_state(_prod)
        check(f"F28.5 其它字段不确定/条件表述 → state 必须判定为未经确认「{_other}」",
              _st.get("allowed") is False and bool(_st.get("unverified")),
              f"actual state={_st!r}")
        check(f"F28.5 其它字段不确定/条件表述 → state.limitation 必须非空「{_other}」",
              isinstance(_st.get("limitation"), dict), f"实际 {_st.get('limitation')!r}")
        check(f"F28.5 其它字段不确定/条件表述 → 不得宣称轻症「{_other}」",
              "轻症" not in (PD._crx_key_benefits(_prod, 500000, "standard") or ""),
              f"实际 {PD._crx_key_benefits(_prod, 500000, 'standard')!r}")
        check(f"F28.5 其它字段不确定/条件表述 → 轻症宣称必须被压制（_crx_disease_claim）「{_other}」",
              PD._crx_disease_claim(_prod) == "",
              f"实际 {PD._crx_disease_claim(_prod)!r}")

    # ==================================================================
    # ⑥ F28.6 端到端：肯定 highlights + 其它字段不确定 / 条件表述（S-2 e2e）
    # ==================================================================
    for _kind, _kind_cn in (("standard", "标准版"), ("premium", "全面版")):
        for _other in _S2_OTHER:
            _pl = _plan(_mutate_pool("120种重疾，含轻症保障", _other), _kind)
            _entry = _ci_entry(_pl)
            _lims = _ci_limits(_pl)
            _matched = [l for l in _lims
                        if _entry is not None and l.get("product") == _entry.get("product_name")]
            check(f"F28.6 肯定highlights + 其它字段待核实 → {_kind_cn}最终 JSON 不得广告无条件轻症保障「{_other}」",
                  _entry is None or "轻症" not in (_entry.get("key_benefits") or ""),
                  f"实际 kb={(_entry or {}).get('key_benefits')!r}")
            _txt = _claim_text(_pl)
            check(f"F28.6 肯定highlights + 其它字段待核实 → {_kind_cn}宣称面不得出现「轻症」或「确诊即赔付」「{_other}」",
                  "轻症" not in _txt and "确诊即赔付" not in _txt,
                  f"宣称面文案含轻症/确诊即赔付")
            check(f"F28.6 肯定highlights + 其它字段待核实 → {_kind_cn}须给出如实限制说明「{_other}」",
                  _entry is None or bool(_matched), f"limitations={_lims!r}")

    # ==================================================================
    # ⑦ F28.7 红线：其它字段提到轻症但**无**不确定/条件/除外语义 → 不得误伤
    # ==================================================================
    _BENIGN = ["40种轻症赔20%x6次", "轻症赔付比例25%", "被保险人轻症豁免"]
    for _b in _BENIGN:
        _prod = {"name": "T", "type": "重疾险", "highlights": "120种重疾+60种轻症",
                 "key_benefits": ["120种重疾+60种轻症"], "notes": _b}
        _st = PD._crx_ci_claim_state(_prod)
        check(f"F28.7 红线：其它字段仅提到轻症不得被误判「{_b}」",
              _st.get("allowed") is True and not _st.get("unverified"),
              f"实际 state={_st!r}")
        check(f"F28.7 红线：正常轻症宣称必须保留「{_b}」",
              "轻症" in (PD._crx_key_benefits(_prod, 500000, "standard") or ""),
              f"实际 {PD._crx_key_benefits(_prod, 500000, 'standard')!r}")
    for _kind, _kind_cn in (("standard", "标准版"), ("premium", "全面版")):
        _pl = _plan(_mutate_pool("120种重疾+60种轻症", "轻症赔付比例25%"), _kind)
        _entry = _ci_entry(_pl)
        _lims = _ci_limits(_pl)
        # 红线口径 = **不得过度压制**：重疾条目须保留其正常卖点文案（未被置空），
        #   且**不得**凭空产生轻症限制说明。
        #   ⚠ standard 样式的卖点含「轻症」、premium 样式按设计**不**含「轻症」
        #     （用「重疾多次赔付/终身保障」表述）→ 统一断言「非空 + 无轻症限制」。
        check(f"F28.7 红线：{_kind_cn}方案的重疾条目卖点不得被过度压制（置空）",
              _entry is None or bool(_entry.get("key_benefits")),
              f"实际 kb={(_entry or {}).get('key_benefits')!r}")
        check(f"F28.7 红线：{_kind_cn}方案不得凭空产生轻症限制说明",
              not _lims, f"实际 limitations={_lims!r}")

    # ==================================================================
    # ⑧ F28.8 源码级防改回断言
    # ==================================================================
    src = open(os.path.join(SKILL_DIR, "scripts", "plan_designer.py"),
               "r", encoding="utf-8").read()
    check("F28.8 源码级：记录级轻症覆盖状态已实现", "def _crx_record_mild_state(" in src)
    check("F28.8 源码级：轻症未确认限制文案函数已实现",
          "def _crx_mild_unverified_limitation(" in src)
    check("F28.8 源码级：轻症专属条件线索常量已定义", "_CRX_MILD_CONDITIONAL_RE" in src)
    _i_state = src.find("def _crx_ci_claim_state(")
    _i_mild = src.find("_crx_record_mild_state(product)", _i_state)
    check("F28.8 源码级：共享状态必须消费记录级轻症覆盖状态",
          _i_state != -1 and _i_mild != -1,
          f"状态定义={_i_state} 记录级调用={_i_mild}")
    check("F28.8 源码级：宣称面必须过记录级轻症状态闸",
          '_crx_record_mild_state(product)["unverified"]' in src)
    check("F28.8 源码级：两个 plan builder 都必须传导共享状态的 limitation",
          src.count('_crx_ci_claim_state(crx_product).get("limitation")') == 2,
          f"命中 {src.count('_crx_ci_claim_state(crx_product).get("limitation")')} 次")
    check("F28.8 源码级：不得回退到只挂类别级限制",
          "_crx_lim = _crx_ci_category_limitation(crx_product)" not in src)
    return True


def test_f29_residual_p_generic_cue_distinct_object(pd=None):
    """F29（官方 SDI-4 残余 P · remediation **后半句** · 2026-11-24 落地）

    【官方 finding · ai v2.4.30 · L2119-2125 · 原文】
      "The mild-illness exclusion guard can convert an explicit exclusion into an
       affirmative benefit claim."

    【官方 remediation · ai v2.4.30 · 原文】
      "Replace keyword-presence authorization with validated, structured mild-illness
       coverage decisions, preserving applicable conditions and suppressing unresolved
       claims. If free-text parsing remains necessary, recognize「轻症疾病」as the same
       coverage subject as「轻症」rather than treating「疾病」as a different object, and
       handle exclusions consistently before and after that subject. Add regression tests
       for「120种重疾，轻症疾病不保」and similar variants, asserting that the final
       generated plans never claim mild-illness coverage."

    【官方 explanation · ai v2.4.30 · 原文】
      "For example, highlights containing「120种重疾，轻症疾病不保」can produce
       「120种重疾+轻症保障」: the exclusion checker treats「疾病」between「轻症」and
       「不保」as another coverage object and skips the explicit exclusion. The
       record-wide contradiction check reuses this faulty interpretation, so it does not
       prevent the affirmative claim. In an insurance-advice skill, this can mislead
       customers into purchasing coverage that excludes a benefit they believe is included."

    【官方 finding · china v2.4.30 · 原文 · 同条 SDI-4 的另一半要求】
      "The mild-illness exclusion guard can mistake the excluded subject's own
       wording for another coverage object."

    【官方 remediation · china v2.4.30 · 原文 · 同条 SDI-4 的另一半要求】
      "Normalize coverage subjects and their extensions, such as 「轻症」and
       「轻症疾病」, before resolving exclusion scope. Require evidence of a
       genuinely distinct coverage object rather than accepting any generic cue
       substring; suppress claims when the exclusion target is ambiguous. Add
       tests for post-subject exclusions, subject extensions, and contradictory
       fields, checking final plan benefits rather than only helper outputs."

    根因（主侧已坐实 · 非猜测）：
      `_crx_gap_targets_other_object()` 只要 gap 里出现**任意一个**
      `_CRX_OTHER_OBJECT_CUES` 子串就判定「指向别的保障对象」→ 该除外标记与
      subject 无关 → 除外被跳过 → 轻症仍被肯定宣称。而 `_CRX_OTHER_OBJECT_CUES`
      混入了大量**泛用词 / 政策词**（疾病 / 给付 / 医疗 / 住院 / 费用 / 保费 /
      等待期 …）→「轻症医疗保障不保」「轻症费用不赔」这类**明确针对轻症**的
      除外会被误当成「指向别的保障对象」→ 泄漏。

    修法（官方口径落地）：
      ① gap 必须命中 **Tier A · 确凿的独立保障对象** 才算「指向别的保障对象」；
      ② 只命中 **Tier B · 泛用词 / 政策词**（或不认识）→ **歧义** → 官方口径
         「suppress claims when the exclusion target is ambiguous」→ 判为对
         subject 的除外 → 压制宣称；
      ③ 主体**自身的延伸措辞**（疾病 / 给付 / 保险金 / 赔付 / 责任 / 保障 …）
         在 gap 判定前先剔除（官方口径「Normalize coverage subjects and their
         extensions」）。

    覆盖：
      ① 行为矩阵（11 条）：泛用词 gap → 判为对轻症的除外；确凿的别的保障对象
         → **不得**误伤（官方矩阵 G-1 ~ G-5）
      ② 端到端（**最终方案 JSON**）：泛用词除外（post-subject / subject extension /
         矛盾字段）→ 标准版 + 全面版**不得**宣称轻症、**必须**给出如实限制说明
      ③ 红线（**最终方案 JSON**）：确凿的别的保障对象 → 轻症宣称必须保留、
         **不得**凭空产生轻症限制说明（不得过度收紧）
      ④ 证据分层：Tier A（确凿对象 → distinct）vs Tier B（泛用词 → generic）
      ⑤ 源码级防改回断言（分层常量 + 证据函数 + **病种数路径口径不变**）
    """
    print("\nTest F29: 残余 P 后半句（泛用 cue → 须有确凿的独立保障对象证据）")
    if pd is None:
        import plan_designer as PD
        PD = PD
    else:
        PD = pd

    with open(os.path.join(SKILL_DIR, "references", "products.json"), encoding="utf-8") as _fh:
        _PRODUCTS = json.load(_fh)["products"]
    _NEEDS = {"death": 1000000, "critical_illness": 500000}

    def _mutate_pool(highlights, other=""):
        """把**所有**重疾险产品改成指定 highlights / 其它字段表述 → 返回产品池

        ⚠ 必须 mutate **所有** type=重疾险 产品（含 is_active=false）：
          design_standard_plan / design_premium_plan 选品时可能选中**非在售**品，
          只 mutate 在售品 → 选中品未带证据 → 计划级断言**退化**。
        """
        pool = []
        for _p in _PRODUCTS:
            _q = dict(_p)
            if (_q.get("type") or "") == "重疾险":
                _q["highlights"] = highlights
                _q["key_benefits"] = [highlights]
                _q["notes"] = other
                _q["suitable_for"] = ""
                _q["weakness"] = []
                _q["competitive_edge"] = ""
            pool.append(_q)
        return pool

    def _plan(pool, kind):
        if kind == "standard":
            return PD.design_standard_plan(35, "男", 300000, 60000, _NEEDS, pool)
        return PD.design_premium_plan(35, "男", 300000, 80000, _NEEDS, pool)

    def _ci_entry(plan):
        return next((e for e in plan.get("products", []) if e.get("type") == "重疾险"), None)

    def _ci_limits(plan):
        return [l for l in (plan.get("limitations") or [])
                if isinstance(l, dict) and l.get("product_type") == "重疾险"]

    def _claim_text(plan):
        """方案里**对外宣称面**的文案（不含 limitations —— 限制说明里提到「轻症」是如实报告）"""
        chunks = [str(plan.get("description") or "")]
        for _e in plan.get("products", []):
            chunks.append(str(_e.get("key_benefits") or ""))
        for _f in plan.get("features", []):
            chunks.append(str(_f))
        return "\n".join(chunks)

    # ==================================================================
    # ① F29.1 行为矩阵（官方矩阵 G-1 ~ G-5）
    # ==================================================================
    _MATRIX = [
        ("自身宾语尾巴", "轻症疾病不保", True),
        ("自身给付措辞", "轻症给付责任除外", True),
        ("泛用词·疾病(填充)", "轻症疾病类不保", True),
        ("泛用词·医疗", "轻症医疗保障不保", True),
        ("泛用词·费用", "轻症费用不赔", True),
        ("泛用词·保险金", "轻症保险金不保", True),
        ("泛用词·给付(句尾)", "轻症不予给付", True),
        ("真·住院津贴", "轻症不保住院津贴", False),
        ("真·身故责任", "轻症不保身故责任", False),
        ("真·意外医疗", "轻症不保意外医疗", False),
        ("头侧前向绑定", "不保轻症疾病", True),
    ]
    for _tag, _clause, _expect in _MATRIX:
        _got = bool(PD._crx_clause_excludes_subject(_clause, "轻症"))
        check(f"F29.1 行为矩阵「{_clause}」（{_tag}）→ 判定为对轻症的除外={_expect}",
              _got == _expect, f"实际 {_got}")

    # ==================================================================
    # ④ F29.4 证据分层：Tier A（确凿对象）vs Tier B（泛用词）
    # ==================================================================
    _EVIDENCE = [
        ("住院津贴", "distinct"),      # 确凿的独立保障对象
        ("住院医疗", "distinct"),      # 多字短语：区分性成分不得被剥离吃掉
        ("意外医疗", "distinct"),
        ("身故责任", "distinct"),      # 剥离主体自身给付措辞后仍剩「身故」
        ("医疗保障", "generic"),       # 剥离「保障」后只剩泛用词「医疗」→ 歧义
        ("医疗", "generic"),
        ("费用", "generic"),
        ("疾病", "generic"),
        ("等待期", "generic"),         # 政策词 → 不是别的保障对象
        ("保费", "generic"),
        ("", "unknown"),
    ]
    for _gap, _expect in _EVIDENCE:
        _got = PD._crx_gap_object_evidence(_gap)
        check(f"F29.4 缺口证据分层 {_gap!r} → {_expect}", _got == _expect, f"实际 {_got}")
    check("F29.4 泛用词必须**不构成**「别的保障对象」的证据（official: generic cue substring）",
          PD._crx_gap_object_evidence("医疗") != "distinct"
          and PD._crx_gap_object_evidence("疾病") != "distinct"
          and PD._crx_gap_object_evidence("费用") != "distinct",
          "泛用词被当成了确凿对象")
    check("F29.4 确凿对象必须构成证据（official: genuinely distinct coverage object）",
          PD._crx_gap_object_evidence("住院津贴") == "distinct"
          and PD._crx_gap_object_evidence("意外医疗") == "distinct"
          and PD._crx_gap_object_evidence("身故") == "distinct",
          "确凿对象未被识别")

    # ==================================================================
    # ② F29.2 端到端（**最终方案 JSON**）：泛用词除外 → 不得宣称轻症
    #    官方要求：checking final plan benefits rather than only helper outputs
    # ==================================================================
    _GENERIC_EXCL = [
        "轻症医疗保障不保",   # 泛用词·医疗
        "轻症费用不赔",       # 泛用词·费用
        "轻症疾病不保",       # subject 自身扩展（已修，防回归）
        "轻症疾病类不保",     # subject 自身扩展 + 填充词
        "轻症给付责任除外",   # 自身给付措辞（已修，防回归）
        "轻症保险金不保",     # 自身给付措辞（已修，防回归）
        "不保轻症疾病",       # 头侧前向绑定（已修，防回归）
    ]
    for _other in _GENERIC_EXCL:
        for _kind, _kind_cn in (("standard", "标准版"), ("premium", "全面版")):
            # 矛盾字段场景：highlights 肯定宣称 + **其它字段**明确除外
            _pl = _plan(_mutate_pool("120种重疾，含轻症保障", _other), _kind)
            _entry = _ci_entry(_pl)
            _lims = _ci_limits(_pl)
            _matched = [l for l in _lims
                        if _entry is not None and l.get("product") == _entry.get("product_name")]
            check(f"F29.2 泛用词除外「{_other}」→ {_kind_cn}最终 JSON 的重疾条目不得宣称轻症",
                  _entry is None or "轻症" not in (_entry.get("key_benefits") or ""),
                  f"实际 kb={(_entry or {}).get('key_benefits')!r}")
            _txt = _claim_text(_pl)
            check(f"F29.2 泛用词除外「{_other}」→ {_kind_cn}宣称面不得出现「轻症」",
                  "轻症" not in _txt, "宣称面文案含轻症")
            check(f"F29.2 泛用词除外「{_other}」→ {_kind_cn}不得出现肯定的「确诊即赔付」宣称",
                  "确诊即赔付" not in _txt, "宣称面文案含确诊即赔付")
            check(f"F29.2 泛用词除外「{_other}」→ {_kind_cn}须给出如实限制说明",
                  _entry is None or bool(_matched), f"limitations={_lims!r}")
            check(f"F29.2 泛用词除外「{_other}」→ {_kind_cn}如实限制说明须点明「轻症」且待核实",
                  _entry is None or all("轻症" in (l.get("reason") or "")
                                        and "待核实" in (l.get("reason") or "")
                                        for l in _matched),
                  f"实际 {_matched!r}")
            # post-subject 除外场景：除外就在 highlights 里
            _pl2 = _plan(_mutate_pool(f"120种重疾，{_other}"), _kind)
            _entry2 = _ci_entry(_pl2)
            _txt2 = _claim_text(_pl2)
            check(f"F29.2 post-subject 除外「120种重疾，{_other}」→ {_kind_cn}最终 JSON 不得宣称轻症",
                  _entry2 is None or "轻症" not in (_entry2.get("key_benefits") or ""),
                  f"实际 kb={(_entry2 or {}).get('key_benefits')!r}")
            check(f"F29.2 post-subject 除外「120种重疾，{_other}」→ {_kind_cn}宣称面不得出现「轻症」",
                  "轻症" not in _txt2, "宣称面文案含轻症")

    # ==================================================================
    # ③ F29.3 红线：确凿的别的保障对象 → **不得**误伤（最终方案 JSON）
    # ==================================================================
    _DISTINCT_EXCL = [
        "轻症不保住院津贴",
        "轻症不保身故责任",
        "轻症不保意外医疗",
        "轻症不保住院医疗",
    ]
    for _other in _DISTINCT_EXCL:
        for _kind, _kind_cn in (("standard", "标准版"), ("premium", "全面版")):
            _pl = _plan(_mutate_pool("120种重疾，含轻症保障", _other), _kind)
            _entry = _ci_entry(_pl)
            _lims = _ci_limits(_pl)
            _kb = (_entry or {}).get("key_benefits") or ""
            if _kind == "standard":
                check(f"F29.3 红线：确凿的别的保障对象「{_other}」→ {_kind_cn}轻症宣称必须保留",
                      _entry is None or "轻症" in _kb, f"实际 kb={_kb!r}")
            else:
                # ⚠ premium 样式的卖点按设计**不**含「轻症」（用「重疾多次赔付/终身保障」
                #   表述）→ 统一断言「非空（未被置空 = 未被过度压制）」
                check(f"F29.3 红线：确凿的别的保障对象「{_other}」→ {_kind_cn}卖点不得被过度压制（置空）",
                      _entry is None or bool(_kb), f"实际 kb={_kb!r}")
            check(f"F29.3 红线：确凿的别的保障对象「{_other}」→ {_kind_cn}不得凭空产生轻症限制说明",
                  not _lims, f"实际 limitations={_lims!r}")
            _txt = _claim_text(_pl)
            check(f"F29.3 红线：确凿的别的保障对象「{_other}」→ {_kind_cn}重疾宣称必须保留",
                  "重疾" in _txt, f"宣称面文案={_txt[:80]!r}")

    # ==================================================================
    # ⑤ F29.5 源码级防改回断言
    # ==================================================================
    src = open(os.path.join(SKILL_DIR, "scripts", "plan_designer.py"),
               "r", encoding="utf-8").read()
    check("F29.5 源码级：Tier A 确凿对象线索表已定义",
          "_CRX_DISTINCT_OBJECT_CUES" in src)
    check("F29.5 源码级：Tier B 泛用词线索表已定义",
          "_CRX_GENERIC_CUE_WORDS" in src)
    check("F29.5 源码级：主体自身延伸措辞表已定义",
          "_CRX_SUBJECT_OWN_EXTENSION_CUES" in src)
    check("F29.5 源码级：缺口证据分类函数已实现",
          "def _crx_gap_object_evidence(" in src)
    check("F29.5 源码级：主体自身延伸措辞剔除函数已实现",
          "def _crx_strip_subject_own_extension(" in src)
    check("F29.5 源码级：轻症主体路径必须走分层口径（Tier A 证据）",
          '_crx_gap_object_evidence(gap) == "distinct"' in src)
    check("F29.5 源码级：病种数路径口径**不得**被改动（仍用既有线索表）",
          "_crx_count_object_is_other" in src
          and "def _crx_count_object_is_other(" in src
          and "def _crx_clause_excludes_disease_count(" in src)
    check("F29.5 源码级：病种数专属线索表必须保持原口径（不得并入 Tier A/B）",
          "_CRX_COUNT_OTHER_OBJECT_CUES = (" in src
          and '"轻症", "中症", "少儿特定疾病",' in src)
    check("F29.5 源码级：既有混合线索表不得再被轻症主体路径直接使用",
          "_crx_subject_gap_targets_other_object(gap, subject)" not in src
          or "return _crx_gap_targets_other_object(gap)" in src)
    return True


def test_f30_residual_t_local_binding(pd=None):
    """F30（官方 SDI-4 残余 T · 2026-11-24 落地 · v2.4.35 公开复扫）

    【官方 finding · ai v2.4.35 · L2309-2313 · 原文 · 本库官方原文】
      "The mild-illness exclusion guard can discard an explicit exclusion when a
       different benefit is mentioned afterward, contradicting the documented
       record-wide suppression guarantee."

    【官方 explanation · ai v2.4.35 · 原文 · 本库官方原文】
      "The tail-side exclusion check discards an exclusion whenever its remaining
       suffix mentions another benefit, even when the exclusion clearly applies to mild
       illness. For example, highlights reading 「120种重疾，轻症除外但含身故保障」 cause
       the guard to overlook 「轻症除外」 because 「身故」 appears afterward, allowing
       downstream generation of 「120种重疾+轻症保障」 without an unverified-coverage
       warning."

    【官方 remediation · ai v2.4.35 · 原文 · 本库官方原文】
      "Bind each exclusion to its coverage subject using local grammatical scope; do not
       discard an already-bound exclusion merely because a subsequent clause introduces
       another benefit. Prefer validated structured coverage decisions, suppress
       unresolved interpretations, and propagate the resulting state to benefits,
       features, descriptions, and explicit limitations. Add end-to-end regression tests
       for 「120种重疾，轻症除外但含身故保障」 and equivalent conflicting-field variants in
       both standard and comprehensive plans."

    【官方 finding · china v2.4.35 · L3060-3081 · 原文 · 同条 SDI-4】
      "The documented record-wide mild-illness exclusion guard can still turn an
       explicit exclusion into an affirmative benefit claim."

    【官方 explanation · china v2.4.35 · 原文 · 同条 SDI-4】
      "The record-wide mild-illness guard relies on an incomplete exclusion
       vocabulary: for example, highlights containing 「120种重疾，轻症责任免除」 are
       not recognized as excluding mild-illness coverage because 「责任免除」 is absent
       from _CRX_EXCLUSION_MARKERS. The shared state consequently permits
       _crx_disease_claim to produce 「120种重疾+轻症保障」 without an unverified
       limitation. In an insurance-advice skill, this reversal of an exclusion into an
       affirmative benefit can mislead purchasing decisions and leave users with
       unexpected coverage gaps; filesystem and network restrictions do not mitigate
       this output-integrity risk."

    【官方 remediation · china v2.4.35 · 原文 · 同条 SDI-4】
      "Require validated, structured mild-illness coverage decisions before generating
       affirmative claims, preserving applicable conditions and treating missing,
       ambiguous, or conflicting evidence as unverified. If free-text parsing remains,
       recognize responsibility-exemption wording such as 「轻症责任免除」 in both word
       orders and reconcile exclusions across the entire product record. Apply the
       resulting state to every benefits, features, and description output, propagate an
       explicit limitation, and add end-to-end regression tests asserting that excluded
       mild-illness coverage is never advertised."

    根因（主侧已坐实 · 非猜测）：
      ① T-1：`_CRX_EXCLUSION_MARKERS` 缺 **「责任免除」** → 「轻症责任免除」
         （含记录级）不被识别为对轻症的除外 → `_crx_disease_claim` 仍输出
         「120种重疾+轻症保障」且**无**任何未确认限制说明（泄漏）。
      ② T-2：tail 侧判定把「除外标记**之后**的全部剩余文本」当作「别的保障对象」
         的证据 → 「轻症除外但含身故保障」里的「除外」明明已绑定「轻症」，
         却因后缀出现「身故」而被**丢弃** → 轻症仍被宣称（泄漏）。

    修法（官方口径落地）：
      ① T-1：`_CRX_EXCLUSION_MARKERS` 补入 **「责任免除」** → 后向「轻症责任免除」
         + 前向「责任免除轻症」**双向**生效。
      ② T-2：**局部语法作用域**绑定 ——
         · **后置型**标记（「除外」/「责任免除」/「不在保障范围」/「无保障」）
           绑定**前面的** subject；其后的文本属**后续子句**（「但含身故保障」）
           → **不得**推翻已绑定的除外；
         · **前置型**标记（「不保」/「不含」…）绑定**紧邻的后置宾语**；
         · head 侧：标记若**紧邻**跟在别的保障对象之后（「住院津贴不保轻症」）
           → 它绑定的是**那个对象** → 与 subject 无关。

    覆盖：
      ① T-1 词表**双向**生效（后向 / 前向 / 带前文）
      ② T-2 局部语法绑定：后续子句的别的保障对象**不得**推翻已绑定的除外
      ③ 红线：确实指向别的保障对象的除外**不得**误伤（三个方向）
      ④ 端到端（**最终方案 JSON**）：标准版 + 全面版不得宣称轻症 + 须有如实限制说明
      ⑤ 记录级：`_crx_record_mild_excluded` / `_crx_ci_claim_state` 判定
      ⑥ 源码级防改回断言
    """
    print("\nTest F30: 残余 T（责任免除词表双向 + 局部语法作用域绑定）")
    if pd is None:
        import plan_designer as PD
        PD = PD
    else:
        PD = pd

    with open(os.path.join(SKILL_DIR, "references", "products.json"), encoding="utf-8") as _fh:
        _PRODUCTS = json.load(_fh)["products"]
    _NEEDS = {"death": 1000000, "critical_illness": 500000}

    def _mutate_pool(highlights, other=""):
        """把**所有**重疾险产品改成指定 highlights / 其它字段表述 → 返回产品池

        ⚠ 必须 mutate **所有** type=重疾险 产品（含 is_active=false）：
          design_standard_plan / design_premium_plan 选品时可能选中**非在售**品，
          只 mutate 在售品 → 选中品未带证据 → 计划级断言**退化**。
        """
        pool = []
        for _p in _PRODUCTS:
            _q = dict(_p)
            if (_q.get("type") or "") == "重疾险":
                _q["highlights"] = highlights
                _q["key_benefits"] = [highlights]
                _q["notes"] = other
                _q["suitable_for"] = ""
                _q["weakness"] = []
                _q["competitive_edge"] = ""
            pool.append(_q)
        return pool

    def _plan(pool, kind):
        if kind == "standard":
            return PD.design_standard_plan(35, "男", 300000, 60000, _NEEDS, pool)
        return PD.design_premium_plan(35, "男", 300000, 80000, _NEEDS, pool)

    def _ci_entry(plan):
        return next((e for e in plan.get("products", []) if e.get("type") == "重疾险"), None)

    def _ci_limits(plan):
        return [l for l in (plan.get("limitations") or [])
                if isinstance(l, dict) and l.get("product_type") == "重疾险"]

    def _claim_text(plan):
        """方案里**对外宣称面**的文案（不含 limitations —— 限制说明里提到「轻症」是如实报告）"""
        chunks = [str(plan.get("description") or "")]
        for _e in plan.get("products", []):
            chunks.append(str(_e.get("key_benefits") or ""))
        for _f in plan.get("features", []):
            chunks.append(str(_f))
        return "\n".join(chunks)

    # ==================================================================
    # ① F30.1 T-1 词表双向生效
    # ==================================================================
    _T1_MUST_EXCLUDE = [
        ("后向·责任免除", "轻症责任免除"),
        ("后向·责任免除(带前文)", "120种重疾，轻症责任免除"),
        ("前向·责任免除", "责任免除轻症"),
        ("后向·责任不保", "轻症责任不保"),
        ("后向·责任不予给付", "轻症责任不予给付"),
    ]
    for _tag, _clause in _T1_MUST_EXCLUDE:
        _got = bool(PD._crx_clause_excludes_subject(_clause, "轻症"))
        check(f"F30.1 T-1「{_clause}」（{_tag}）→ 必须判定为对轻症的除外",
              _got, f"实际 {_got}")

    # ==================================================================
    # ② F30.2 T-2 局部语法作用域绑定
    # ==================================================================
    _T2_MUST_EXCLUDE = [
        ("后续子句·身故", "轻症除外但含身故保障"),
        ("后续子句·住院津贴", "轻症除外但含住院津贴"),
        ("后续子句·身故(带前文)", "120种重疾，轻症除外但含身故保障"),
        ("后续子句·责任免除", "轻症责任免除但含身故保障"),
    ]
    for _tag, _clause in _T2_MUST_EXCLUDE:
        _got = bool(PD._crx_clause_excludes_subject(_clause, "轻症"))
        check(f"F30.2 T-2「{_clause}」（{_tag}）→ 已绑定的除外不得被后续子句推翻",
              _got, f"实际 {_got}")

    # ==================================================================
    # ③ F30.3 红线：确实指向别的保障对象 → 不得误伤
    # ==================================================================
    _RED_LINE = [
        ("轻症不保住院津贴", "轻症不保住院津贴"),
        ("轻症不保身故责任", "轻症不保身故责任"),
        ("住院津贴不保轻症", "住院津贴不保轻症"),
        ("住院津贴不保的轻症", "住院津贴不保的轻症"),
    ]
    for _tag, _clause in _RED_LINE:
        _got = bool(PD._crx_clause_excludes_subject(_clause, "轻症"))
        check(f"F30.3 红线「{_clause}」（{_tag}）→ 与轻症无关，不得判定为对轻症的除外",
              not _got, f"实际 {_got}")

    # ==================================================================
    # ⑤ F30.5 记录级：除外 / 共享状态 / 限制说明
    # ==================================================================
    _RECORD_CASES = [
        "120种重疾，轻症责任免除",
        "120种重疾，轻症除外但含身故保障",
        "120种重疾，轻症责任免除，含身故保障",
    ]
    for _hl in _RECORD_CASES:
        _prod = {"name": "T", "type": "重疾险", "highlights": _hl,
                 "key_benefits": [_hl], "notes": ""}
        _excl = bool(PD._crx_record_mild_excluded(_prod))
        _st = PD._crx_ci_claim_state(_prod)
        check(f"F30.5 记录级除外必须成立「{_hl}」", _excl, f"实际 {_excl}")
        check(f"F30.5 共享状态必须为「未经确认 + 不得宣称」「{_hl}」",
              _st.get("unverified") is True and _st.get("allowed") is False,
              f"实际 state={_st!r}")
        check(f"F30.5 共享状态必须带**如实限制说明**「{_hl}」",
              isinstance(_st.get("limitation"), dict), f"实际 {_st.get('limitation')!r}")
        _kb_std = PD._crx_key_benefits(_prod, 500000, "standard")
        _kb_pre = PD._crx_key_benefits(_prod, 500000, "premium")
        check(f"F30.5 key_benefits 不得宣称轻症「{_hl}」",
              "轻症" not in (_kb_std or "") and "轻症" not in (_kb_pre or ""),
              f"实际 std={_kb_std!r} pre={_kb_pre!r}")
        check(f"F30.5 轻症宣称必须被压制「{_hl}」",
              PD._crx_disease_claim(_prod) == "",
              f"实际 {PD._crx_disease_claim(_prod)!r}")

    # ==================================================================
    # ④ F30.4 端到端（**最终方案 JSON**）
    # ==================================================================
    for _hl in _RECORD_CASES:
        for _kind, _kind_cn in (("standard", "标准版"), ("premium", "全面版")):
            _pl = _plan(_mutate_pool(_hl), _kind)
            _entry = _ci_entry(_pl)
            _lims = _ci_limits(_pl)
            _matched = [l for l in _lims
                        if _entry is not None and l.get("product") == _entry.get("product_name")]
            check(f"F30.4 「{_hl}」→ {_kind_cn}最终 JSON 的重疾条目不得宣称轻症",
                  _entry is None or "轻症" not in (_entry.get("key_benefits") or ""),
                  f"实际 kb={(_entry or {}).get('key_benefits')!r}")
            _txt = _claim_text(_pl)
            check(f"F30.4 「{_hl}」→ {_kind_cn}宣称面不得出现「轻症」",
                  "轻症" not in _txt, "宣称面文案含轻症")
            check(f"F30.4 「{_hl}」→ {_kind_cn}须给出如实限制说明",
                  _entry is None or bool(_matched), f"limitations={_lims!r}")
            check(f"F30.4 「{_hl}」→ {_kind_cn}如实限制说明须点明「轻症」且待核实",
                  _entry is None or all("轻症" in (l.get("reason") or "")
                                        and "待核实" in (l.get("reason") or "")
                                        for l in _matched),
                  f"实际 {_matched!r}")
    # 跨字段（矛盾字段）场景：highlights 肯定 + 其它字段除外
    for _other in ("轻症责任免除", "轻症除外但含身故保障"):
        for _kind, _kind_cn in (("standard", "标准版"), ("premium", "全面版")):
            _pl = _plan(_mutate_pool("120种重疾，含轻症保障", _other), _kind)
            _entry = _ci_entry(_pl)
            _txt = _claim_text(_pl)
            check(f"F30.4 跨字段除外「{_other}」→ {_kind_cn}最终 JSON 不得宣称轻症",
                  _entry is None or "轻症" not in (_entry.get("key_benefits") or ""),
                  f"实际 kb={(_entry or {}).get('key_benefits')!r}")
            check(f"F30.4 跨字段除外「{_other}」→ {_kind_cn}宣称面不得出现「轻症」",
                  "轻症" not in _txt, "宣称面文案含轻症")

    # 红线端到端：除外确实指向别的保障对象 → 轻症宣称必须保留
    for _other in ("轻症不保住院津贴", "轻症不保身故责任", "住院津贴不保轻症"):
        for _kind, _kind_cn in (("standard", "标准版"), ("premium", "全面版")):
            _pl = _plan(_mutate_pool("120种重疾，含轻症保障", _other), _kind)
            _entry = _ci_entry(_pl)
            _lims = _ci_limits(_pl)
            _kb = (_entry or {}).get("key_benefits") or ""
            if _kind == "standard":
                check(f"F30.4 红线「{_other}」→ {_kind_cn}轻症宣称必须保留",
                      _entry is None or "轻症" in _kb, f"实际 kb={_kb!r}")
            else:
                # ⚠ premium 样式的卖点按设计**不**含「轻症」→ 断言「非空（未被置空）」
                check(f"F30.4 红线「{_other}」→ {_kind_cn}卖点不得被过度压制（置空）",
                      _entry is None or bool(_kb), f"实际 kb={_kb!r}")
            check(f"F30.4 红线「{_other}」→ {_kind_cn}不得凭空产生轻症限制说明",
                  not _lims, f"实际 limitations={_lims!r}")

    # ==================================================================
    # ⑥ F30.6 源码级防改回断言
    # ==================================================================
    src = open(os.path.join(SKILL_DIR, "scripts", "plan_designer.py"),
               "r", encoding="utf-8").read()
    check("F30.6 源码级：除外标记表必须含「责任免除」（T-1）",
          '"责任免除", "除外"' in src or '"除外", "责任免除"' in src)
    check("F30.6 源码级：后置型除外标记表已定义（T-2）",
          "_CRX_POSTPOSED_EXCLUSION_MARKERS" in src)
    check("F30.6 源码级：局部语法作用域常量已定义（T-2）",
          "_CRX_SCOPE_BREAK_CHARS" in src and "_CRX_SCOPE_CONNECTORS" in src
          and "_CRX_ADJACENT_OBJECT_WINDOW" in src)
    check("F30.6 源码级：紧邻宾语片段函数已实现（T-2）",
          "def _crx_adjacent_object(" in src and "def _crx_preceding_object(" in src)
    check("F30.6 源码级：前置标记绑定紧邻宾语、后置标记绑定前面的 subject",
          'if mk in _CRX_POSTPOSED_EXCLUSION_MARKERS:' in src
          and "_crx_adjacent_object(after)" in src)
    check("F30.6 源码级：head 侧必须检查标记前紧邻的别的保障对象（T-2）",
          "_crx_preceding_binds_other_object(" in src)
    check("F30.6 源码级：轻症路径与病种数路径的口径边界必须写在注释里",
          "非「症」主体（病种数路径）沿用既有口径" in src)
    return True


def test_f31_residual_t_same_family_binding(pd=None):
    """F31（官方 SDI-4 残余 T **回归修正** · 2026-11-24 · v2.4.36 回归）

    【回归根因（v2.4.36 · 残余 T 的 head 侧新逻辑引入）】
      head 侧新逻辑 `_crx_preceding_binds_other_object` 把**前序片段**里命中的
      Tier A「别的保障对象」线索当作「标记绑定的是**那个**对象」→ 跳过该标记。
      但「重疾 / 重大疾病 / 中症」与「轻症」属于**同一保障家族（重疾家族）**，
      **不是**「另一个保障对象」：
        「120种重疾不含轻症」=「120 种重疾，**不含**轻症」
        → 「不含」应**后向绑定**「轻症」→ 轻症被除外 → 整句宣称必须被压制；
        → v2.4.36 误判为「标记绑定的是**重疾**」→ 除外被跳过
           → `_crx_disease_claim` 仍产出「120种重疾+轻症保障」→ **明确泄漏**
           → 被 `sdi4_residual_o_accept_check.py` ⑦ 拦下（69/72 REJECT）。

    【修法（最小改动 · 不推翻已完成的 T-2 口径）】
      把「**同家族**」证据从「**别的**保障对象」证据里剔除：
        · 新增 `_CRX_SAME_FAMILY_CUES = ("重疾", "重大疾病", "中症", "轻症")`
        · 新增 `_crx_strip_same_family_cues()`（前序片段 → 剔除同家族 cue）
        · `_crx_preceding_binds_other_object` 在**「症」结尾主体**（轻症路径）下
          先剔除同家族 cue → 片段若**只**靠同家族 cue 命中 → 不算「别的对象」
          → 标记**后向绑定** subject → 除外成立。
      ⚠ 病种数路径（`_crx_clause_excludes_disease_count` /
        `_crx_count_object_is_other` / `_CRX_COUNT_OTHER_OBJECT_CUES`）、
        残余 P 的 Tier A·B 分层口径（`_CRX_DISTINCT_OBJECT_CUES` /
        `_CRX_GENERIC_CUE_WORDS` / `_crx_gap_object_evidence`）、
        官方 T-1 / T-2 口径**一字不动**（避免口径漂移引发新回归）。

    覆盖：
      ① 同家族前序片段 → 除外**成立**（回归修复本体）
      ② 红线：确凿的别的保障对象 → **不得**误伤
      ③ 官方 T-1 / T-2 口径**保持**
      ④ 端到端（**最终方案 JSON**）：notes 字段的同家族除外 → 不得宣称轻症
      ⑤ 源码级防改回断言
    """
    print("\nTest F31: 残余 T 回归修正（同家族 ≠ 别的保障对象）")
    if pd is None:
        import plan_designer as PD
        PD = PD
    else:
        PD = pd

    with open(os.path.join(SKILL_DIR, "references", "products.json"), encoding="utf-8") as _fh:
        _PRODUCTS = json.load(_fh)["products"]
    _NEEDS = {"death": 1000000, "critical_illness": 500000}

    def _mutate_pool(highlights, other=""):
        """把**所有**重疾险产品改成指定 highlights / 其它字段表述 → 返回产品池"""
        pool = []
        for _p in _PRODUCTS:
            _q = dict(_p)
            if (_q.get("type") or "") == "重疾险":
                _q["highlights"] = highlights
                _q["key_benefits"] = [highlights]
                _q["notes"] = other
                _q["suitable_for"] = ""
                _q["weakness"] = []
                _q["competitive_edge"] = ""
            pool.append(_q)
        return pool

    def _plan(pool, kind):
        if kind == "standard":
            return PD.design_standard_plan(35, "男", 300000, 60000, _NEEDS, pool)
        return PD.design_premium_plan(35, "男", 300000, 80000, _NEEDS, pool)

    def _ci_entry(plan):
        return next((e for e in plan.get("products", []) if e.get("type") == "重疾险"), None)

    def _ci_limits(plan):
        return [l for l in (plan.get("limitations") or [])
                if isinstance(l, dict) and l.get("product_type") == "重疾险"]

    def _claim_text(plan):
        """方案里**对外宣称面**的文案（不含 limitations —— 限制说明里提到「轻症」是如实报告）"""
        chunks = [str(plan.get("description") or "")]
        for _e in plan.get("products", []):
            chunks.append(str(_e.get("key_benefits") or ""))
        for _f in plan.get("features", []):
            chunks.append(str(_f))
        return "\n".join(chunks)

    # ==================================================================
    # ① F31.1 同家族前序片段 → 除外**成立**（回归修复本体）
    # ==================================================================
    _SAME_FAMILY_MUST_EXCLUDE = [
        ("病种数主体·不含", "120种重疾不含轻症"),
        ("病种数主体·不含(自身尾巴)", "120种重疾不含轻症疾病"),
        ("病种数主体·不保", "120种重疾不保轻症"),
        ("重疾主体·不含", "重疾不含轻症"),
        ("重大疾病主体·不含", "重大疾病不含轻症"),
        ("中症主体·不含", "中症不含轻症"),
        ("带前文", "120种重疾+60种轻症，120种重疾不含轻症"),
    ]
    for _tag, _clause in _SAME_FAMILY_MUST_EXCLUDE:
        _got = bool(PD._crx_clause_excludes_subject(_clause, "轻症"))
        check(f"F31.1 同家族前序片段「{_clause}」（{_tag}）→ 必须判定为对轻症的除外",
              _got, f"实际 {_got}")

    # ==================================================================
    # ② F31.2 红线：确凿的别的保障对象 → **不得**误伤
    # ==================================================================
    _SAME_FAMILY_RED_LINE = [
        ("住院津贴·前向", "住院津贴不保轻症"),
        ("住院津贴·前向(填充)", "住院津贴不保的轻症"),
        ("住院津贴·前向·不含", "住院津贴不含轻症"),
        ("意外医疗·前向", "意外医疗不保轻症"),
        ("住院津贴·后向", "轻症不保住院津贴"),
        ("身故责任·后向", "轻症不保身故责任"),
        ("意外医疗·后向", "轻症不保意外医疗"),
        ("住院医疗·后向", "轻症不保住院医疗"),
    ]
    for _tag, _clause in _SAME_FAMILY_RED_LINE:
        _got = bool(PD._crx_clause_excludes_subject(_clause, "轻症"))
        check(f"F31.2 红线「{_clause}」（{_tag}）→ 与轻症无关，不得判定为对轻症的除外",
              not _got, f"实际 {_got}")

    # ==================================================================
    # ③ F31.3 官方 T-1 / T-2 口径**保持**
    # ==================================================================
    _T12_KEEP = [
        ("T-1·后向", "轻症责任免除"),
        ("T-1·前向", "责任免除轻症"),
        ("T-2·后续子句", "轻症除外但含身故保障"),
        ("T-2·后续子句(住院津贴)", "轻症除外但含住院津贴"),
    ]
    for _tag, _clause in _T12_KEEP:
        _got = bool(PD._crx_clause_excludes_subject(_clause, "轻症"))
        check(f"F31.3 官方口径保持「{_clause}」（{_tag}）→ 必须判定为对轻症的除外",
              _got, f"实际 {_got}")

    # ==================================================================
    # ④ F31.4 端到端（**最终方案 JSON**）：同家族除外 → 不得宣称轻症
    # ==================================================================
    for _other in ("120种重疾不含轻症", "120种重疾不含轻症疾病"):
        for _kind, _kind_cn in (("standard", "标准版"), ("premium", "全面版")):
            _pl = _plan(_mutate_pool("120种重疾+60种轻症", _other), _kind)
            _entry = _ci_entry(_pl)
            _lims = _ci_limits(_pl)
            _matched = [l for l in _lims
                        if _entry is not None and l.get("product") == _entry.get("product_name")]
            check(f"F31.4 同家族除外「{_other}」→ {_kind_cn}最终 JSON 的重疾条目不得宣称轻症",
                  _entry is None or "轻症" not in (_entry.get("key_benefits") or ""),
                  f"实际 kb={(_entry or {}).get('key_benefits')!r}")
            _txt = _claim_text(_pl)
            check(f"F31.4 同家族除外「{_other}」→ {_kind_cn}宣称面不得出现「轻症」",
                  "轻症" not in _txt, "宣称面文案含轻症")
            check(f"F31.4 同家族除外「{_other}」→ {_kind_cn}须给出如实限制说明",
                  _entry is None or bool(_matched), f"limitations={_lims!r}")
            check(f"F31.4 同家族除外「{_other}」→ {_kind_cn}如实限制说明须点明「轻症」且待核实",
                  _entry is None or all("轻症" in (l.get("reason") or "")
                                        and "待核实" in (l.get("reason") or "")
                                        for l in _matched),
                  f"实际 {_matched!r}")
    # 红线端到端：除外确实指向别的保障对象 → 轻症宣称必须保留
    for _other in ("120种重疾不含住院津贴", "住院津贴不保轻症"):
        for _kind, _kind_cn in (("standard", "标准版"), ("premium", "全面版")):
            _pl = _plan(_mutate_pool("120种重疾+60种轻症", _other), _kind)
            _entry = _ci_entry(_pl)
            _lims = _ci_limits(_pl)
            _kb = (_entry or {}).get("key_benefits") or ""
            if _kind == "standard":
                check(f"F31.4 红线「{_other}」→ {_kind_cn}轻症宣称必须保留",
                      _entry is None or "轻症" in _kb, f"实际 kb={_kb!r}")
            else:
                check(f"F31.4 红线「{_other}」→ {_kind_cn}卖点不得被过度压制（置空）",
                      _entry is None or bool(_kb), f"实际 kb={_kb!r}")
            check(f"F31.4 红线「{_other}」→ {_kind_cn}不得凭空产生轻症限制说明",
                  not _lims, f"实际 limitations={_lims!r}")

    # ==================================================================
    # ⑤ F31.5 源码级防改回断言
    # ==================================================================
    src = open(os.path.join(SKILL_DIR, "scripts", "plan_designer.py"),
               "r", encoding="utf-8").read()
    check("F31.5 源码级：同家族 cue 表已定义",
          "_CRX_SAME_FAMILY_CUES" in src)
    check("F31.5 源码级：同家族 cue 表必须含「重疾」「重大疾病」「中症」",
          all(_c in src for _c in ('"重疾"', '"重大疾病"', '"中症"')))
    check("F31.5 源码级：同家族 cue 剔除函数已实现",
          "def _crx_strip_same_family_cues(" in src)
    check("F31.5 源码级：head 侧前序片段判定必须调用同家族剔除",
          "_crx_strip_same_family_cues(frag)" in src)
    check("F31.5 源码级：病种数路径口径**不得**被改动（仍用既有线索表）",
          "_CRX_COUNT_OTHER_OBJECT_CUES" in src
          and "def _crx_count_object_is_other(" in src
          and "def _crx_clause_excludes_disease_count(" in src)
    check("F31.5 源码级：残余 P 的 Tier A / Tier B 分层口径**不得**被改动",
          "_CRX_DISTINCT_OBJECT_CUES" in src
          and "_CRX_GENERIC_CUE_WORDS" in src
          and "def _crx_gap_object_evidence(" in src)
    return True



def test_f32_residual_uv_backward_binding(pd=None):
    """F32（官方 SDI-4 残余 U + 残余 V · 2026-11-24 · v2.4.36）

    【官方 finding（china v2.4.36 · SDI-4 · Excessive Agency · MEDIUM · 原文）】
      finding:
        "The documented record-wide disease-count safeguard can discard an
         explicit exclusion when another benefit is mentioned afterward."
      explanation:
        "The disease-count exclusion check skips an exclusion whenever its
         following window mentions another benefit, even if the exclusion already
         binds to the disease count: 「120种重疾除外但含身故保障」 is skipped
         because the suffix contains 「身故」. With affirmative highlights such as
         「120种重疾，含轻症保障」, the record-wide contradiction check can miss
         the same exclusion, allowing the final standard plan to advertise
         「120种重疾+轻症保障」. …"
      remediation:
        "Bind exclusions to their subjects using local grammatical scope:
         postposed markers such as 「除外」 and 「责任免除」 must remain attached to
         the preceding disease-count subject, regardless of a subsequent benefit
         clause. Distinguish these from forward-binding exclusions such as
         「不含轻症」, preferably using validated structured coverage decisions
         rather than keyword windows. Propagate unresolved evidence as an explicit
         limitation and suppress unsupported claims across benefits, features, and
         descriptions. Add end-to-end regression tests combining affirmative
         highlights with 「120种重疾除外但含身故保障」 in the same or another field,
         asserting that final JSON never advertises the excluded disease-count
         coverage."

    【官方 finding（ai v2.4.36 · SDI-4 · Excessive Agency · MEDIUM · 原文）】
      finding:
        "Already-bound critical-illness exclusions are discarded when a later
         phrase mentions another benefit."
      explanation:
        "The critical-illness exclusion checks can discard an exclusion because
         the text following it mentions another benefit: for example,
         「重疾除外但含身故保障」 is not classified as a category exclusion because
         the suffix contains 「身故」. Combined with affirmative counted highlights
         elsewhere, this allows downstream plans to advertise critical-illness
         coverage despite conflicting exclusion evidence, without the
         corresponding unverified limitation. …"
      remediation:
        "Bind each exclusion to its local coverage subject before evaluating
         subsequent benefits, and do not let later phrases revoke an already-bound
         exclusion. Prefer validated structured coverage decisions, reconcile
         conflicts record-wide, and propagate unresolved states into benefits,
         features, descriptions, and explicit limitations. Add end-to-end tests
         pairing affirmative counted highlights with 「重疾除外但含身故保障」 and
         equivalent exclusions in other fields for both standard and comprehensive
         plans."

    【官方 finding（ai v2.4.36 · SDI-4 · Excessive Agency · MEDIUM · 原文 · 残余 V）】
      finding:
        "Medical benefit generation can convert explicit noncoverage into an
         affirmative treatment claim."
      explanation:
        "Medical claim authorization still relies on affirmative keywords and an
         incomplete exclusion vocabulary: “CAR-T治疗不予给付” contains the
         affirmative marker “给付”, but “不予给付” is not recognized by the medical
         negation rules. With no other blocking evidence, this can become
         “含CAR-T治疗”, reversing an explicit noncoverage statement into a
         covered-benefit claim. …"
      remediation:
        "Require validated, treatment-specific coverage decisions before emitting
         affirmative benefit claims, preserving applicable conditions and
         suppressing unresolved evidence. If retaining free-text interpretation,
         consistently recognize nonpayment expressions such as “不予给付” in both
         authorization and record-wide exclusion checks, ensuring words within
         those expressions cannot authorize coverage. Add regression tests that
         verify final plan benefits and features never advertise treatments
         explicitly excluded by the source record."

    【根因（4 处 · 必须同时修）】
      ① `_crx_clause_excludes_disease_count` tail 侧用「标记**之后** 12 字窗口」
         判别的保障对象 → 后续保障从句撤销了已绑定的除外（残余 U-1）；
      ② `_crx_clause_excludes_ci_category` tail 侧同写法（残余 U-2）；
      ③ `_NEG_MARKERS_BOTH` 缺「不予给付 / 不予赔付」，而 `_AFFIRM_MARKERS` 含
         「给付」→ 「CAR-T治疗不予给付」被当承保（残余 V）；
      ④ **同源第三处（必需）**：`_crx_record_disease_count_issue` 第③步走
         `_crx_record_contradiction` → 内部调用共享函数
         `_crx_clause_excludes_subject` 的**非「症」主体分支** → 该分支同样有
         「后续从句撤销除外」+ head 侧只看标记**之后**的缺陷
         → 只改 ①② 的话验收器 ④ 仍会 FAIL（被判成 `contradiction`）。

    【修法】
      · 新增常量 `_CRX_BACKWARD_BINDING_MARKERS`（后向绑定标记：除外 / 责任免除 /
        不在保障范围 / 无保障 / 不在保障责任范围 / 不予给付 / 不予赔付 / 不予支付）
        ⚠ **不得**复用 / 扩写 `_CRX_POSTPOSED_EXCLUSION_MARKERS`（轻症路径
          残余 T 口径 → 扩写会回归）；
      · 病种数路径：后向标记 → 只看「标记**之前**」的片段判绑定对象，
        **不再**用「标记之后」的窗口撤销已绑定的除外；
      · 类别级路径：后向标记 → 直接判除外（跳过宾语窗口）；
      · 共享函数 `_crx_clause_excludes_subject`：**仅非「症」主体分支**补同构
        规则（轻症分支**一字不动**）；
      · 医疗：`_NEG_MARKERS_BOTH` 追加「不予给付」「不予赔付」（与「不予报销」
        同口径 · 双向绑定）→ 否定跨度吃掉内部的「给付 / 赔付」。

    覆盖：
      ① 病种数路径：后向绑定除外必须命中（残余 U-1）
      ② 类别级路径：后向绑定除外必须成立（残余 U-2）
      ③ 前向绑定口径**保持**（残余 U 红线 + 轻症路径官方 T-1 / T-2 一字不动）
      ④ 防过度收紧：后向标记绑定**别的保障对象** → 不得误伤
      ⑤ 残余 V · 医疗：不予给付 / 不予赔付 → 不得宣称 + 记录级除外证据收录
      ⑥ 残余 V · 防过度收紧：肯定表述仍可宣称
      ⑦ 端到端（**最终方案 JSON**）：被压制的保障不得出现在宣称面
      ⑧ 源码级防改回断言
    """
    print("\nTest F32: 残余 U + 残余 V（后向绑定除外 + 不予给付/不予赔付）")
    if pd is None:
        import plan_designer as PD
        PD = PD
    else:
        PD = pd

    with open(os.path.join(SKILL_DIR, "references", "products.json"), encoding="utf-8") as _fh:
        _PRODUCTS = json.load(_fh)["products"]
    _NEEDS = {"death": 1000000, "critical_illness": 500000}

    def _mutate_pool(highlights, other=""):
        """把**所有**重疾险产品改成指定 highlights / 其它字段表述 → 返回产品池"""
        pool = []
        for _p in _PRODUCTS:
            _q = dict(_p)
            if (_q.get("type") or "") == "重疾险":
                _q["highlights"] = highlights
                _q["key_benefits"] = [highlights]
                _q["notes"] = other
                _q["suitable_for"] = ""
                _q["weakness"] = []
                _q["competitive_edge"] = ""
            pool.append(_q)
        return pool

    def _plan(pool, kind):
        if kind == "standard":
            return PD.design_standard_plan(35, "男", 300000, 60000, _NEEDS, pool)
        return PD.design_premium_plan(35, "男", 300000, 80000, _NEEDS, pool)

    def _ci_entry(plan):
        return next((e for e in plan.get("products", []) if e.get("type") == "重疾险"), None)

    def _claim_text(plan):
        """方案里**对外宣称面**的文案（不含 limitations —— 限制说明里提到「轻症」是如实报告）"""
        chunks = [str(plan.get("description") or "")]
        for _e in plan.get("products", []):
            chunks.append(str(_e.get("key_benefits") or ""))
        for _f in plan.get("features", []):
            chunks.append(str(_f))
        return "\n".join(chunks)

    # ==================================================================
    # ① F32.1 病种数路径：后向绑定除外必须命中（残余 U-1）
    # ==================================================================
    _COUNT_BACKWARD = [
        ("notes", "120种重疾除外但含身故保障"),
        ("key_benefits", ["120种重疾除外但含身故保障"]),
        ("notes", "120种重疾责任免除但含身故保障"),
        ("key_benefits", ["120种重疾责任免除但含身故保障"]),
        ("notes", "120种重疾除外但含住院津贴"),
        ("notes", "120种重疾不在保障范围但含身故保障"),
        ("notes", "120种重疾不予给付但含身故保障"),
    ]
    for _field, _val in _COUNT_BACKWARD:
        _prod = {"highlights": "120种重疾+60种轻症", _field: _val}
        _code = PD._crx_record_disease_count_issue(_prod, "120种重疾")
        check(f"F32.1 病种数后向除外必须命中（{_val}·{_field}）",
              _code in ("excluded", "category-excluded"), f"实际 {_code!r}")
        _got = PD._crx_disease_claim(_prod)
        check(f"F32.1 病种数宣称必须压制（{_val}·{_field}）",
              _got == "", f"实际 {_got!r}")

    # ==================================================================
    # ② F32.2 类别级路径：后向绑定除外必须成立（残余 U-2）
    # ==================================================================
    _CI_BACKWARD = [
        ("notes", "重疾除外但含身故保障"),
        ("key_benefits", ["重疾除外但含身故保障"]),
        ("notes", "重疾责任免除但含身故保障"),
        ("notes", "重疾不在保障范围但含身故保障"),
    ]
    for _field, _val in _CI_BACKWARD:
        _prod = {"highlights": "120种重疾+60种轻症", _field: _val}
        _excl = PD._crx_record_ci_category_excluded(_prod)
        check(f"F32.2 类别级后向除外必须成立（{_val}·{_field}）",
              bool(_excl), f"实际 {_excl!r}")
        _code = PD._crx_record_disease_count_issue(_prod, "120种重疾")
        check(f"F32.2 类别级除外须绑定到病种数（{_val}·{_field}）",
              _code in ("excluded", "category-excluded"), f"实际 {_code!r}")
        _got = PD._crx_disease_claim(_prod)
        check(f"F32.2 病种数宣称必须压制（{_val}·{_field}）",
              _got == "", f"实际 {_got!r}")

    # ==================================================================
    # ③ F32.3 前向绑定口径**保持**（残余 U 红线）+ 轻症路径官方口径**保持**
    # ==================================================================
    _FORWARD_KEEP_COUNT = [
        "120种重疾不含轻症",
        "120种重疾不保轻症",
        "120种重疾不承保轻症",
    ]
    for _clause in _FORWARD_KEEP_COUNT:
        _got = PD._crx_clause_excludes_disease_count(_clause, "120种重疾")
        check(f"F32.3 前向绑定：病种数专属除外判定为 False（{_clause}）",
              _got is False, f"实际 {_got!r}")
    _MILD_KEEP = [
        "轻症责任免除",
        "责任免除轻症",
        "轻症除外但含身故保障",
        "轻症除外但含住院津贴",
    ]
    for _clause in _MILD_KEEP:
        _got = bool(PD._crx_clause_excludes_subject(_clause, "轻症"))
        check(f"F32.3 轻症路径官方口径保持（{_clause}）→ 必须判定为对轻症的除外",
              _got, f"实际 {_got}")
    for _clause in ("轻症不保住院津贴", "轻症不保身故责任", "住院津贴不保轻症"):
        _got = bool(PD._crx_clause_excludes_subject(_clause, "轻症"))
        check(f"F32.3 轻症路径红线保持（{_clause}）→ 与轻症无关，不得判定为除外",
              not _got, f"实际 {_got}")

    # ==================================================================
    # ④ F32.4 防过度收紧：后向标记绑定**别的保障对象** → 不得误伤病种数
    # ==================================================================
    _OTHER_OBJECT = [
        "120种重疾保障住院津贴除外",
        "住院津贴除外后120种重疾照常承保",
    ]
    for _clause in _OTHER_OBJECT:
        _prod = {"highlights": "120种重疾+60种轻症", "notes": _clause}
        _code = PD._crx_record_disease_count_issue(_prod, "120种重疾")
        check(f"F32.4 后向标记绑定别的对象时病种数不得误伤（{_clause}）",
              _code == "", f"实际 {_code!r}")
        _got = PD._crx_disease_claim(_prod)
        check(f"F32.4 整句宣称不得受影响（{_clause}）",
              _got != "", f"实际 {_got!r}")

    # ==================================================================
    # ⑤ F32.5 残余 V · 医疗：不予给付 / 不予赔付 → 不得宣称 + 除外证据收录
    # ==================================================================
    for _neg in ("CAR-T治疗不予给付", "CAR-T治疗不予赔付"):
        _prod = {"key_benefits": [_neg], "highlights": _neg}
        _claims = PD._medical_treatment_claims(_prod)
        check(f"F32.5 「{_neg}」不得宣称 CAR-T 治疗",
              not any("CAR-T" in c for c in _claims), f"实际 {_claims!r}")
        _excl = PD._record_exclusion_keywords(_prod)
        check(f"F32.5 「{_neg}」记录级除外证据必须收录 CAR-T 治疗",
              any("CAR-T" in k for k in _excl), f"实际 {sorted(_excl)!r}")
        try:
            _kb = PD.derive_medical_key_benefits(_prod, [])
            _blob = json.dumps(_kb, ensure_ascii=False)
        except Exception as _e:  # noqa: BLE001
            _blob = "__ERR__:%r" % (_e,)
        check(f"F32.5 「{_neg}」端到端：最终 key_benefits 不得出现「含CAR-T治疗」",
              "含CAR-T治疗" not in _blob, _blob[:300])

    # ==================================================================
    # ⑥ F32.6 残余 V · 防过度收紧：肯定表述仍可宣称
    # ==================================================================
    for _ok in ("含CAR-T治疗费用报销", "CAR-T治疗可报销"):
        _prod = {"key_benefits": [_ok], "highlights": _ok}
        _claims = PD._medical_treatment_claims(_prod)
        check(f"F32.6 肯定表述「{_ok}」仍可宣称",
              any("CAR-T" in c for c in _claims), f"实际 {_claims!r}")

    # ==================================================================
    # ⑦ F32.7 端到端（**最终方案 JSON**）：被压制的保障不得出现在宣称面
    # ==================================================================
    for _other in ("120种重疾除外但含身故保障", "重疾除外但含身故保障"):
        for _kind, _kind_cn in (("standard", "标准版"), ("premium", "全面版")):
            _pl = _plan(_mutate_pool("120种重疾+60种轻症", _other), _kind)
            _entry = _ci_entry(_pl)
            _kb = (_entry or {}).get("key_benefits") or ""
            check(f"F32.7 端到端：{_other} → {_kind_cn}重疾条目不得宣称轻症",
                  _entry is None or "轻症" not in _kb, f"实际 kb={_kb!r}")
            _txt = _claim_text(_pl)
            check(f"F32.7 端到端：{_other} → {_kind_cn}宣称面不得出现「轻症」",
                  "轻症" not in _txt, f"宣称面文案含轻症：{_txt[:200]!r}")

    # ==================================================================
    # ⑧ F32.8 源码级防改回断言
    # ==================================================================
    src = open(os.path.join(SKILL_DIR, "scripts", "plan_designer.py"),
               "r", encoding="utf-8").read()
    check("F32.8 源码级：后向绑定标记表已定义",
          "_CRX_BACKWARD_BINDING_MARKERS" in src)
    check("F32.8 源码级：后向绑定标记表必须含「除外」「责任免除」「不予给付」「不予赔付」",
          all(_c in src for _c in ('"除外"', '"责任免除"', '"不予给付"', '"不予赔付"')))
    _post_block = src.split("_CRX_POSTPOSED_EXCLUSION_MARKERS = (")[1].split(")")[0]
    check("F32.8 源码级：轻症路径后置型标记表**不得**被扩写（残余 T 口径保持）",
          "不予给付" not in _post_block and "不予赔付" not in _post_block)
    check("F32.8 源码级：病种数 tail 侧必须用**前置片段**判定后向标记",
          "_crx_count_object_is_other(tail[:_s])" in src)
    check("F32.8 源码级：病种数 head 侧必须用**前置片段**判定后向标记",
          "_crx_count_object_is_other(head[:pos])" in src)
    check("F32.8 源码级：类别级 tail 侧必须对后向标记直接判除外（不查宾语窗口）",
          "_crx_ci_marker_positions(tail)" in src
          and "mk in _CRX_BACKWARD_BINDING_MARKERS" in src)
    check("F32.8 源码级：共享函数的非「症」分支必须按后向绑定判定（根因④）",
          "mk in _CRX_BACKWARD_BINDING_MARKERS" in src
          and "_crx_subject_gap_targets_other_object(head[:pos], subject)" in src)
    check("F32.8 源码级：医疗否定词表必须含「不予给付」「不予赔付」（残余 V）",
          '"不予给付", "不予赔付"' in src)
    check("F32.8 源码级：残余 P 的 Tier A / Tier B 分层口径**不得**被改动",
          "_CRX_DISTINCT_OBJECT_CUES" in src
          and "_CRX_GENERIC_CUE_WORDS" in src
          and "def _crx_gap_object_evidence(" in src)
    return True


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
    test_f11_income_multiple_claim_sync(pd)
    test_f12_crx_claim_derivation(pd)
    test_f13_treatment_negation_context(pd)
    test_f14_treatment_negation_scope(pd)
    test_f15_whitespace_negation_scope(pd)
    test_f16_mixed_negation_authorization(pd)
    test_f17_residual_f_structured_authority(pd)
    test_f18_residual_g_conflicting_decision_keys(pd)
    test_f19_residual_h_exclusion_and_reimbursement(pd)
    test_f20_residual_i_bare_string_identifier(pd)
    test_f21_residual_j_post_treatment_negation(pd)
    test_f22_residual_k_uncertainty_guard(pd)
    test_f23_residual_lmn_conditions_and_structured_authority(pd)
    test_f24_residual_n2_bidirectional_exclusion(pd)
    test_f25_residual_o_disease_count_record_gate(pd)
    test_f26_residual_pq_subject_and_category_exclusion(pd)
    test_f27_residual_r_shared_coverage_state(pd)
    test_f28_residual_s_shared_mild_state(pd)
    test_f29_residual_p_generic_cue_distinct_object(pd)
    test_f30_residual_t_local_binding(pd)
    test_f31_residual_t_same_family_binding(pd)
    test_f32_residual_uv_backward_binding(pd)
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
