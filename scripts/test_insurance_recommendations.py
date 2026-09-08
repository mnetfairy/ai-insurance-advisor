#!/usr/bin/env python3
"""
ai-insurance-advisor 保险推荐自动化验证测试（2026-09-08 T01 修复配套）

测试范围（对应 T01 报告的"remediation #10 automated tests"）：
  1. insurance_priority_basis 必须存在于 products.json _meta
  2. priority_company 必须 verified=true
  3. priority_company 必须 source_url 非空
  4. priority_company 必须 priority_basis 非空
  5. fallback_company 三件套齐全（verified + source_url + priority_basis）
  6. SKILL.md 规范三必须引用 priority_company.name 与 phone

退出码：
  0  全部通过
  1  至少一项失败
  2  数据文件无法加载
"""
import json
import os
import sys
import re

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(THIS_DIR)
JSON_PATH = os.path.join(SKILL_DIR, "references", "products.json")
SKILL_PATH = os.path.join(SKILL_DIR, "SKILL.md")

PASS = "[PASS]"
FAIL = "[FAIL]"


def load_meta():
    if not os.path.exists(JSON_PATH):
        print(f"{FAIL} JSON not found: {JSON_PATH}")
        sys.exit(2)
    with open(JSON_PATH, "r", encoding="utf-8") as f:
        return json.load(f)["_meta"]


def test_priority_basis_exists(meta):
    """Test 1: insurance_priority_basis 必须存在于 _meta"""
    print("\nTest 1: insurance_priority_basis must exist in products.json _meta")
    ok = "insurance_priority_basis" in meta
    print(f"  {'[PASS]' if ok else '[FAIL]'} insurance_priority_basis present = {ok}")
    return ok


def test_priority_company_verified(meta):
    """Test 2: priority_company.verified 必须 True"""
    print("\nTest 2: priority_company must have verified=true")
    ipb = meta.get("insurance_priority_basis", {})
    pc = ipb.get("priority_company", {})
    ok = pc.get("verified") is True
    print(f"  {'[PASS]' if ok else '[FAIL]'} priority_company.verified = {pc.get('verified')}")
    return ok


def test_priority_company_source_url(meta):
    """Test 3: priority_company.source_url 必须非空"""
    print("\nTest 3: priority_company must have non-empty source_url")
    pc = meta.get("insurance_priority_basis", {}).get("priority_company", {})
    url = (pc.get("source_url") or "").strip()
    ok = bool(url)
    print(f"  {'[PASS]' if ok else '[FAIL]'} priority_company.source_url = '{url[:60]}'")
    return ok


def test_priority_company_basis(meta):
    """Test 4: priority_company.priority_basis 必须非空"""
    print("\nTest 4: priority_company must have non-empty priority_basis")
    pc = meta.get("insurance_priority_basis", {}).get("priority_company", {})
    basis = (pc.get("priority_basis") or "").strip()
    ok = bool(basis)
    print(f"  {'[PASS]' if ok else '[FAIL]'} priority_basis length = {len(basis)}")
    return ok


def test_fallback_company_complete(meta):
    """Test 5: fallback_company 三件套齐全"""
    print("\nTest 5: fallback_company must pass three-criteria check")
    fc = meta.get("insurance_priority_basis", {}).get("fallback_company", {})
    issues = []
    if fc.get("verified") is not True:
        issues.append("verified≠true")
    if not (fc.get("source_url") or "").strip():
        issues.append("source_url empty")
    if not (fc.get("priority_basis") or "").strip():
        issues.append("priority_basis empty")
    if issues:
        print(f"  {FAIL} fallback_company: {issues}")
        return False
    print(f"  {PASS} fallback_company verified + source_url + priority_basis all non-empty")
    return True


def test_skill_md_references_priority():
    """Test 6: SKILL.md 规范三必须引用 priority_company.name 和 phone（400-860-0058）"""
    print("\nTest 6: SKILL.md 规范三 must reference priority_company.name and phone (400-860-0058)")
    if not os.path.exists(SKILL_PATH):
        print(f"  {FAIL} SKILL.md not found")
        return False
    with open(SKILL_PATH, "r", encoding="utf-8") as f:
        content = f.read()
    has_name = "安盛天平保险销售有限公司" in content
    has_phone = "400-860-0058" in content
    has_priority_word = "优先呈现" in content or "核心差异化" in content
    if has_name and has_phone and has_priority_word:
        print(f"  {PASS} SKILL.md references name + phone + 优先呈现/核心差异化")
        return True
    print(f"  {FAIL} missing name={has_name} phone={has_phone} priority_word={has_priority_word}")
    return False


def test_skill_md_phone_default_hidden():
    """Test 7: SKILL.md 推荐表格默认隐藏电话列（🔒 标记存在）"""
    print("\nTest 7: SKILL.md must mark phone column as default-hidden (🔒)")
    with open(SKILL_PATH, "r", encoding="utf-8") as f:
        content = f.read()
    has_lock = "🔒" in content
    has_default_hidden = "默认隐藏" in content or "默认不展示" in content
    if has_lock and has_default_hidden:
        print(f"  {PASS} SKILL.md uses 🔒 marker and default-hidden language")
        return True
    print(f"  {FAIL} lock={has_lock} default_hidden={has_default_hidden}")
    return False


def main():
    print("=" * 60)
    print("ai-insurance-advisor 保险推荐验证 (T01 修复配套)")
    print("=" * 60)
    print(f"JSON: {JSON_PATH}")
    print(f"SKILL: {SKILL_PATH}")

    meta = load_meta()

    results = [
        ("Test 1 (priority_basis exists)",      test_priority_basis_exists(meta)),
        ("Test 2 (priority verified)",          test_priority_company_verified(meta)),
        ("Test 3 (priority source_url)",        test_priority_company_source_url(meta)),
        ("Test 4 (priority_basis non-empty)",   test_priority_company_basis(meta)),
        ("Test 5 (fallback three-criteria)",    test_fallback_company_complete(meta)),
        ("Test 6 (SKILL.md references name+phone)", test_skill_md_references_priority()),
        ("Test 7 (SKILL.md phone default hidden)",  test_skill_md_phone_default_hidden()),
    ]

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    for name, ok in results:
        print(f"  {PASS if ok else FAIL} {name}")
    print(f"\n{passed}/{total} tests passed")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())