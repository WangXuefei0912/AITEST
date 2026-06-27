import os
import csv
import json
import hashlib
import requests
from natsort import natsorted
#import re
# =========================
# 配置（请根据实际修改）
# =========================
ROOT_DIR = "/data/example-s2/code1"
RES_DIR = "/data/example-s2"
OUTPUT_CSV = os.path.join(RES_DIR, "result.csv")
LLM_API_URL = "http://localhost:8000/v1/completions"
MODEL_NAME = "/data/model/Qwen3-Coder-30B-A3B-Instruct"
MAX_FILE_SIZE = 100 * 1024

# =========================
# MD5计算
# =========================
def calc_md5(filepath):
    md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        while True:
            data = f.read(8192)
            if not data:
                break
            md5.update(data)
    return md5.hexdigest()

# =========================
# 读取文件（仅读前 MAX_FILE_SIZE 字节）
# =========================
def read_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(MAX_FILE_SIZE)
        return content
    except Exception as e:
        print(f"[ERROR] Read file failed: {filepath}, {e}")
        return ""

# =========================
# 调用大模型审计（返回中文JSON）
# =========================
def audit_code(filepath, code_content):
    prompt = f"""
你是一名资深代码审计专家。
请对下面代码进行安全审计，并用中文回答。
要求：
1. 判断是否存在漏洞，如果有返回"是"，否则返回"否"。
2. 给出漏洞起始行（整数）。
3. 给出漏洞结束行（整数）。
4. 给出漏洞编号（CWE/CVE），若无则留空。
5. 给出漏洞类型（中文）。
6. 给出漏洞描述（中文）。
必须仅返回JSON，不允许输出任何解释。
返回格式（存在漏洞时）：
{{
    "has_vulnerability": "是",
    "start_line": 10,
    "end_line": 20,
    "vuln_id": "CWE-79",
    "vuln_type": "跨站脚本攻击",
    "description": "用户输入未过滤导致XSS"
}}
如果不存在漏洞：
{{
    "has_vulnerability": "否",
    "start_line": "",
    "end_line": "",
    "vuln_id": "",
    "vuln_type": "",
    "description": ""
}}
文件路径:
{filepath}
代码如下：
```text
{code_content}
"""
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "max_tokens": 1024,
        "temperature": 0
    }

    try:
        response = requests.post(
            LLM_API_URL,
            json=payload,
            timeout=300
        )
        response.raise_for_status()
        result = response.json()
        text = result["choices"][0]["text"].strip()

        # 提取JSON
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            text = text[start:end + 1]

        return json.loads(text)

    except Exception as e:
        print(f"[ERROR] Audit failed: {filepath}")
        print(e)
        return {
            "has_vulnerability": "错误",
            "start_line": "",
            "end_line": "",
            "vuln_id": "",
            "vuln_type": "",
            "description": str(e)
        }

# =========================
# 获取所有文件（过滤输出文件，按文件名升序）
# =========================
"""
def natural_key(filename):
    return [int(part) if part.isdigit() else part for part in re.split(r'(\d+)', filename)]
"""

def get_all_files(root_dir):
    files = []
    for root, dirs, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename == os.path.basename(OUTPUT_CSV):
                continue
            full_path = os.path.join(root, filename)
            if os.path.isfile(full_path):
                files.append(full_path)
    # 使用 natsorted 按文件名自然排序
    files = natsorted(files, key=lambda x: os.path.basename(x))
    return files

# =========================
# 主函数
# =========================
def main():
    # 表头：新增“序号”列放在最前面
    headers = [
        "序号",
        "项目名（文件夹）",
        "目标文件（文件名）",
        "目录文件路径",
        "文件md5",
        "是否存在漏洞",
        "漏洞起始行",
        "漏洞结束行",
        "漏洞编号（CWE、CVE）",
        "漏洞类型",
        "漏洞描述"
    ]

    files = get_all_files(ROOT_DIR)

    # ===== 每次运行重新生成CSV（覆盖旧文件）=====
    # 先以写入模式打开，写入表头，然后关闭，后续用追加模式
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8-sig") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)

    # 逐个审计并实时追加一行（包含序号）
    total = len(files)
    for idx, filepath in enumerate(files, start=1):  # idx 从1开始作为序号
        print(f"[+] Auditing ({idx}/{total}): {filepath}")

        folder = os.path.basename(os.path.dirname(filepath))
        filename = os.path.basename(filepath)

        md5 = calc_md5(filepath)
        code = read_file(filepath)
        audit_result = audit_code(filepath, code)

        # 构造数据行，序号放在最前面
        row = [
            idx, # 序号
            folder,
            filename,
            filepath,
            md5,
            audit_result.get("has_vulnerability", ""),
            audit_result.get("start_line", ""),
            audit_result.get("end_line", ""),
            audit_result.get("vuln_id", ""),
            audit_result.get("vuln_type", ""),
            audit_result.get("description", "")
        ]

        # 实时追加一行（每次打开文件追加后立即关闭）
        with open(OUTPUT_CSV, "a", newline="", encoding="utf-8-sig") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(row)

        print(f"   已写入序号 {idx} 的文件: {filename}")

    print(f"\n审计完成，结果已实时保存至: {OUTPUT_CSV}")

if __name__ == "__main__":
    main()