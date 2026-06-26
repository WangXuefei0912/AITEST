import os
import csv
import json
import hashlib
import requests

# =========================
# 配置（请根据实际修改）
# =========================
ROOT_DIR = "/data/example-s2/code1"          # 待审计的代码根目录
OUTPUT_CSV = os.path.join(ROOT_DIR, "result.csv")
LLM_API_URL = "http://localhost:8000/v1/completions"  # 你的LLM API地址
MODEL_NAME = "default"
MAX_FILE_SIZE = 100 * 1024  # 每个文件最大读取100KB（可调整）

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
# 调用大模型审计
# =========================
def audit_code(filepath, code_content):
    prompt = f"""
你是一名资深代码审计专家。
请对下面代码进行安全审计。
要求：
1. 判断是否存在安全漏洞
2. 给出漏洞起始行
3. 给出漏洞结束行
4. 给出漏洞编号(CWE/CVE)
5. 给出漏洞类型
6. 给出漏洞描述
必须仅返回JSON，不允许输出任何解释。
返回格式：
{{
    "has_vulnerability": true,
    "start_line": 10,
    "end_line": 20,
    "vuln_id": "CWE-79",
    "vuln_type": "Cross Site Scripting",
    "description": "用户输入未过滤导致XSS"
}}

如果不存在漏洞：

{{
    "has_vulnerability": false,
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

        # OpenAI兼容格式
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
            "has_vulnerability": "ERROR",
            "start_line": "",
            "end_line": "",
            "vuln_id": "",
            "vuln_type": "",
            "description": str(e)
        }
def get_all_files(root_dir):
    files = []
    for root, dirs, filenames in os.walk(root_dir):

        for filename in filenames:

            if filename == "result.csv":
                continue

            full_path = os.path.join(root, filename)

            if os.path.isfile(full_path):
                files.append(full_path)

    return files
def main():
    headers = [
        "folder",
        "filename",
        "filepath",
        "md5",
        "has_vulnerability",
        "start_line",
        "end_line",
        "vuln_id",
        "vuln_type",
        "description"
    ]

    files = get_all_files(ROOT_DIR)

    with open(
            OUTPUT_CSV,
            "w",
            newline="",
            encoding="utf-8-sig"
    ) as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow(headers)

        for filepath in files:
            print(f"[+] Auditing: {filepath}")

            folder = os.path.basename(os.path.dirname(filepath))
            filename = os.path.basename(filepath)

            md5 = calc_md5(filepath)

            code = read_file(filepath)

            audit_result = audit_code(filepath, code)

            writer.writerow([
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
            ])

            csvfile.flush()

    print(f"\n审计完成，结果已保存至: {OUTPUT_CSV}")
if __name__=="__main__":
    main()
