import os
import csv
import json
import hashlib
import requests
import threading
import time
from natsort import natsorted
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

# =========================
# 配置（请根据实际修改）
# =========================
ROOT_DIR = "/data/example-s2/code1"
RES_DIR = "/data/example-s2"
OUTPUT_CSV = os.path.join(RES_DIR, "result.csv")

LLM_API_URL = "http://localhost:8000/v1/chat/completions"
MODEL_NAME = "/data/model/Qwen3-Coder-30B-A3B-Instruct"
MAX_FILE_SIZE = 100 * 1024  # 100KB

# =========================
# 并发配置
# =========================
MAX_WORKERS = 32
MAX_RETRIES = 3
RETRY_DELAY = 2

# =========================
# 全局连接池 + CSV写入缓冲
# =========================
http_session = requests.Session()
adapter = requests.adapters.HTTPAdapter(
    pool_connections=MAX_WORKERS,
    pool_maxsize=MAX_WORKERS * 2,
    max_retries=0
)
http_session.mount("http://", adapter)

csv_lock = threading.Lock()
csv_buffer = []

# =========================
# 断点续传读取已完成MD5
# =========================
def load_completed_md5s():
    completed = set()
    if os.path.exists(OUTPUT_CSV):
        try:
            with open(OUTPUT_CSV, "r", encoding="utf-8-sig") as f:
                reader = csv.reader(f)
                next(reader, None)  # skip header
                for row in reader:
                    if len(row) >= 5:
                        completed.add(row[4])  # md5 列
        except Exception:
            pass
    return completed

# =========================
# 工具函数
# =========================
def read_file_and_md5(filepath):
    """合并MD5计算和文件读取为一次I/O，返回md5和截断后的内容"""
    md5 = hashlib.md5()
    content_chunks = []
    total_read = 0
    try:
        with open(filepath, "rb") as f:
            while True:
                data = f.read(8192)
                if not data:
                    break
                md5.update(data)
                if total_read < MAX_FILE_SIZE:
                    remaining = MAX_FILE_SIZE - total_read
                    content_chunks.append(data[:remaining])
                    total_read += len(data[:remaining])
        content = b"".join(content_chunks).decode("utf-8", errors="ignore")
        return md5.hexdigest(), content
    except Exception:
        return "", ""

def get_all_files(root_dir):
    files = []
    for root, dirs, filenames in os.walk(root_dir):
        for filename in filenames:
            # 跳过输出CSV本身
            if filename == os.path.basename(OUTPUT_CSV):
                continue
            full_path = os.path.join(root, filename)
            if os.path.isfile(full_path):
                files.append(full_path)
    files = natsorted(files, key=lambda x: os.path.basename(x))
    return files

# =========================
# 核心审计逻辑（已修复缩进和异常处理）
# =========================
def audit_code(filepath, code_content):
    system_prompt = """你是一名资深代码审计专家。请对用户提供的代码进行安全审计，并用中文回答。
要求：
1. 判断是否存在漏洞，返回"是"或"否"。
2. 如果存在漏洞，给出起始行、结束行、漏洞编号(CWE/CVE)、漏洞类型(中文)、漏洞描述(中文)。
3. 必须仅返回JSON，不要包含Markdown标记或其他解释。
返回格式示例：
{"has_vulnerability": "是", "start_line": 10, "end_line": 20, "vuln_id": "CWE-79", "vuln_type": "跨站脚本攻击", "description": "..."}
或者（无漏洞时）：
{"has_vulnerability": "否", "start_line": "", "end_line": "", "vuln_id": "", "vuln_type": "", "description": ""}"""

    user_prompt = f"文件路径: {filepath}\n代码如下：\n{code_content}"

    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "max_tokens": 512,
        "temperature": 0,
    }

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = http_session.post(LLM_API_URL, json=payload, timeout=300)

            if response.status_code != 200:
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY * attempt)
                    continue
                return {
                    "has_vulnerability": "API错误",
                    "description": f"Status: {response.status_code}, {response.text[:100]}"
                }

            result = response.json()
            text = result["choices"][0]["message"]["content"].strip()

            # 去除可能的 Markdown 代码块标记
            if "```json" in text:
                text = text.replace("```json", "").replace("```", "").strip()

            start = text.find("{")
            end = text.rfind("}")
            if start >= 0 and end > start:
                json_str = text[start:end + 1]
                return json.loads(json_str)
            else:
                return {
                    "has_vulnerability": "解析失败",
                    "description": f"模型返回非JSON格式: {text[:50]}"
                }

        except json.JSONDecodeError:
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY * attempt)
                continue
            return {"has_vulnerability": "解析错误", "description": "JSON解码失败"}

        except requests.exceptions.Timeout:
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY * attempt)
                continue
            return {"has_vulnerability": "超时", "description": "模型推理超时"}

        except requests.exceptions.ConnectionError:
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY * attempt)
                continue
            return {"has_vulnerability": "连接错误", "description": "无法连接到模型服务"}

        except Exception as e:
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY * attempt)
                continue
            return {"has_vulnerability": "异常", "description": str(e)}

    return {"has_vulnerability": "失败", "description": "重试次数耗尽"}

# =========================
# CSV 后台写入线程
# =========================
csv_flush_event = threading.Event()
csv_writer_thread = None
csv_stop_flag = threading.Event()

def csv_writer_worker(output_path):
    """后台线程：定期将缓冲区数据刷写到CSV文件"""
    while not csv_stop_flag.is_set() or csv_buffer:
        if csv_flush_event.wait(timeout=2.0) or csv_buffer:
            csv_flush_event.clear()
            with csv_lock:
                if not csv_buffer:
                    continue
                rows_to_write = csv_buffer.copy()
                csv_buffer.clear()
            # 批量写入（在锁外进行I/O）
            with open(output_path, "a", newline="", encoding="utf-8-sig") as csvfile:
                writer = csv.writer(csvfile)
                for row in rows_to_write:
                    writer.writerow(row)

# =========================
# 单个任务处理流程
# =========================
def process_file(idx, filepath, pbar, completed_md5s):
    folder = os.path.basename(os.path.dirname(filepath))
    filename = os.path.basename(filepath)

    md5, code = read_file_and_md5(filepath)

    # 如果MD5为空（读文件失败）或已在已完成集合中，则跳过
    if not md5:
        # 无法读取文件，记录错误行
        row = [
            idx, folder, filename, filepath, "",
            "读取失败", "", "", "", "", "文件无法读取或MD5计算失败"
        ]
        with csv_lock:
            csv_buffer.append(row)
        if pbar:
            pbar.update(1)
        return filename

    if md5 in completed_md5s:
        if pbar:
            pbar.update(1)
        return filename

    # 调用模型审计
    audit_result = audit_code(filepath, code)

    row = [
        idx, folder, filename, filepath, md5,
        audit_result.get("has_vulnerability", ""),
        audit_result.get("start_line", ""),
        audit_result.get("end_line", ""),
        audit_result.get("vuln_id", ""),
        audit_result.get("vuln_type", ""),
        audit_result.get("description", "")
    ]

    with csv_lock:
        csv_buffer.append(row)

    if pbar:
        pbar.update(1)

    return filename

def sort_csv_by_index(output_path):
    """读取CSV，按第一列(序号)数值升序排序后重写"""
    with open(output_path, "r", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        rows = list(reader)

    # 修复：过滤掉空行，并增加长度判断，防止 IndexError
    rows = [r for r in rows if r and len(r) > 0]
    rows.sort(key=lambda r: int(r[0]) if r[0].isdigit() else 0)

    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        if header:
            writer.writerow(header)
        writer.writerows(rows)

# =========================
# 主函数
# =========================
def main():
    headers = [
        "序号", "项目名（文件夹）", "目标文件（文件名）", "目录文件路径",
        "文件md5", "是否存在漏洞", "漏洞起始行", "漏洞结束行",
        "漏洞编号（CWE、CVE）", "漏洞类型", "漏洞描述"
    ]

    files = get_all_files(ROOT_DIR)
    total = len(files)
    if total == 0:
        print("未找到文件。")
        return

    # 断点续传
    completed_md5s = load_completed_md5s()
    if completed_md5s:
        print(f"[INFO] 检测到已有结果文件，已完成 {len(completed_md5s)} 个文件（将跳过）")

    is_resume = len(completed_md5s) > 0
    if not is_resume:
        # 首次运行，创建CSV并写入表头
        with open(OUTPUT_CSV, "w", newline="", encoding="utf-8-sig") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)

    print(f"[INFO] 检测到文件总数: {total}")
    print(f"[INFO] 并发线程数: {MAX_WORKERS}")
    print(f"[INFO] 模型服务地址: {LLM_API_URL}")
    print(f"[INFO] 断点续传: {'是' if is_resume else '否'}")

    # 启动后台CSV写入线程
    global csv_writer_thread
    csv_stop_flag.clear()
    csv_writer_thread = threading.Thread(
        target=csv_writer_worker, args=(OUTPUT_CSV,), daemon=True
    )
    csv_writer_thread.start()

    pbar = tqdm(total=total, desc="审计进度", unit="file") if tqdm else None

    # 并发执行
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(process_file, idx, filepath, pbar, completed_md5s): idx
            for idx, filepath in enumerate(files, start=1)
        }

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"\n[ERROR] Task failed: {e}")

    # 等待所有数据写入完成
    csv_stop_flag.set()
    csv_flush_event.set()
    csv_writer_thread.join(timeout=30)  # 适当增加超时时间

    # 修复：如果超时后缓冲区仍有数据，强制写入一次，确保数据不丢失
    if csv_buffer:
        with csv_lock:
            rows_to_write = csv_buffer.copy()
            csv_buffer.clear()
        with open(OUTPUT_CSV, "a", newline="", encoding="utf-8-sig") as csvfile:
            writer = csv.writer(csvfile)
            for row in rows_to_write:
                writer.writerow(row)

    if pbar:
        pbar.close()

    # 最终按序号排序CSV
    print("[INFO] 正在按文件序号排序结果...")
    sort_csv_by_index(OUTPUT_CSV)
    print(f"\n[SUCCESS] 审计完成，结果文件: {OUTPUT_CSV}")

if __name__ == "__main__":
    main()