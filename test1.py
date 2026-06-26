import requests
url = "http://localhost:8000/v1/completions"
payload = {
    "model": "/data/model/Qwen3-Coder-30B-A3B-Instruct",  # 与 curl 中完全一致
    "prompt": "Hello, how are you?",
    "max_tokens": 50
}
resp = requests.post(url, json=payload, timeout=10)
print("Status:", resp.status_code)
print("Response:", resp.text)