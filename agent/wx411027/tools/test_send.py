"""向 wx411027 HTTP API 发送一条 filehelper 测试消息。"""
import json
import time
import urllib.request

URL = "http://127.0.0.1:19088/api/message/text"
payload = {
    "contactId": "filehelper",
    "text": f"wx411027-{int(time.time())}",
}
data = json.dumps(payload).encode("utf-8")
req = urllib.request.Request(
    URL, data=data, headers={"Content-Type": "application/json"}, method="POST"
)
with urllib.request.urlopen(req, timeout=20) as resp:
    print(resp.read().decode("utf-8"))
