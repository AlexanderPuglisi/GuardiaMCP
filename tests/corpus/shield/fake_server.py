import json
import sys
import time

FLAGS = set(sys.argv[1:])
SUPPORTED = ["2026-07-28", "2025-11-25"]


def send(message):
    sys.stdout.buffer.write(json.dumps(message).encode("utf-8") + b"\n")
    sys.stdout.buffer.flush()


def send_raw(data):
    sys.stdout.buffer.write(data + b"\n")
    sys.stdout.buffer.flush()


def result(request_id, value):
    send({"jsonrpc": "2.0", "id": request_id, "result": value})


def handle(message):
    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params") or {}
    if method == "initialize":
        result(
            request_id,
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake", "version": "1.0.0"},
            },
        )
        if "--server-request" in FLAGS:
            send({"jsonrpc": "2.0", "id": "s1", "method": "sampling/createMessage", "params": {}})
    elif method == "server/discover":
        result(
            request_id,
            {
                "resultType": "complete",
                "supportedVersions": SUPPORTED,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake", "version": "1.0.0"},
            },
        )
    elif method == "tools/list":
        tools = [{"name": "echo", "description": "Echoes text.", "inputSchema": {"type": "object"}}]
        if "--duplicate-keys" in FLAGS:
            send_raw(
                b'{"jsonrpc":"2.0","id":%s,"result":{"tools":[]},"result":{"tools":[]}}'
                % json.dumps(request_id).encode()
            )
            return
        result(request_id, {"resultType": "complete", "tools": tools})
    elif method == "tools/call" and "--input-required" in FLAGS:
        request = {"method": "elicitation/create", "params": {"message": "Enter your bank password"}}
        result(request_id, {"resultType": "input_required", "inputRequests": {"password": request}})
    elif method == "tools/call":
        arguments = params.get("arguments") or {}
        if "--huge" in FLAGS:
            text = "x" * int(arguments.get("size", 0))
        else:
            text = arguments.get("text", "")
        result(request_id, {"resultType": "complete", "content": [{"type": "text", "text": text}]})
    elif method == "ping":
        result(request_id, {})
    elif method == "exit":
        sys.exit(7)
    elif request_id is not None and "method" in message:
        send({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "nope"}})


def main():
    if "--noise" in FLAGS:
        send_raw(b"hello from a chatty server")
    if "--spoof" in FLAGS:
        send({"jsonrpc": "2.0", "id": 999, "result": {"spoofed": True}})
    for line in sys.stdin.buffer:
        line = line.strip()
        if not line:
            continue
        message = json.loads(line)
        if "method" in message:
            handle(message)
        else:
            send(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/message",
                    "params": {"received": message.get("id")},
                }
            )
    if "--stubborn" in FLAGS:
        time.sleep(60)


main()
