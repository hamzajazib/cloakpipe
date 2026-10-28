#!/usr/bin/env python3
"""The support-agent stand-in MCP server, over Streamable HTTP.

The same tools as mock_upstream.py, served at POST /mcp (one JSON response
per request, 202 for a notification; initialize issues an Mcp-Session-Id).
It is the example upstream of docker/compose.example.yaml:

    python3 mock_http_upstream.py            # listens on 0.0.0.0:3000
    MOCK_PORT=3001 python3 mock_http_upstream.py

Every tools/call it receives is logged to stderr as
`upstream received: <tool> <arguments>`, so you can see which calls got past
the gate. Standard library only.
"""
import json
import os
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOLS = [
    {"name": "read_ticket", "inputSchema": {"type": "object", "properties": {"ticket_id": {"type": "string"}}}},
    {"name": "send_email", "inputSchema": {"type": "object", "properties": {
        "ticket_id": {"type": "string"}, "to": {"type": "string"}, "subject": {"type": "string"},
        "body": {"type": "string"}}}},
    {"name": "issue_refund", "inputSchema": {"type": "object", "properties": {
        "ticket_id": {"type": "string"}, "amount": {"type": "number"}}}},
    {"name": "export_customers", "inputSchema": {"type": "object"}},
]


def answer(msg):
    """The JSON-RPC reply to one request."""
    method, params = msg.get("method"), msg.get("params") or {}
    if method == "initialize":
        result = {
            "protocolVersion": params.get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mock-support-tools", "version": "0"},
        }
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        name, arguments = params.get("name"), params.get("arguments", {})
        sys.stderr.write("upstream received: %s %s\n" % (name, json.dumps(arguments, sort_keys=True)))
        sys.stderr.flush()
        result = {"content": [{"type": "text", "text": "%s: done" % name}]}
    elif method == "ping":
        result = {}
    else:
        return {"jsonrpc": "2.0", "id": msg.get("id"), "error": {"code": -32601, "message": "method not found"}}
    return {"jsonrpc": "2.0", "id": msg.get("id"), "result": result}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/mcp":
            self.send_error(404)
            return
        try:
            msg = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        except ValueError:
            self.send_error(400)
            return
        if msg.get("id") is None or "method" not in msg:
            self.send_response(202)  # a notification or a response: no body
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps(answer(msg)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if msg.get("method") == "initialize":
            self.send_header("Mcp-Session-Id", uuid.uuid4().hex)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.send_error(405)

    def do_DELETE(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("MOCK_PORT", "3000"))
    sys.stderr.write("mock-support-tools: MCP over HTTP on 0.0.0.0:%d/mcp\n" % port)
    sys.stderr.flush()
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
