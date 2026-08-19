#!/usr/bin/env python3
"""
CDP 9223 MASTER SCRIPT — Chrome DevTools Protocol Automation Controller
=========================================================================
Targets: 127.0.0.1:9222 (native Chrome) / 127.0.0.1:9223 (socat proxy)
Environment: Kubernetes pod, Chrome/149.0.7827.196, KasmVNC/4.0

Capabilities:
  - Tab/target enumeration
  - Navigation and DOM manipulation
  - Screenshot capture (PNG base64)
  - JavaScript execution
  - Network request interception
  - Cookie/localStorage extraction
  - Extension background page inspection
  - Automated OSINT page harvesting

Dependencies: websocket-client (pip install websocket-client)
Fallback: Pure HTTP via curl for read-only operations
"""

import json, sys, argparse, base64, time, os, urllib.request, urllib.parse
from pathlib import Path

try:
    import websocket
    HAS_WS = True
except ImportError:
    HAS_WS = False
    print("[!] websocket-client not installed. HTTP-only mode.", file=sys.stderr)

class CDPMaster:
    def __init__(self, endpoint="http://127.0.0.1:9223", ws_endpoint=None):
        self.http = endpoint.rstrip("/")
        self.ws = ws_endpoint
        self.targets = []
        self.session_id = None
        self.msg_id = 0
        self.ws_conn = None

    def _http_get(self, path):
        url = f"{self.http}{path}"
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            return {"error": str(e)}

    def _http_put(self, path, data=None):
        url = f"{self.http}{path}"
        try:
            req = urllib.request.Request(url, method="PUT")
            if data:
                req.add_header("Content-Type", "application/json")
                req.data = json.dumps(data).encode()
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            return {"error": str(e)}

    def list_targets(self):
        """Enumerate all tabs, service workers, iframes."""
        self.targets = self._http_get("/json/list")
        return self.targets

    def version(self):
        """Get browser version info."""
        return self._http_get("/json/version")

    def protocol(self):
        """Get full CDP protocol definition (1.5MB JSON)."""
        return self._http_get("/json/protocol")

    def new_tab(self, url="about:blank"):
        """Create new tab and return target info."""
        return self._http_put(f"/json/new?url={urllib.parse.quote(url)}")

    def close_tab(self, target_id):
        """Close tab by target ID."""
        return self._http_get(f"/json/close/{target_id}")

    def activate_tab(self, target_id):
        """Activate/focus tab."""
        return self._http_get(f"/json/activate/{target_id}")

    def connect_ws(self, target_id=None):
        """Connect to a target via WebSocket for bidirectional control."""
        if not HAS_WS:
            return {"error": "websocket-client not available"}

        if target_id:
            target = next((t for t in self.targets if t.get("id") == target_id), None)
        else:
            target = next((t for t in self.targets if t.get("type") == "page"), None)

        if not target:
            return {"error": "Target not found"}

        ws_url = target.get("webSocketDebuggerUrl")
        if not ws_url:
            return {"error": "No WebSocket URL for target"}

        self.ws_conn = websocket.create_connection(ws_url, timeout=10)
        return {"status": "connected", "target": target.get("id"), "url": ws_url}

    def send_ws(self, method, params=None):
        """Send CDP command via WebSocket."""
        if not self.ws_conn:
            return {"error": "Not connected"}
        self.msg_id += 1
        msg = {"id": self.msg_id, "method": method, "params": params or {}}
        self.ws_conn.send(json.dumps(msg))

        # Wait for response with matching ID
        for _ in range(100):
            try:
                resp = json.loads(self.ws_conn.recv())
                if resp.get("id") == self.msg_id:
                    return resp
            except Exception as e:
                return {"error": str(e)}
        return {"error": "Timeout waiting for response"}

    def navigate(self, url):
        """Navigate current tab to URL."""
        return self.send_ws("Page.navigate", {"url": url})

    def get_dom(self):
        """Get full DOM tree."""
        return self.send_ws("DOM.getDocument")

    def query_selector(self, selector):
        """Query DOM for CSS selector."""
        doc = self.send_ws("DOM.getDocument")
        root = doc.get("result", {}).get("root", {}).get("nodeId")
        if not root:
            return {"error": "No root node"}
        return self.send_ws("DOM.querySelector", {"nodeId": root, "selector": selector})

    def screenshot(self, output_path=None):
        """Capture full-page screenshot."""
        resp = self.send_ws("Page.captureScreenshot", {"format": "png", "fromSurface": True})
        data = resp.get("result", {}).get("data", "")
        if data and output_path:
            Path(output_path).write_bytes(base64.b64decode(data))
        return resp

    def execute_js(self, expression, return_by_value=True):
        """Execute JavaScript in page context."""
        return self.send_ws("Runtime.evaluate", {
            "expression": expression,
            "returnByValue": return_by_value,
            "awaitPromise": True
        })

    def get_cookies(self):
        """Get all cookies."""
        return self.send_ws("Network.getAllCookies")

    def get_local_storage(self):
        """Get localStorage contents."""
        return self.execute_js("JSON.stringify(localStorage)")

    def get_session_storage(self):
        """Get sessionStorage contents."""
        return self.execute_js("JSON.stringify(sessionStorage)")

    def intercept_network(self, enable=True):
        """Enable/disable network request interception."""
        if enable:
            self.send_ws("Network.enable")
            self.send_ws("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]})
        else:
            self.send_ws("Fetch.disable")
            self.send_ws("Network.disable")

    def harvest_page(self, url, output_dir="/mnt/agents/output/cdp_harvest"):
        """Full page harvest: screenshot, DOM, cookies, storage, network log."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        self.navigate(url)
        time.sleep(3)  # Let page load

        # Screenshot
        ts = int(time.time())
        self.screenshot(out / f"{ts}_screenshot.png")

        # DOM
        dom = self.get_dom()
        (out / f"{ts}_dom.json").write_text(json.dumps(dom, indent=2))

        # Cookies
        cookies = self.get_cookies()
        (out / f"{ts}_cookies.json").write_text(json.dumps(cookies, indent=2))

        # Storage
        ls = self.get_local_storage()
        (out / f"{ts}_localstorage.json").write_text(json.dumps(ls, indent=2))

        # Title and URL
        title = self.execute_js("document.title")
        (out / f"{ts}_meta.json").write_text(json.dumps({
            "url": url,
            "title": title.get("result", {}).get("value", ""),
            "timestamp": ts
        }, indent=2))

        return {"status": "harvested", "dir": str(out), "timestamp": ts}

    def inspect_extension(self, extension_id):
        """Navigate to chrome-extension://<id>/ and harvest."""
        url = f"chrome-extension://{extension_id}/"
        return self.harvest_page(url)

    def close(self):
        if self.ws_conn:
            self.ws_conn.close()

def main():
    parser = argparse.ArgumentParser(description="CDP 9223 Master Controller")
    parser.add_argument("--endpoint", default="http://127.0.0.1:9223", help="CDP HTTP endpoint")
    parser.add_argument("--list", action="store_true", help="List all targets")
    parser.add_argument("--version", action="store_true", help="Get browser version")
    parser.add_argument("--navigate", help="Navigate to URL")
    parser.add_argument("--screenshot", help="Save screenshot to path")
    parser.add_argument("--harvest", help="Harvest page at URL")
    parser.add_argument("--js", help="Execute JavaScript expression")
    parser.add_argument("--inspect-ext", help="Inspect chrome extension by ID")
    parser.add_argument("--target", help="Target ID to connect to")
    args = parser.parse_args()

    cdp = CDPMaster(args.endpoint)

    if args.version:
        print(json.dumps(cdp.version(), indent=2))

    if args.list:
        targets = cdp.list_targets()
        for t in targets:
            print(f"[{t.get('type','?'):15}] {t.get('id','?')[:16]}... | {t.get('url','?')[:60]}")

    if args.navigate or args.harvest or args.js or args.inspect_ext:
        cdp.list_targets()
        conn = cdp.connect_ws(args.target)
        if "error" in conn:
            print(f"[!] Connection failed: {conn['error']}", file=sys.stderr)
            sys.exit(1)

        if args.navigate:
            print(json.dumps(cdp.navigate(args.navigate), indent=2))

        if args.harvest:
            print(json.dumps(cdp.harvest_page(args.harvest), indent=2))

        if args.js:
            print(json.dumps(cdp.execute_js(args.js), indent=2))

        if args.inspect_ext:
            print(json.dumps(cdp.inspect_extension(args.inspect_ext), indent=2))

        cdp.close()

if __name__ == "__main__":
    main()
