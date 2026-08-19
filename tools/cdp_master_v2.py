#!/usr/bin/env python3
"""
CDP 9223 MASTER v2 — Chrome DevTools Protocol + curl_cffi Cloudflare Bypass
============================================================================
Targets: 127.0.0.1:9223 (CDP via socat proxy)
         External web via curl_cffi (TLS fingerprint impersonation)

Capabilities:
  - CDP tab/target enumeration, navigation, screenshot, JS execution
  - curl_cffi external scraping with JA3/TLS fingerprint bypass
  - /proc-based process tracing (strace fallback)
  - Automated OSINT harvest pipeline
"""

import json, sys, os, base64, time, urllib.request, urllib.parse
from pathlib import Path

# curl_cffi for Cloudflare bypass
try:
    from curl_cffi import requests as curl_requests
    HAS_CURL_CFFI = True
except ImportError:
    HAS_CURL_CFFI = False
    import requests as curl_requests

try:
    import websocket
    HAS_WS = True
except ImportError:
    HAS_WS = False

class CDPMasterV2:
    def __init__(self, endpoint="http://127.0.0.1:9223"):
        self.http = endpoint.rstrip("/")
        self.targets = []
        self.ws_conn = None
        self.msg_id = 0

    def _http_get(self, path):
        url = f"{self.http}{path}"
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            return {"error": str(e)}

    def version(self):
        return self._http_get("/json/version")

    def list_targets(self):
        self.targets = self._http_get("/json/list")
        return self.targets

    def new_tab(self, url="about:blank"):
        req = urllib.request.Request(
            f"{self.http}/json/new?url={urllib.parse.quote(url)}",
            method="PUT"
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            return {"error": str(e)}

    def close_tab(self, target_id):
        return self._http_get(f"/json/close/{target_id}")

    def connect_ws(self, target_id=None):
        if not HAS_WS:
            return {"error": "websocket-client not available"}
        self.list_targets()
        target = None
        if target_id:
            target = next((t for t in self.targets if t.get("id") == target_id), None)
        else:
            target = next((t for t in self.targets if t.get("type") == "page"), None)
        if not target:
            return {"error": "Target not found"}
        ws_url = target.get("webSocketDebuggerUrl")
        if not ws_url:
            return {"error": "No WebSocket URL"}
        self.ws_conn = websocket.create_connection(ws_url, timeout=10)
        return {"status": "connected", "target": target.get("id"), "url": ws_url}

    def send_ws(self, method, params=None):
        if not self.ws_conn:
            return {"error": "Not connected"}
        self.msg_id += 1
        msg = {"id": self.msg_id, "method": method, "params": params or {}}
        self.ws_conn.send(json.dumps(msg))
        for _ in range(100):
            try:
                resp = json.loads(self.ws_conn.recv())
                if resp.get("id") == self.msg_id:
                    return resp
            except:
                break
        return {"error": "Timeout"}

    def navigate(self, url):
        return self.send_ws("Page.navigate", {"url": url})

    def screenshot(self, output_path=None):
        resp = self.send_ws("Page.captureScreenshot", {"format": "png", "fromSurface": True})
        data = resp.get("result", {}).get("data", "")
        if data and output_path:
            Path(output_path).write_bytes(base64.b64decode(data))
        return resp

    def execute_js(self, expr):
        return self.send_ws("Runtime.evaluate", {
            "expression": expr, "returnByValue": True, "awaitPromise": True
        })

    def get_cookies(self):
        return self.send_ws("Network.getAllCookies")

    def close(self):
        if self.ws_conn:
            self.ws_conn.close()

class CurlCffiScraper:
    """External web scraper with Cloudflare/TLS fingerprint bypass."""

    def __init__(self, impersonate="chrome124"):
        self.impersonate = impersonate
        self.session = curl_requests.Session() if HAS_CURL_CFFI else None

    def get(self, url, headers=None, timeout=30):
        if not HAS_CURL_CFFI or not self.session:
            # Fallback to standard requests
            import requests
            return requests.get(url, headers=headers, timeout=timeout)
        return self.session.get(url, headers=headers, timeout=timeout, impersonate=self.impersonate)

    def get_text(self, url, **kwargs):
        r = self.get(url, **kwargs)
        return {"status": r.status_code, "url": r.url, "text": r.text[:50000], "headers": dict(r.headers)}

class ProcTracer:
    """/proc-based process tracing (strace fallback)."""

    def trace_pid(self, pid):
        """Read /proc/<pid> for syscall, fd, maps info."""
        result = {"pid": pid, "status": {}, "fd": [], "maps": [], "syscall": None}
        try:
            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith("Name:") or line.startswith("State:") or line.startswith("PPid:"):
                        k, v = line.strip().split(":", 1)
                        result["status"][k.strip()] = v.strip()
        except:
            pass
        try:
            with open(f"/proc/{pid}/syscall") as f:
                result["syscall"] = f.read().strip()
        except:
            pass
        try:
            fd_dir = f"/proc/{pid}/fd"
            for fd in os.listdir(fd_dir):
                try:
                    link = os.readlink(f"{fd_dir}/{fd}")
                    result["fd"].append({"fd": fd, "target": link})
                except:
                    pass
        except:
            pass
        try:
            with open(f"/proc/{pid}/maps") as f:
                result["maps"] = [line.strip() for line in f.readlines()[:20]]
        except:
            pass
        return result

    def trace_processes(self, name_filter=None):
        """Trace all processes matching name_filter."""
        results = []
        for pid_str in os.listdir("/proc"):
            if not pid_str.isdigit():
                continue
            try:
                with open(f"/proc/{pid_str}/comm") as f:
                    comm = f.read().strip()
                if name_filter and name_filter not in comm:
                    continue
                results.append(self.trace_pid(int(pid_str)))
            except:
                pass
        return results

def main():
    import argparse
    parser = argparse.ArgumentParser(description="CDP 9223 Master + curl_cffi Scraper")
    parser.add_argument("--cdp-list", action="store_true", help="List CDP targets")
    parser.add_argument("--cdp-version", action="store_true", help="Get CDP version")
    parser.add_argument("--cdp-navigate", help="Navigate to URL via CDP")
    parser.add_argument("--cdp-screenshot", help="Screenshot to path")
    parser.add_argument("--cdp-js", help="Execute JS expression")
    parser.add_argument("--scrape", help="Scrape URL with curl_cffi")
    parser.add_argument("--trace-pid", type=int, help="Trace PID via /proc")
    parser.add_argument("--trace-name", help="Trace processes by name")
    args = parser.parse_args()

    if args.cdp_version:
        cdp = CDPMasterV2()
        print(json.dumps(cdp.version(), indent=2))

    if args.cdp_list:
        cdp = CDPMasterV2()
        targets = cdp.list_targets()
        for t in targets:
            print(f"[{t.get('type','?'):15}] {t.get('id','?')[:20]}... | {t.get('url','?')[:60]}")

    if args.cdp_navigate or args.cdp_screenshot or args.cdp_js:
        cdp = CDPMasterV2()
        conn = cdp.connect_ws()
        if "error" in conn:
            print(f"[!] {conn['error']}", file=sys.stderr)
            sys.exit(1)
        if args.cdp_navigate:
            print(json.dumps(cdp.navigate(args.cdp_navigate), indent=2))
            time.sleep(2)
        if args.cdp_screenshot:
            print(json.dumps(cdp.screenshot(args.cdp_screenshot), indent=2))
        if args.cdp_js:
            print(json.dumps(cdp.execute_js(args.cdp_js), indent=2))
        cdp.close()

    if args.scrape:
        scraper = CurlCffiScraper()
        result = scraper.get_text(args.scrape)
        print(json.dumps(result, indent=2, default=str))

    if args.trace_pid:
        tracer = ProcTracer()
        print(json.dumps(tracer.trace_pid(args.trace_pid), indent=2, default=str))

    if args.trace_name:
        tracer = ProcTracer()
        results = tracer.trace_processes(args.trace_name)
        for r in results:
            print(f"PID {r['pid']}: {r['status'].get('Name','?')} [{r['status'].get('State','?')}]")
            if r['syscall']:
                print(f"  syscall: {r['syscall']}")
            for fd in r['fd'][:5]:
                print(f"  fd {fd['fd']}: {fd['target']}")

if __name__ == "__main__":
    main()
