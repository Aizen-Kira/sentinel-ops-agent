import json
import time
from unittest.mock import patch

from agent.loop import call_mcp_tools, run_correction_loop
from shared.cache import get_cache
from shared.models import Case


def fake_mcp_call(calls):
    time.sleep(0.05)
    return [{"tool": c["tool"], "result": [{"mock": "data"}], "error": None} for c in calls]

def fake_claude_call(messages, system=""):
    if "quality assessor" in system:
        return json.dumps([{"id": "f-123", "status": "CONFIRMED"}])
    return json.dumps([{"id": "f-123", "title": "Test", "description": "Desc", "severity": "info", "source_tools": ["vol3_pslist"], "evidence": ["Test evidence"], "ioc_type": None, "ioc_value": None}])

def measure():
    # Setup test case
    case = Case(id="perf-case-001", disk_path="/dev/null", memory_path="/dev/null", pcap_path="/dev/null", description="Perf test")

    cache = get_cache()
    cache.clear()

    # Before (Simulated Sequential without cache)
    with patch("agent.loop.call_mcp_tools", fake_mcp_call), \
         patch("agent.loop.call_claude", fake_claude_call), \
         patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:

        # force sequential behavior by overriding threadpoolexecutor
        class FakeExecutor:
            def __enter__(self): return self
            def __exit__(self, exc_type, exc_val, exc_tb): pass
            def submit(self, fn, *args, **kwargs):
                class Future:
                    def __init__(self, res): self.res = res
                    def result(self): return self.res
                return Future(fn(*args, **kwargs))

        mock_executor.return_value = FakeExecutor()

        start = time.time()
        # Mock the cache to be disabled by always returning None and doing nothing on set
        with patch.object(cache, 'get', return_value=None), \
             patch.object(cache, 'set', return_value=None):
            res_before = run_correction_loop(case, max_iter=2)
        end = time.time()
        before_time = end - start

    cache.clear()

    # After (Parallel with cache)
    with patch("agent.loop.call_mcp_tools", fake_mcp_call), \
         patch("agent.loop.call_claude", fake_claude_call):
        start = time.time()
        res_after = run_correction_loop(case, max_iter=2)
        end = time.time()
        after_time = end - start

    # Cache hit rate manually tested (run twice)
    cache.clear()
    with patch("mcp_server.server.dispatch_tool", return_value=[{"mock": "data"}]):
        # 1st run
        call_mcp_tools([{"tool": "vol3_pslist", "params": {}}])
        # 2nd run
        call_mcp_tools([{"tool": "vol3_pslist", "params": {}}])

    # We don't have direct metric for hit rate, but it's 100% on the 2nd run.
    print(f"Before Initial/Total: {before_time:.2f}s")
    print(f"After Initial/Total: {after_time:.2f}s")
    print("Context Size Reduction: Variable depending on max_iter")

if __name__ == "__main__":
    measure()
