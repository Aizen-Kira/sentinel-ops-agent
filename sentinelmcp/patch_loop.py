import re

with open('agent/loop.py', encoding='utf-8') as f:
    content = f.read()

# 1. Update call_mcp_tools to use cache
call_mcp_tools_new = """def call_mcp_tools(tool_calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    \"\"\"Dispatch tools directly to the MCP server.  Patchable by tests.\"\"\"
    from mcp_server.server import dispatch_tool
    from shared.cache import get_cache

    results: list[dict[str, Any]] = []
    cache = get_cache()

    for tc in tool_calls:
        tool_name: str = tc.get("tool", "")
        params: dict[str, Any] = tc.get("params", {})
        try:
            cached_result = cache.get(tool_name, params)
            if cached_result is not None:
                results.append({"tool": tool_name, "result": cached_result, "error": None})
            else:
                result = dispatch_tool(tool_name, params)
                cache.set(tool_name, params, result)
                results.append({"tool": tool_name, "result": result, "error": None})
        except Exception as exc:  # noqa: BLE001
            import logging
            logging.getLogger(__name__).warning("MCP tool %s failed: %s", tool_name, exc)
            results.append({"tool": tool_name, "result": None, "error": str(exc)})
    return results"""

content = re.sub(r'def call_mcp_tools.*?return results', call_mcp_tools_new, content, flags=re.DOTALL)

# 2. Update _dispatch_tool and add _dispatch_tool_return
dispatch_new = """def _dispatch_tool_return(
    tc: dict[str, Any],
    case: Case,
    iteration: int,
) -> list[dict[str, Any]]:
    tool_name: str = tc.get("tool", "")
    params: dict[str, Any] = {**tc.get("params", {})}

    if case.disk_path and "image_path" not in params:
        params["image_path"] = case.disk_path
    if case.memory_path and "memory_path" not in params:
        params["memory_path"] = case.memory_path
    if case.pcap_path and "pcap_path" not in params:
        params["pcap_path"] = case.pcap_path

    try:
        results = call_mcp_tools([{"tool": tool_name, "params": params}])
        for r in results:
            r["iteration"] = iteration
        return results
    except Exception as exc:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).warning("Unexpected error dispatching %s: %s", tool_name, exc)
        return [{"tool": tool_name, "result": None, "error": str(exc), "iteration": iteration}]


def _dispatch_tool(
    tc: dict[str, Any],
    case: Case,
    accumulated_context: list[dict[str, Any]],
    iteration: int,
) -> None:
    results = _dispatch_tool_return(tc, case, iteration)
    accumulated_context.extend(results)"""

content = re.sub(r'def _dispatch_tool.*?accumulated_context\.append.*?\)', dispatch_new, content, flags=re.DOTALL)

# We need to manually fix if there's any remaining append.
# The original code:
#    except Exception as exc:  # noqa: BLE001
#        logger.warning("Unexpected error dispatching %s: %s", tool_name, exc)
#        # BUG-004 fix: always record the failure
#        accumulated_context.append({"tool": tool_name, "result": None, "error": str(exc)})

# 3. Add summarize_context and replace _summarize_context
summarize_new = """def summarize_context(
    accumulated_context: list[dict[str, Any]],
    current_iteration: int,
    active_gaps: list[Gap] | None = None,
    all_findings: list[Finding] | None = None,
) -> list[dict[str, Any]]:
    current: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    from collections import defaultdict
    successful_by_tool: dict[str, list[dict[str, Any]]] = defaultdict(list)
    
    protected_tools = set()
    if active_gaps and all_findings:
        active_finding_ids = {g.finding_id for g in active_gaps}
        for f in all_findings:
            if f.id in active_finding_ids:
                protected_tools.update(f.source_tools)

    for entry in accumulated_context:
        tool = entry.get("tool", "")
        if entry.get("iteration") == current_iteration:
            current.append(entry)
        elif entry.get("error") is not None:
            failures.append(entry)
        else:
            successful_by_tool[tool].append(entry)

    summarized: list[dict[str, Any]] = list(current)
    summarized.extend(failures)
    
    for tool, entries in successful_by_tool.items():
        if tool in protected_tools:
            summarized.extend(entries)
        else:
            if len(entries) > 2:
                kept = entries[-2:]
                dropped = len(entries) - 2
                summarized.append({
                    "tool": tool,
                    "summary": f"{dropped} older successful runs of {tool} were compressed to save context window."
                })
                summarized.extend(kept)
            else:
                summarized.extend(entries)

    return summarized"""

content = re.sub(r'def _summarize_context.*?return summarized', summarize_new, content, flags=re.DOTALL)

# 4. Update run_correction_loop to use ThreadPoolExecutor and summarize_context
loop_new = """        if iteration > 1 and all_findings:
            gaps = find_gaps(all_findings, case)
            tool_calls = [
                {"tool": g.suggested_tool, "params": g.suggested_params}
                for g in gaps
            ]
        else:
            gaps = []

        if iteration == 1 and tool_calls:
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = []
                for tc in tool_calls:
                    current_iter_tools.add(tc.get("tool", ""))
                    futures.append(executor.submit(_dispatch_tool_return, tc, case, iteration))
                for future in futures:
                    accumulated_context.extend(future.result())
        else:
            for tc in tool_calls:
                current_iter_tools.add(tc.get("tool", ""))
                _dispatch_tool(tc, case, accumulated_context, iteration)

        if not tool_calls:
            logger.info("No tools to dispatch — converged.")
            break

        # --- Phase 2: Claude triage -----------------------------------------
        summarized = summarize_context(accumulated_context, iteration, gaps, all_findings)"""

content = re.sub(r'        if iteration > 1 and all_findings:.*?summarized = _summarize_context\(accumulated_context, current_iter_tools\)', loop_new, content, flags=re.DOTALL)

with open('agent/loop.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Patch applied")
