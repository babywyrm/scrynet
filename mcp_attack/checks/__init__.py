"""Security check registry and runner."""

import time

from mcp_attack.core.models import TargetResult
from mcp_attack.checks.injection import (
    check_prompt_injection,
    check_tool_poisoning,
    check_indirect_injection,
)
from mcp_attack.checks.permissions import (
    check_excessive_permissions,
    check_schema_risks,
)
from mcp_attack.checks.behavioral import (
    check_rug_pull,
    check_protocol_robustness,
)
from mcp_attack.checks.theft import check_token_theft
from mcp_attack.checks.execution import (
    check_code_execution,
    check_remote_access,
)
from mcp_attack.checks.chaining import (
    check_tool_shadowing,
    check_multi_vector,
    check_attack_chains,
)
from mcp_attack.checks.transport import check_sse_security
from mcp_attack.checks.rate_limit import check_rate_limit
from mcp_attack.checks.prompt_leakage import check_prompt_leakage
from mcp_attack.checks.supply_chain import check_supply_chain

# All checks that require session (for rug_pull, indirect_injection, protocol_robustness, sse_security)
SESSION_CHECKS = [
    check_prompt_injection,
    check_tool_poisoning,
    check_excessive_permissions,
    check_rug_pull,
    check_tool_shadowing,
    check_indirect_injection,
    check_token_theft,
    check_code_execution,
    check_remote_access,
    check_schema_risks,
    check_protocol_robustness,
    check_multi_vector,
    check_attack_chains,
]

# Checks that need (session, result) - sse_security needs base + sse_path
# tool_shadowing needs all_results
# We'll pass session, result, all_results, and optional base/sse_path via a context


def _time_check(name: str, result: TargetResult):
    class _T:
        def __enter__(self):
            self.t0 = time.time()
            return self

        def __exit__(self, *_):
            result.timings[name] = time.time() - self.t0

    return _T()


def run_all_checks(
    session,
    result: TargetResult,
    all_results: list[TargetResult],
    base: str = "",
    sse_path: str = "",
    verbose: bool = False,
):
    """Run all security checks against a target result."""
    check_tool_shadowing(all_results, result)
    check_prompt_injection(result)
    check_tool_poisoning(result)
    check_excessive_permissions(result)
    check_rug_pull(session, result)
    check_indirect_injection(session, result)
    check_token_theft(result)
    check_code_execution(result)
    check_remote_access(result)
    check_schema_risks(result)
    check_rate_limit(result)
    check_prompt_leakage(result)
    check_supply_chain(result)
    check_protocol_robustness(session, result)
    check_multi_vector(result)
    check_attack_chains(result)

    if base and sse_path:
        check_sse_security(base, sse_path, result)
