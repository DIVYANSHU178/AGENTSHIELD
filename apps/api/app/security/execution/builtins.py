import time
from typing import Dict, Any
from app.security.models import ToolRequest

def safe_calculator_handler(request: ToolRequest) -> Dict[str, Any]:
    """
    Deterministic safe arithmetic calculator tool.
    Accepts parameters: {'a': float/int, 'b': float/int, 'op': str}
    Supported ops: 'add', 'sub', 'subtract', 'mul', 'multiply', 'div', 'divide', 'pow', 'mod'
    """
    params = request.parameters or {}
    op = str(params.get("op", "add")).lower().strip()

    try:
        a = float(params.get("a", 0.0))
        b = float(params.get("b", 0.0))
    except (ValueError, TypeError) as e:
        raise ValueError(f"Invalid calculator numeric operands: {str(e)}") from e

    if op in ("add", "+"):
        res = a + b
    elif op in ("sub", "subtract", "-"):
        res = a - b
    elif op in ("mul", "multiply", "*"):
        res = a * b
    elif op in ("div", "divide", "/"):
        if b == 0:
            raise ValueError("Division by zero is not permitted.")
        res = a / b
    elif op in ("pow", "power", "^"):
        if a > 1000 or b > 100:
            raise ValueError("Operand limits exceeded for exponentiation.")
        res = a ** b
    elif op in ("mod", "modulo", "%"):
        if b == 0:
            raise ValueError("Modulo by zero is not permitted.")
        res = a % b
    else:
        raise ValueError(f"Unsupported calculator operation: '{op}'")

    return {
        "operation": op,
        "a": a,
        "b": b,
        "result": res,
    }

def safe_string_transform_handler(request: ToolRequest) -> Dict[str, Any]:
    """
    Deterministic safe string transformation tool.
    Accepts parameters: {'text': str, 'transform': str}
    Supported transforms: 'uppercase', 'lowercase', 'reverse', 'trim', 'length'
    """
    params = request.parameters or {}
    text = str(params.get("text", request.target or ""))
    transform = str(params.get("transform", "uppercase")).lower().strip()

    if transform in ("uppercase", "upper"):
        out = text.upper()
    elif transform in ("lowercase", "lower"):
        out = text.lower()
    elif transform in ("reverse", "rev"):
        out = text[::-1]
    elif transform in ("trim", "strip"):
        out = text.strip()
    elif transform in ("length", "len"):
        out = len(text)
    else:
        raise ValueError(f"Unsupported string transformation: '{transform}'")

    return {
        "transform": transform,
        "output": out,
    }

def safe_health_check_handler(request: ToolRequest) -> Dict[str, Any]:
    """
    Deterministic safe system status inspection tool.
    """
    return {
        "status": "healthy",
        "service": "agentshield_execution_engine",
        "target": request.target,
    }

def failing_demonstration_handler(request: ToolRequest) -> Dict[str, Any]:
    """
    Demonstration handler that intentionally raises an exception to verify error handling.
    """
    raise RuntimeError("Intentional tool execution failure for error path verification.")

def slow_demonstration_handler(request: ToolRequest) -> Dict[str, Any]:
    """
    Demonstration handler that sleeps to verify sandbox timeout enforcement.
    """
    params = request.parameters or {}
    try:
        delay = float(params.get("delay", 2.0))
    except (ValueError, TypeError):
        delay = 2.0
    time.sleep(delay)
    return {
        "status": "completed_after_delay",
        "slept_seconds": delay,
    }
