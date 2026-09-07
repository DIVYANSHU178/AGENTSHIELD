"""
RealCalculatorTool: Safe AST-based mathematical expression evaluator.
Pure deterministic abstract syntax tree evaluator without dynamic code evaluation.
"""

import ast
import math
import operator
from typing import Dict, Any, Optional
from app.security.models import ToolCategory
from app.security.execution.tools.base import BaseTool

# Supported binary operators
_SAFE_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}

# Whitelisted safe math functions and constants
_SAFE_FUNCTIONS = {
    "sin": math.sin,
    "cos": math.cos,
    "tan": math.tan,
    "sqrt": math.sqrt,
    "log": math.log,
    "log10": math.log10,
    "exp": math.exp,
    "abs": abs,
    "round": round,
    "floor": math.floor,
    "ceil": math.ceil,
    "pi": math.pi,
    "e": math.e,
}


def _safe_eval_node(node: ast.AST) -> Any:
    """Recursively evaluate an AST expression node with strict whitelist enforcement."""
    if isinstance(node, ast.Expression):
        return _safe_eval_node(node.body)

    if isinstance(node, ast.Constant):  # Python 3.8+ numeric/bool constant
        if isinstance(node.value, (int, float)):
            return node.value
        raise ValueError(f"Unsupported constant type: {type(node.value).__name__}")

    if isinstance(node, ast.UnaryOp):
        op_type = type(node.op)
        if op_type in _SAFE_OPERATORS:
            operand = _safe_eval_node(node.operand)
            return _SAFE_OPERATORS[op_type](operand)
        raise ValueError(f"Unsupported unary operator: {op_type.__name__}")

    if isinstance(node, ast.BinOp):
        op_type = type(node.op)
        if op_type in _SAFE_OPERATORS:
            left = _safe_eval_node(node.left)
            right = _safe_eval_node(node.right)
            if op_type in (ast.Div, ast.FloorDiv, ast.Mod) and right == 0:
                raise ZeroDivisionError("Division or modulo by zero is not permitted.")
            if op_type == ast.Pow and (abs(left) > 1000 or abs(right) > 100):
                raise ValueError("Exponentiation operands exceed safe limits.")
            return _SAFE_OPERATORS[op_type](left, right)
        raise ValueError(f"Unsupported binary operator: {op_type.__name__}")

    if isinstance(node, ast.Name):
        if node.id in _SAFE_FUNCTIONS and isinstance(_SAFE_FUNCTIONS[node.id], (int, float)):
            return _SAFE_FUNCTIONS[node.id]
        raise ValueError(f"Undefined or unauthorized variable: '{node.id}'")

    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name):
            raise ValueError("Only direct whitelisted function calls are permitted.")
        func_name = node.func.id
        if func_name not in _SAFE_FUNCTIONS or not callable(_SAFE_FUNCTIONS[func_name]):
            raise ValueError(f"Function '{func_name}' is not authorized.")
        args = [_safe_eval_node(arg) for arg in node.args]
        return _SAFE_FUNCTIONS[func_name](*args)

    raise ValueError(f"Unsupported AST node type: {type(node).__name__}")


class RealCalculatorTool(BaseTool):
    """
    Real arithmetic & mathematical expression evaluator.
    Operates without arbitrary code execution.
    """

    @property
    def name(self) -> str:
        return "calculator"

    @property
    def description(self) -> str:
        return "Safe mathematical expression and arithmetic evaluator"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.READ_ONLY

    def execute(self, parameters: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        expr = parameters.get("expression")
        if expr is not None:
            expr_str = str(expr).strip()
            if not expr_str:
                raise ValueError("Expression parameter cannot be empty.")
            if len(expr_str) > 500:
                raise ValueError("Expression exceeds maximum allowed length of 500 characters.")
            try:
                tree = ast.parse(expr_str, mode="eval")
            except SyntaxError as e:
                raise ValueError(f"Invalid mathematical syntax: {str(e)}") from e

            result = _safe_eval_node(tree)
            return {
                "expression": expr_str,
                "result": result,
                "type": type(result).__name__,
            }

        # Fallback to operation + a + b parameters
        op = str(parameters.get("op", "add")).lower().strip()
        a = float(parameters.get("a", 0.0))
        b = float(parameters.get("b", 0.0))

        if op in ("add", "+"):
            res = a + b
        elif op in ("sub", "subtract", "-"):
            res = a - b
        elif op in ("mul", "multiply", "*"):
            res = a * b
        elif op in ("div", "divide", "/"):
            if b == 0:
                raise ZeroDivisionError("Division by zero is not permitted.")
            res = a / b
        elif op in ("pow", "power", "^"):
            if abs(a) > 1000 or abs(b) > 100:
                raise ValueError("Exponentiation operands exceed safe limits.")
            res = a ** b
        elif op in ("mod", "modulo", "%"):
            if b == 0:
                raise ZeroDivisionError("Modulo by zero is not permitted.")
            res = a % b
        else:
            raise ValueError(f"Unsupported operation: '{op}'")

        return {
            "operation": op,
            "a": a,
            "b": b,
            "result": res,
        }
