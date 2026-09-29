from __future__ import annotations

import ast
import re
from typing import Any


class SafeExpressionEngine:
    def parse(self, expression: str) -> None:
        normalized = self._normalize(expression)
        tree = ast.parse(normalized, mode="eval")
        self._validate_node(tree.body)

    def evaluate(self, expression: str, context: dict[str, Any]) -> bool:
        normalized = self._normalize(expression)
        tree = ast.parse(normalized, mode="eval")
        self._validate_node(tree.body)
        return bool(self._eval_node(tree.body, context))

    def _validate_node(self, node: ast.AST) -> None:
        allowed = (
            ast.BoolOp,
            ast.UnaryOp,
            ast.Compare,
            ast.Name,
            ast.Attribute,
            ast.Constant,
            ast.List,
            ast.Call,
            ast.Load,
            ast.And,
            ast.Or,
            ast.Not,
            ast.Eq,
            ast.NotEq,
            ast.Gt,
            ast.GtE,
            ast.Lt,
            ast.LtE,
            ast.In,
            ast.NotIn,
        )
        for child in ast.walk(node):
            if not isinstance(child, allowed):
                raise ValueError(f"Unsafe or unsupported expression node: {type(child).__name__}")
            if isinstance(child, ast.Call):
                if not isinstance(child.func, ast.Name):
                    raise ValueError("Only named safe functions are allowed")
                if child.func.id not in {"starts_with", "contains", "length", "count_distinct"}:
                    raise ValueError(f"Unsupported safe function: {child.func.id}")

    def _normalize(self, expression: str) -> str:
        normalized = self._normalize_keywords(expression)
        normalized = re.sub(r"(\S+)\s+not starts_with\s+('.*?'|\".*?\")", r"not starts_with(\1, \2)", normalized)
        normalized = re.sub(r"(\S+)\s+starts_with\s+('.*?'|\".*?\")", r"starts_with(\1, \2)", normalized)
        normalized = re.sub(r"(\S+)\s+not contains\s+('.*?'|\".*?\"|\S+)", r"not contains(\1, \2)", normalized)
        normalized = re.sub(r"(\S+)\s+contains\s+('.*?'|\".*?\"|\S+)", r"contains(\1, \2)", normalized)
        normalized = re.sub(r"(\S+)\.length", r"length(\1)", normalized)
        normalized = re.sub(r"(\S+)\.count_distinct", r"count_distinct(\1)", normalized)
        return normalized

    def _normalize_keywords(self, expression: str) -> str:
        parts: list[str] = []
        index = 0
        start = 0
        quote: str | None = None
        while index < len(expression):
            char = expression[index]
            if quote:
                if char == "\\":
                    index += 2
                    continue
                if char == quote:
                    quote = None
                index += 1
                continue
            if char in {"'", '"'}:
                if start < index:
                    parts.append(self._normalize_unquoted_keywords(expression[start:index]))
                literal_start = index
                quote = char
                index += 1
                while index < len(expression):
                    literal_char = expression[index]
                    if literal_char == "\\":
                        index += 2
                        continue
                    if literal_char == quote:
                        index += 1
                        break
                    index += 1
                parts.append(expression[literal_start:index])
                start = index
                quote = None
                continue
            index += 1
        if start < len(expression):
            parts.append(self._normalize_unquoted_keywords(expression[start:]))
        return "".join(parts)

    def _normalize_unquoted_keywords(self, text: str) -> str:
        normalized = re.sub(r"\bis\s+not\s+null\b", "!= None", text)
        normalized = re.sub(r"\bis\s+null\b", "== None", normalized)
        return re.sub(
            r"(?<![\w.])(?:true|false|null)\b(?!\s*\()",
            lambda match: {"true": "True", "false": "False", "null": "None"}[match.group(0)],
            normalized,
        )

    def _eval_node(self, node: ast.AST, context: dict[str, Any]) -> Any:
        if isinstance(node, ast.BoolOp):
            values = [self._eval_node(value, context) for value in node.values]
            if isinstance(node.op, ast.And):
                return all(values)
            if isinstance(node.op, ast.Or):
                return any(values)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not self._eval_node(node.operand, context)
        if isinstance(node, ast.Compare):
            left = self._eval_node(node.left, context)
            for op, comparator in zip(node.ops, node.comparators, strict=True):
                right = self._eval_node(comparator, context)
                if not self._compare(left, op, right):
                    return False
                left = right
            return True
        if isinstance(node, ast.Name):
            return context.get(node.id)
        if isinstance(node, ast.Attribute):
            value = self._eval_node(node.value, context)
            if isinstance(value, dict):
                return value.get(node.attr)
            return getattr(value, node.attr, None)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.List):
            return [self._eval_node(item, context) for item in node.elts]
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            args = [self._eval_node(arg, context) for arg in node.args]
            return self._call(node.func.id, args)
        raise ValueError(f"Unsafe or unsupported expression node: {type(node).__name__}")

    def _call(self, name: str, args: list[Any]) -> Any:
        if name == "starts_with" and len(args) == 2:
            return str(args[0] or "").startswith(str(args[1]))
        if name == "contains" and len(args) == 2:
            left, right = args
            if left is None:
                return False
            return right in left
        if name == "length" and len(args) == 1:
            value = args[0]
            if value is None:
                return 0
            return len(value)
        if name == "count_distinct" and len(args) == 1:
            value = args[0]
            if value is None:
                return 0
            return len(set(value))
        raise ValueError(f"Unsupported safe function: {name}")

    def _compare(self, left: Any, op: ast.cmpop, right: Any) -> bool:
        if isinstance(op, ast.Eq):
            return left == right
        if isinstance(op, ast.NotEq):
            return left != right
        if isinstance(op, ast.Gt):
            return left > right
        if isinstance(op, ast.GtE):
            return left >= right
        if isinstance(op, ast.Lt):
            return left < right
        if isinstance(op, ast.LtE):
            return left <= right
        if isinstance(op, ast.In):
            return left in right
        if isinstance(op, ast.NotIn):
            return left not in right
        raise ValueError(f"Unsupported comparison operator: {type(op).__name__}")
