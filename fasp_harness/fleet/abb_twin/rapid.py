"""A RAPID interpreter narrow enough to run the pilot mailbox, and no wider.

The point of interpreting rather than reimplementing is fidelity of the thing
under test.  A Python translation of `FASP_Pilot.mod` would test the
translation; this executes the module file an ABB programmer will actually
load, so an edit to the RAPID -- a new branch, a moved acknowledgement, a
forgotten `fasp_ack_seq` -- changes what the twin does too.

The supported subset is deliberately small: module and procedure structure,
`PERS`/`VAR`/`CONST` declarations of `num`, `string` and `bool`, assignment,
`IF`/`ELSEIF`/`ELSE`, `WHILE`, `WaitTime`, `RETURN`, and the operators those
need.  Anything outside it raises at parse time rather than being skipped,
because a mailbox module that silently half-runs is worse than one that
refuses to load.  Motion instructions are not supported and are not wanted:
this interpreter has no robot to move.

`PERS` values live in the controller's symbol table, not in the interpreter,
so a value written over Robot Web Services and a value written by RAPID are
the same value -- which is the entire mechanism the pilot depends on.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from ...protocol.errors import FaspError

# ---------------------------------------------------------------------------
# values and their canonical RAPID text
# ---------------------------------------------------------------------------

RAPID_TYPES = {"num", "string", "bool"}


def render(value: Any) -> str:
    """Render a Python value as the RAPID text Robot Web Services would show."""

    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, str):
        return f'"{value}"'
    if isinstance(value, (int, float)):
        # RWS shows an integral num without a decimal point, as RAPID does.
        return str(int(value)) if float(value).is_integer() else repr(float(value))
    raise FaspError("schema.invalid", f"Cannot render {type(value).__name__} as RAPID text.")


def parse_value(text: str, declared: str | None = None) -> Any:
    """Parse RAPID text back into a value, honouring the declared type."""

    raw = text.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] == '"':
        return raw[1:-1]
    upper = raw.upper()
    if upper in {"TRUE", "FALSE"}:
        return upper == "TRUE"
    try:
        number = float(raw)
    except ValueError as exc:
        raise FaspError("schema.invalid", f"{text!r} is not a RAPID num, string, or bool.") from exc
    if declared == "string":
        raise FaspError("schema.invalid", "A num was written to a string symbol.")
    return number


class SymbolStore(Protocol):
    """The controller's PERS table, seen from inside RAPID."""

    def read_symbol(self, name: str) -> str: ...
    def write_symbol(self, name: str, text: str) -> None: ...


# ---------------------------------------------------------------------------
# tokens
# ---------------------------------------------------------------------------

_TOKEN = re.compile(
    r"""
    (?P<space>\s+)
  | (?P<comment>![^\n]*)
  | (?P<string>"(?:[^"\n]|"")*")
  | (?P<number>\d+\.\d+|\d+)
  | (?P<op>:=|<>|<=|>=|[=<>+\-*/();,])
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
    """,
    re.VERBOSE,
)

_KEYWORDS = {
    "module", "endmodule", "proc", "endproc", "pers", "var", "const",
    "if", "then", "elseif", "else", "endif", "while", "do", "endwhile",
    "return", "waittime", "true", "false", "and", "or", "not", "div", "mod",
}


@dataclass(frozen=True)
class Token:
    kind: str  # "op" | "ident" | "keyword" | "number" | "string" | "end"
    text: str
    line: int


def tokenize(source: str) -> list[Token]:
    tokens: list[Token] = []
    index, line = 0, 1
    while index < len(source):
        match = _TOKEN.match(source, index)
        if match is None:
            raise FaspError("schema.invalid", f"RAPID line {line}: unexpected character {source[index]!r}.")
        text = match.group()
        line += text.count("\n")
        index = match.end()
        kind = match.lastgroup or ""
        if kind in {"space", "comment"}:
            continue
        if kind == "ident" and text.lower() in _KEYWORDS:
            kind = "keyword"
        tokens.append(Token(kind, text, line))
    tokens.append(Token("end", "", line))
    return tokens


# ---------------------------------------------------------------------------
# syntax tree
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Literal:
    value: Any


@dataclass(frozen=True)
class Name:
    name: str
    line: int


@dataclass(frozen=True)
class Unary:
    op: str
    operand: Any


@dataclass(frozen=True)
class Binary:
    op: str
    left: Any
    right: Any


@dataclass(frozen=True)
class Assign:
    target: str
    value: Any
    line: int


@dataclass(frozen=True)
class If:
    branches: tuple[tuple[Any, tuple[Any, ...]], ...]
    otherwise: tuple[Any, ...]


@dataclass(frozen=True)
class While:
    condition: Any
    body: tuple[Any, ...]


@dataclass(frozen=True)
class WaitTime:
    seconds: Any


@dataclass(frozen=True)
class Return:
    pass


@dataclass(frozen=True)
class Declaration:
    kind: str  # pers | var | const
    type_name: str
    name: str
    initial: Any | None


@dataclass(frozen=True)
class Procedure:
    name: str
    body: tuple[Any, ...]


@dataclass(frozen=True)
class Module:
    name: str
    declarations: tuple[Declaration, ...]
    procedures: dict[str, Procedure]

    @property
    def persistents(self) -> tuple[Declaration, ...]:
        return tuple(item for item in self.declarations if item.kind == "pers")


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

class Parser:
    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = tokens
        self.position = 0

    @property
    def current(self) -> Token:
        return self.tokens[self.position]

    def _fail(self, expected: str) -> FaspError:
        token = self.current
        found = token.text or "end of module"
        return FaspError("schema.invalid", f"RAPID line {token.line}: expected {expected}, found {found!r}.")

    def _take(self, kind: str, text: str | None = None) -> Token:
        token = self.current
        matches = token.kind == kind and (text is None or token.text.lower() == text)
        if not matches:
            raise self._fail(text or kind)
        self.position += 1
        return token

    def _at(self, kind: str, *texts: str) -> bool:
        token = self.current
        return token.kind == kind and (not texts or token.text.lower() in texts)

    # -- module ------------------------------------------------------------
    def parse_module(self) -> Module:
        self._take("keyword", "module")
        name = self._take("ident").text
        declarations: list[Declaration] = []
        procedures: dict[str, Procedure] = {}
        while not self._at("keyword", "endmodule"):
            if self._at("keyword", "pers", "var", "const"):
                declarations.append(self._parse_declaration())
            elif self._at("keyword", "proc"):
                procedure = self._parse_procedure()
                procedures[procedure.name.lower()] = procedure
            else:
                raise self._fail("a declaration, PROC, or ENDMODULE")
        self._take("keyword", "endmodule")
        if self.current.kind != "end":
            raise self._fail("end of file after ENDMODULE")
        return Module(name, tuple(declarations), procedures)

    def _parse_declaration(self) -> Declaration:
        kind = self._take("keyword").text.lower()
        type_name = self._take("ident").text.lower()
        if type_name not in RAPID_TYPES:
            raise FaspError("schema.invalid", f"RAPID line {self.current.line}: this interpreter supports only {sorted(RAPID_TYPES)}, not {type_name!r}.")
        name = self._take("ident").text
        initial = None
        if self._at("op", ":="):
            self._take("op", ":=")
            initial = self._parse_expression()
        self._take("op", ";")
        return Declaration(kind, type_name, name, initial)

    def _parse_procedure(self) -> Procedure:
        self._take("keyword", "proc")
        name = self._take("ident").text
        self._take("op", "(")
        if not self._at("op", ")"):
            raise FaspError("schema.invalid", f"RAPID line {self.current.line}: mailbox procedures must take no arguments.")
        self._take("op", ")")
        body = self._parse_statements("endproc")
        self._take("keyword", "endproc")
        return Procedure(name, body)

    def _parse_statements(self, *terminators: str) -> tuple[Any, ...]:
        statements: list[Any] = []
        while not self._at("keyword", *terminators):
            if self.current.kind == "end":
                raise self._fail(" or ".join(terminators).upper())
            statements.append(self._parse_statement())
        return tuple(statements)

    def _parse_statement(self) -> Any:
        if self._at("keyword", "var", "const"):
            return self._parse_declaration()
        if self._at("keyword", "if"):
            return self._parse_if()
        if self._at("keyword", "while"):
            return self._parse_while()
        if self._at("keyword", "waittime"):
            self._take("keyword", "waittime")
            seconds = self._parse_expression()
            self._take("op", ";")
            return WaitTime(seconds)
        if self._at("keyword", "return"):
            self._take("keyword", "return")
            self._take("op", ";")
            return Return()
        if self.current.kind == "ident":
            token = self._take("ident")
            self._take("op", ":=")
            value = self._parse_expression()
            self._take("op", ";")
            return Assign(token.text, value, token.line)
        raise self._fail("a statement")

    def _parse_if(self) -> If:
        branches: list[tuple[Any, tuple[Any, ...]]] = []
        self._take("keyword", "if")
        condition = self._parse_expression()
        self._take("keyword", "then")
        branches.append((condition, self._parse_statements("elseif", "else", "endif")))
        while self._at("keyword", "elseif"):
            self._take("keyword", "elseif")
            condition = self._parse_expression()
            self._take("keyword", "then")
            branches.append((condition, self._parse_statements("elseif", "else", "endif")))
        otherwise: tuple[Any, ...] = ()
        if self._at("keyword", "else"):
            self._take("keyword", "else")
            otherwise = self._parse_statements("endif")
        self._take("keyword", "endif")
        return If(tuple(branches), otherwise)

    def _parse_while(self) -> While:
        self._take("keyword", "while")
        condition = self._parse_expression()
        self._take("keyword", "do")
        body = self._parse_statements("endwhile")
        self._take("keyword", "endwhile")
        return While(condition, body)

    # -- expressions -------------------------------------------------------
    def _parse_expression(self) -> Any:
        return self._parse_or()

    def _parse_or(self) -> Any:
        node = self._parse_and()
        while self._at("keyword", "or"):
            self._take("keyword", "or")
            node = Binary("or", node, self._parse_and())
        return node

    def _parse_and(self) -> Any:
        node = self._parse_comparison()
        while self._at("keyword", "and"):
            self._take("keyword", "and")
            node = Binary("and", node, self._parse_comparison())
        return node

    def _parse_comparison(self) -> Any:
        node = self._parse_sum()
        while self._at("op", "=", "<>", "<", ">", "<=", ">="):
            op = self._take("op").text
            node = Binary(op, node, self._parse_sum())
        return node

    def _parse_sum(self) -> Any:
        node = self._parse_product()
        while self._at("op", "+", "-"):
            op = self._take("op").text
            node = Binary(op, node, self._parse_product())
        return node

    def _parse_product(self) -> Any:
        node = self._parse_unary()
        while self._at("op", "*", "/") or self._at("keyword", "div", "mod"):
            op = (self._take("op") if self.current.kind == "op" else self._take("keyword")).text.lower()
            node = Binary(op, node, self._parse_unary())
        return node

    def _parse_unary(self) -> Any:
        if self._at("keyword", "not"):
            self._take("keyword", "not")
            return Unary("not", self._parse_unary())
        if self._at("op", "-"):
            self._take("op", "-")
            return Unary("-", self._parse_unary())
        return self._parse_primary()

    def _parse_primary(self) -> Any:
        token = self.current
        if token.kind == "number":
            self.position += 1
            return Literal(float(token.text))
        if token.kind == "string":
            self.position += 1
            return Literal(token.text[1:-1].replace('""', '"'))
        if self._at("keyword", "true", "false"):
            self.position += 1
            return Literal(token.text.lower() == "true")
        if token.kind == "ident":
            self.position += 1
            return Name(token.text, token.line)
        if self._at("op", "("):
            self._take("op", "(")
            node = self._parse_expression()
            self._take("op", ")")
            return node
        raise self._fail("a value")


def parse_module(source: str) -> Module:
    """Parse one RAPID module. Raises rather than tolerating what it cannot run."""

    return Parser(tokenize(source)).parse_module()


# ---------------------------------------------------------------------------
# execution
# ---------------------------------------------------------------------------

class TaskStopped(Exception):
    """Raised inside the interpreter when the controller stops the task."""


@dataclass
class ExecutionReport:
    """What one run of the entry procedure did, for evidence and for tests."""

    started_at: float
    stopped_at: float | None = None
    statements: int = 0
    error: str | None = None
    persistent_writes: list[tuple[str, str]] = field(default_factory=list)


class RapidTask:
    """One RAPID task executing one module against a controller symbol table.

    `stop()` is a cooperative interrupt checked before every statement and
    inside `WaitTime`, which is how a real controller stopping a task behaves
    from the outside: the task does not resume mid-instruction, it unwinds.
    """

    def __init__(self, module: Module, store: SymbolStore, entry: str, *, sleep: Any = time.sleep) -> None:
        if entry.lower() not in module.procedures:
            raise FaspError("schema.invalid", f"RAPID module {module.name} has no procedure {entry!r}.")
        self.module = module
        self.store = store
        self.entry = entry
        self._sleep = sleep
        self._declared = {item.name: item for item in module.persistents}
        self._locals: dict[str, Any] = {}
        self._stop = threading.Event()
        self.report: ExecutionReport | None = None

    # -- lifecycle ---------------------------------------------------------
    def stop(self) -> None:
        self._stop.set()

    def run(self) -> ExecutionReport:
        self._stop.clear()
        self._locals = {}
        report = ExecutionReport(started_at=time.time())
        self.report = report
        try:
            self._execute(self.module.procedures[self.entry.lower()].body, report)
        except TaskStopped:
            pass
        except FaspError as error:
            # A RAPID error stops the task, exactly as an unhandled ERROR does
            # on the controller.  It must be visible, never swallowed.
            report.error = f"{error.code}: {error.detail}"
        report.stopped_at = time.time()
        return report

    # -- statements --------------------------------------------------------
    def _execute(self, statements: tuple[Any, ...], report: ExecutionReport) -> None:
        for statement in statements:
            if self._stop.is_set():
                raise TaskStopped
            report.statements += 1
            if isinstance(statement, Assign):
                self._assign(statement, report)
            elif isinstance(statement, Declaration):
                self._locals[statement.name] = self._evaluate(statement.initial) if statement.initial is not None else self._zero(statement.type_name)
            elif isinstance(statement, If):
                self._execute_if(statement, report)
            elif isinstance(statement, While):
                while self._truth(self._evaluate(statement.condition)):
                    if self._stop.is_set():
                        raise TaskStopped
                    self._execute(statement.body, report)
            elif isinstance(statement, WaitTime):
                self._wait(float(self._evaluate(statement.seconds)))
            elif isinstance(statement, Return):
                return
            else:  # pragma: no cover - the parser cannot produce anything else
                raise FaspError("schema.invalid", f"Unsupported RAPID statement {type(statement).__name__}.")

    def _execute_if(self, statement: If, report: ExecutionReport) -> None:
        for condition, body in statement.branches:
            if self._truth(self._evaluate(condition)):
                self._execute(body, report)
                return
        self._execute(statement.otherwise, report)

    def _assign(self, statement: Assign, report: ExecutionReport) -> None:
        value = self._evaluate(statement.value)
        declared = self._declared.get(statement.target)
        if declared is not None:
            if declared.type_name == "string" and not isinstance(value, str):
                raise FaspError("schema.invalid", f"RAPID line {statement.line}: {statement.target} is a string.")
            text = render(value)
            self.store.write_symbol(statement.target, text)
            report.persistent_writes.append((statement.target, text))
        elif statement.target in self._locals:
            self._locals[statement.target] = value
        else:
            raise FaspError("schema.invalid", f"RAPID line {statement.line}: {statement.target} is not declared.")

    def _wait(self, seconds: float) -> None:
        # Sliced so a stop lands inside a WaitTime rather than after it.
        deadline = time.monotonic() + max(0.0, seconds)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            if self._stop.is_set():
                raise TaskStopped
            self._sleep(min(0.01, remaining))

    # -- expressions -------------------------------------------------------
    def _evaluate(self, node: Any) -> Any:
        if isinstance(node, Literal):
            return node.value
        if isinstance(node, Name):
            return self._lookup(node)
        if isinstance(node, Unary):
            operand = self._evaluate(node.operand)
            return (not self._truth(operand)) if node.op == "not" else -float(operand)
        if isinstance(node, Binary):
            return self._binary(node)
        raise FaspError("schema.invalid", f"Unsupported RAPID expression {type(node).__name__}.")

    def _binary(self, node: Binary) -> Any:
        if node.op in {"and", "or"}:
            left = self._truth(self._evaluate(node.left))
            if node.op == "and":
                return left and self._truth(self._evaluate(node.right))
            return left or self._truth(self._evaluate(node.right))
        left, right = self._evaluate(node.left), self._evaluate(node.right)
        if node.op == "=":
            return left == right
        if node.op == "<>":
            return left != right
        if node.op == "+" and isinstance(left, str) and isinstance(right, str):
            return left + right
        if isinstance(left, str) or isinstance(right, str) or isinstance(left, bool) or isinstance(right, bool):
            if node.op in {"<", ">", "<=", ">="}:
                raise FaspError("schema.invalid", f"RAPID cannot order {type(left).__name__} with {node.op}.")
        left, right = float(left), float(right)
        operations = {
            "<": left < right, ">": left > right, "<=": left <= right, ">=": left >= right,
            "+": left + right, "-": left - right, "*": left * right,
        }
        if node.op in operations:
            return operations[node.op]
        if node.op in {"/", "div", "mod"}:
            if right == 0:
                raise FaspError("schema.invalid", "RAPID division by zero.")
            return left / right if node.op == "/" else (left // right if node.op == "div" else left % right)
        raise FaspError("schema.invalid", f"Unsupported RAPID operator {node.op!r}.")

    def _lookup(self, node: Name) -> Any:
        declared = self._declared.get(node.name)
        if declared is not None:
            return parse_value(self.store.read_symbol(node.name), declared.type_name)
        if node.name in self._locals:
            return self._locals[node.name]
        raise FaspError("schema.invalid", f"RAPID line {node.line}: {node.name} is not declared.")

    @staticmethod
    def _zero(type_name: str) -> Any:
        return {"num": 0.0, "string": "", "bool": False}[type_name]

    @staticmethod
    def _truth(value: Any) -> bool:
        if not isinstance(value, bool):
            raise FaspError("schema.invalid", "A RAPID condition must be a bool.")
        return value
