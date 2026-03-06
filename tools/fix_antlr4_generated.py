#!/usr/bin/env python3
"""
Post-process ANTLR4 generated C++ files to fix two issues for parameterized rules
(rules with [...] parameters that generate context classes with reference members):

1. No-arg constructor issue: ANTLR4 generates a no-arg constructor for every
   context class, but reference members can't be left uninitialized. We delete
   the no-arg constructor declaration (from .h) and definition (from .cpp).

2. Parameterized constructor issue: ANTLR4 generates `this->member = member;`
   assignments in the constructor body, but references must be initialized in
   the initializer list. We move these assignments to the initializer list.
"""

import re
import sys


def find_ref_classes(header_content: str) -> set[str]:
    """Find all context class names that have reference member variables."""
    pattern = r"class\s+(\w+Context)\s*:[^{]*\{(.*?)\n  \};"
    ref_classes = set()
    for m in re.finditer(pattern, header_content, re.DOTALL):
        cls = m.group(1)
        body = m.group(2)
        # Look for lines like: "  SomeType& member_name;"
        if re.search(r"(?:^|\n)\s+[^;/]+&\s+\w+\s*;", body):
            ref_classes.add(cls)
    return ref_classes


def fix_header(content: str, ref_classes: set[str]) -> str:
    """Remove no-arg constructor declarations from the header for ref classes."""
    for cls in ref_classes:
        # Remove the no-arg constructor declaration:
        # "    ClassName(antlr4::ParserRuleContext *parent, size_t invokingState);\n"
        pattern = (
            r"(?m)^(\s+)"
            + re.escape(cls)
            + r"\(antlr4::ParserRuleContext \*parent, size_t invokingState\);\n"
        )
        content = re.sub(pattern, "", content)
    return content


def fix_cpp(content: str, ref_classes: set[str]) -> str:
    """
    For ref classes in the .cpp:
    1. Remove the no-arg constructor definitions.
    2. Fix parameterized constructors to initialize refs in the initializer list
       instead of assigning in the body.
    """
    # Step 1: remove no-arg constructors
    for cls in ref_classes:
        pattern = (
            r"(?m)^ ?CqlParser::"
            + re.escape(cls)
            + r"::"
            + re.escape(cls)
            + r"\(ParserRuleContext \*parent, size_t invokingState\)\n"
            r"  : ParserRuleContext\(parent, invokingState\) \{\n"
            r"\}\n"
            r"\n"
        )
        content = re.sub(pattern, "", content)

    # Step 2: fix parameterized constructors
    # Pattern: constructor with body containing "this->member = member;" lines
    ctor_pattern = re.compile(
        r"( ?CqlParser::(\w+Context)::\2\(ParserRuleContext \*parent, size_t invokingState,[^)]+\))\n"
        r"(  : ParserRuleContext\(parent, invokingState\)) \{\n"
        r"((?:  this->(\w+) = \5;\n)+)"
        r"(\})",
        re.MULTILINE,
    )

    def fix_ctor(m: re.Match) -> str:
        sig = m.group(1)
        base_init = m.group(3)
        body = m.group(4)
        # Extract member names from "  this->member = member;\n"
        members = re.findall(r"  this->(\w+) = \1;\n", body)
        # Build initializer list
        inits = ", ".join(f"{name}({name})" for name in members)
        return f"{sig}\n{base_init}, {inits} {{\n}}"

    content = ctor_pattern.sub(fix_ctor, content)
    return content


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <CqlParser.h> <CqlParser.cpp>", file=sys.stderr)
        sys.exit(1)

    header_path = sys.argv[1]
    cpp_path = sys.argv[2]

    with open(header_path) as f:
        header_content = f.read()
    with open(cpp_path) as f:
        cpp_content = f.read()

    ref_classes = find_ref_classes(header_content)
    if not ref_classes:
        print(
            "No reference-member context classes found, nothing to fix.",
            file=sys.stderr,
        )
        sys.exit(0)

    print(
        f"Fixing {len(ref_classes)} context classes with reference members.",
        file=sys.stderr,
    )

    fixed_header = fix_header(header_content, ref_classes)
    fixed_cpp = fix_cpp(cpp_content, ref_classes)

    with open(header_path, "w") as f:
        f.write(fixed_header)
    with open(cpp_path, "w") as f:
        f.write(fixed_cpp)


if __name__ == "__main__":
    main()
