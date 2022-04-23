import re


def main():
    kallsyms = None
    with open("/proc/kallsyms", "r") as f:
        kallsyms = f.readlines()

    exp = re.compile("([0-9a-fA-F]+) ([TDS]) ([ -~]+)[ ]?")
    kallsyms = [exp.match(sym) for sym in kallsyms if exp.match(sym)]

    kallsyms.sort(key=lambda sym: int(sym.group(1), 16))

    _text_sym = next(sym for sym in kallsyms if sym.group(3) == "_text")
    max_exported = int(_text_sym.group(1), 16) + 0xf85198
    [print(sym.groups()) for sym in kallsyms if int(sym.group(1), 16) < max_exported and int(sym.group(1), 16) > int(_text_sym.group(1), 16)]

if __name__ == "__main__":
    main()
