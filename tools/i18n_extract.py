"""Sammelt alle zu übersetzenden Texte (_("…")) aus sigillum/*.py.

Aufruf:  python tools/i18n_extract.py            → Liste fehlender/überzähliger Einträge in locale/en.json
         python tools/i18n_extract.py --json     → alle Texte als JSON-Liste (Reihenfolge des Auftretens)
"""
import ast
import json
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sigillum")
DYNAMIC = ("persönlich", "Video mit Rückfrage")          # ratchet.METHODS: werden über _(m) übersetzt


def msgids():
    out, nonconst = [], []
    for name in sorted(os.listdir(ROOT)):
        if not name.endswith(".py"):
            continue
        path = os.path.join(ROOT, name)
        tree = ast.parse(open(path, encoding="utf-8").read())
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_" and n.args:
                a = n.args[0]
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    if a.value not in out:
                        out.append(a.value)
                else:
                    nonconst.append(f"{name}:{n.lineno}: {ast.unparse(a)}")
    for d in DYNAMIC:
        if d not in out:
            out.append(d)
    return out, nonconst


if __name__ == "__main__":
    ids, nonconst = msgids()
    if "--json" in sys.argv:
        print(json.dumps(ids, ensure_ascii=False, indent=1))
        sys.exit()
    cat = json.load(open(os.path.join(ROOT, "locale", "en.json"), encoding="utf-8"))
    missing = [i for i in ids if i not in cat]
    extra = [k for k in cat if k not in ids]
    print(f"{len(ids)} Texte, {len(missing)} fehlen, {len(extra)} überzählig")
    for x in nonconst:
        print("nicht konstant:", x)
