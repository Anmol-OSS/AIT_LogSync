"""Drain: online log template mining with a fixed-depth parse tree.

P. He, J. Zhu, Z. Zheng, M. R. Lyu, "Drain: An Online Log Parsing Approach
with Fixed Depth Tree", IEEE ICWS 2017. Best mean accuracy (0.865) of 13
parsers on 16 datasets in Zhu et al., ICSE-SEIP 2019 - our deterministic
fallback when no model is available, and the clustering step before the LLM.

Lines are split on whitespace; the tree routes by token count, then by the
first (depth - 2) tokens (numeric tokens routed as a wildcard); inside a leaf,
a line joins the most similar template if similarity >= threshold.
"""
import re
from dataclasses import dataclass, field

WILDCARD = "<*>"
_HAS_DIGIT = re.compile(r"\d")


@dataclass
class Cluster:
    template: list[str]
    members: list[int] = field(default_factory=list)   # indexes of the lines

    @property
    def text(self) -> str:
        return " ".join(self.template)


class Drain:
    def __init__(self, depth: int = 4, threshold: float = 0.5, max_children: int = 100):
        self.depth, self.threshold, self.max_children = depth, threshold, max_children
        self.root: dict = {}
        self.clusters: list[Cluster] = []

    @staticmethod
    def _similarity(template: list[str], tokens: list[str]) -> tuple[float, int]:
        same = params = 0
        for t, tok in zip(template, tokens):
            if t == WILDCARD:
                params += 1
            elif t == tok:
                same += 1
        return same / len(tokens), params

    def add(self, line: str, index: int) -> Cluster:
        tokens = line.split()
        node = self.root.setdefault(len(tokens), {})
        for tok in tokens[:max(self.depth - 2, 0)]:
            key = WILDCARD if _HAS_DIGIT.search(tok) else tok
            if key not in node and len(node) >= self.max_children:
                key = WILDCARD
            node = node.setdefault(key, {})
        leaf: list[Cluster] = node.setdefault("__clusters__", [])
        best, best_sim, best_params = None, -1.0, -1
        for c in leaf:
            sim, params = self._similarity(c.template, tokens)
            if sim > best_sim or (sim == best_sim and params > best_params):
                best, best_sim, best_params = c, sim, params
        if best is not None and best_sim >= self.threshold:
            best.template = [t if t == tok else WILDCARD for t, tok in zip(best.template, tokens)]
            best.members.append(index)
            return best
        c = Cluster(list(tokens), [index])
        leaf.append(c)
        self.clusters.append(c)
        return c


def cluster(lines: list[str], **kw) -> list[Cluster]:
    d = Drain(**kw)
    for i, ln in enumerate(lines):
        d.add(ln, i)
    return sorted(d.clusters, key=lambda c: -len(c.members))
