"""Code-graph security analysis for the ``analysis`` scanner.

Two layers, both deterministic (no AI):

* ``taint`` — precise Python AST taint analysis (source → sink across function
  boundaries, sanitizer-aware). High confidence.
* ``treesitter_scan`` — multi-language dangerous call-site detection over the
  tree-sitter grammars shipped with ``deepscan-graphify``. Lower confidence
  ("risk zones"): it flags reachable, apparently-unsanitized sinks for review.

``engine.analyze_target`` ties them together, builds the graphify code graph
(the knowledge base + reachability), and returns normalized ``Finding`` objects
plus the graph artifacts.
"""

from .engine import AnalysisResult, analyze_target, security_payload
from .query import QUESTIONS, answer

__all__ = ["AnalysisResult", "analyze_target", "security_payload", "QUESTIONS", "answer"]
