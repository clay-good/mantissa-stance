# stance

Mantissa Stance - Cloud Security Posture Management and Vulnerability Detection

A minimal, focused CSPM tool that answers one question:
"What is wrong with my cloud configuration RIGHT NOW?"

Key Features:
- Read-only by design: Can never modify cloud resources
- Minimal dependencies: Only boto3 required
- YAML-based policies: Write and version control your own security rules
- Natural language queries: Ask questions like "Are we PCI compliant?"
- Multiple LLM providers: Anthropic, OpenAI, and Gemini supported

Quick Start:
    >>> from stance.collectors import run_collection
    >>> from stance.engine import run_evaluation
    >>>
    >>> # Collect assets from AWS
    >>> assets, findings, results = run_collection()
    >>>
    >>> # Evaluate policies
    >>> eval_findings, result = run_evaluation(assets)
    >>> print(f"Found {len(eval_findings)} issues")
