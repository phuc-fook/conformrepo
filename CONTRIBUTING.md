# Contributing

Use Python 3.11 or newer. From a fresh checkout:

```console
python -m pip install -e .
python -m unittest discover -s tests -v
```

Findings and renderers must remain deterministic across repeated equivalent runs. New or changed checks need independently authored neutral fixtures, explicit expected results, and failure-policy coverage. Do not contribute generated or private fixtures, copied proprietary structures, or repository-specific presets.

Keep the tool read-only and configuration-driven. A feature-specific dependency needs a concrete justification, narrow scope, and tests. Avoid frameworks when the standard library or current dependencies are sufficient.
