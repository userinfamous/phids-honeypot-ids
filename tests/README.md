PHIDS Test Suite
================

This directory contains the consolidated and optimized test suite for PHIDS.

How to run
----------

From the project root (python_final_project) run:

```bash
python run_tests.py
```

Notes
-----

- Tests are focused on core demonstration features: honeypots (SSH/HTTP), dashboard API, database logging, and a quick main integration smoke test.
- Tests favor speed and best-effort checks; they will skip when services are not available in the test environment.
- For more verbose output use: pytest -k "" -vv
