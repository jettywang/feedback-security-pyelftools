# Feedback task starting environment

Upstream: https://github.com/eliben/pyelftools
Upstream commit: `25bf486e262426f93c4e79ba9d01b5eac329a368`
Prepared on macOS with the Python version recorded in the environment plan. No external database, queue, or cloud account is required.

The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= test/test_dynamic.py test/test_gnuversions.py test/test_core_notes32.py test/test_data_bounds.py test/test_relocations.py test/test_relr.py test/test_corrupt_files.py
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-13): `36 passed, 168 subtests passed in 0.21s`
Whole-command wall time: 0.350 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
