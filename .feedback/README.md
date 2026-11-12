# Feedback task starting environment

Upstream: https://github.com/vsajip/python-gnupg
Upstream commit: `d107c34b652680ed0df07f14b0837f2e587d1b1e`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.
System prerequisite: gpg (GnuPG) 2.5.24
The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q test_gnupg.py -k 'test_environment or test_list_keys_initial or test_key_generation_with_invalid_key_type'
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-12): `3 passed, 41 deselected in 0.13s`
Whole-command wall time: 0.464 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
