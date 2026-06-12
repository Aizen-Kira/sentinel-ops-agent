# Dependency Baseline (V1.0.0)

SentinelMCP relies on a controlled set of dependencies to ensure strict runtime security and consistent forensic processing.

## Runtime Dependencies
The following packages are locked for production execution:

1. **fastmcp (>=2.0.0)**
   - **Purpose**: Provides the Model Context Protocol Server implementations and SSE connection handling.
   - **Criticality**: Core. Must be audited continuously.
2. **anthropic (>=0.30.0)**
   - **Purpose**: Facilitates LLM interactions (Claude) during the Triage and Evaluation phases of the 6-phase loop.
   - **Criticality**: Core. 
3. **pydantic (>=2.0.0)**
   - **Purpose**: Runtime data validation, strictly enforcing the unified schema formats for datasets and models.
   - **Criticality**: Medium.

## Development Dependencies
Used exclusively for building, testing, and linting the environment. Excluded from production container distributions.

1. **pytest (>=8.0.0)** & **pytest-asyncio (>=0.23.0)**
   - **Purpose**: Harnesses execution for all unit, benchmark, fuzzing, and concurrency testing.
2. **mypy (>=1.10.0)**
   - **Purpose**: Enforces strict static typing (`--strict`), eliminating entire classes of runtime exceptions.
3. **ruff (>=0.4.0)**
   - **Purpose**: Replaces Black, Flake8, and isort to provide sub-second static analysis and formatting.
4. **build (>=1.0.0)** & **hatchling**
   - **Purpose**: Generates reproducible Source Distributions (sdist) and Python Wheels.

*(A complete pip-freeze is retained alongside this baseline in `requirements-lock.txt` for exact sub-dependency mapping).*
