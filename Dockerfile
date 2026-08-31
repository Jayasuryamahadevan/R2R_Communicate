FROM python:3.12-slim AS base

WORKDIR /app

COPY pyproject.toml README.md ./
COPY fasp_harness ./fasp_harness

RUN pip install --no-cache-dir .

RUN useradd --create-home --uid 10001 fasp
USER fasp

VOLUME ["/home/fasp/.fasp"]
EXPOSE 8766

ENTRYPOINT ["python", "-m", "fasp_harness"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8766", "--state-dir", "/home/fasp/.fasp", "--insecure-http"]
