FROM python:3.12-slim

WORKDIR /app
COPY requirements-prod.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements-prod.txt

COPY pyproject.toml README.md ./
COPY fasp_harness ./fasp_harness

RUN pip install --no-cache-dir --no-deps . \
    && useradd --create-home --uid 10001 fasp \
    && install -d --owner=fasp --group=fasp --mode=0700 /home/fasp/.fasp

USER fasp
VOLUME ["/home/fasp/.fasp"]
EXPOSE 8766

# Default listener is loopback inside the container: no accidental public
# plaintext API. For an explicit dev LAN or production TLS deployment, supply
# the full serve command (see PRODUCTION_READINESS.md).
ENTRYPOINT ["python", "-m", "fasp_harness"]
CMD ["serve", "--host", "127.0.0.1", "--port", "8766", "--state-dir", "/home/fasp/.fasp"]
