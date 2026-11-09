FROM python:3.13-slim

# git is needed for the blobless clones
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt   # includes the pinned semgrep

COPY run.py ./
COPY lsaiw/ lsaiw/
COPY rules/ rules/

# HOME=/tmp: compose runs as the WSL user's uid (so results/ stays yours), which has no home here
ENV PYTHONUNBUFFERED=1 PYTHONUTF8=1 SEMGREP_SEND_METRICS=off GIT_TERMINAL_PROMPT=0 HOME=/tmp
EXPOSE 8765
HEALTHCHECK --interval=30s --start-period=60s --timeout=10s \
    CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8765/healthz', timeout=5)"

# Exec form: python is PID 1 and gets SIGTERM from `docker stop` (graceful shutdown).
# The dashboard binds 0.0.0.0 automatically inside a container.
ENTRYPOINT ["python", "run.py"]
CMD ["run"]
