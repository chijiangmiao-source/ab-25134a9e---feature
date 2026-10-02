# Seafloor checkpoint log API + acceptance harness in one image.
FROM python:3.11-slim-bookworm

ARG IMAGE_TAG=dev

WORKDIR /app

# No third-party dependencies: only the CPython standard library is used,
# so there is deliberately no requirements.txt / pip install step.
COPY app ./app
COPY acceptance ./acceptance

# Build-time marker exercised by the acceptance service's build check.
RUN set -eu; \
    built_at="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"; \
    { \
      echo "image=seafloor-checkpoint:${IMAGE_TAG}"; \
      echo "built_at=${built_at}"; \
      echo "python=$(python -c 'import platform;print(platform.python_version())')"; \
    } > /app/IMAGE_BUILD; \
    useradd --system --uid 10001 --home-dir /app --user-group appuser; \
    mkdir -p /data; \
    chown -R appuser:appuser /app /data

USER appuser
EXPOSE 8080

# stdlib-only health probe (no curl in the slim image).
HEALTHCHECK --interval=3s --timeout=3s --start-period=5s --retries=20 \
    CMD python -c "import json,urllib.request; r=urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=3); assert r.status==200 and json.load(r)['status']=='ok'"

CMD ["python", "-m", "app.server"]
