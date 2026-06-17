# Fixture: tag-pinned but NOT digest-pinned base image (MEDIUM).
# Also has FROM with no HEALTHCHECK below (LOW) — distinct file from the :latest one.
FROM python:3.11-slim AS builder

RUN echo "build stage"

# No HEALTHCHECK instruction in this file -> DOCKER_NO_HEALTHCHECK
USER appuser
CMD ["python", "app.py"]
