FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /srv

# No third-party dependencies: the service runs entirely on the stdlib.
COPY app/ ./app/
COPY tests/ ./tests/
COPY smoke/ ./smoke/

EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=5 \
    CMD ["python", "smoke/healthcheck.py"]

CMD ["python", "-m", "app.server"]
