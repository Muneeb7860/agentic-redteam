FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY pyproject.toml README.md /app/
COPY agentic_redteam /app/agentic_redteam/
COPY tests /app/tests/

RUN pip install --no-cache-dir pyyaml requests

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-m", "agentic_redteam.cli"]
CMD ["--iterations", "3"]
