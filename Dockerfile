FROM python:3.14-slim

LABEL org.opencontainers.image.source=https://github.com/mostafahussein/k8s-sec-agent

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY k8s_sec_agent/ k8s_sec_agent/

EXPOSE 8080

CMD ["uvicorn", "k8s_sec_agent.main:app", "--host", "0.0.0.0", "--port", "8080"]
