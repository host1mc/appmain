FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/node-agent

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY node_agent ./node_agent
COPY run.py ./run.py

EXPOSE 8081

# /health is the one route the blanket auth hook exempts, so this needs no
# token, and urllib keeps it to the stdlib — the image has no curl or wget and
# requirements.txt has no HTTP client. A non-200 raises, which fails the check.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import os,sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('NODE_PORT', '8081') + '/health', timeout=4).status == 200 else 1)"]

CMD ["python", "run.py"]
