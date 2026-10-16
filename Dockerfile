FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY static ./static
COPY README.md ./README.md
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
