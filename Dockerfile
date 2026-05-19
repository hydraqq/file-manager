FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN groupadd -g 1000 appuser && useradd -u 1000 -g appuser appuser

COPY . .
RUN mkdir -p /app/logs /app/storage && chown -R appuser:appuser /app

USER appuser

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
