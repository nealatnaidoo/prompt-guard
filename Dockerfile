FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY . .

EXPOSE 8420

CMD ["uvicorn", "src.middleware.app:app", "--host", "0.0.0.0", "--port", "8420"]
