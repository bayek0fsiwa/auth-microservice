FROM python:3.12-slim AS builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim

RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid 1000 --no-create-home appuser

WORKDIR /app

COPY --from=builder /install /usr/local

COPY src/ ./src/
COPY alembic.ini .
COPY migrations/ ./migrations/

COPY start.sh .
RUN sed -i 's/\r$//' start.sh && chmod +x start.sh

USER appuser

EXPOSE 8000

CMD ["./start.sh"]
