# Dev (Windows — gunicorn doesn't support Windows)
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

# Production (Linux / Docker)
# gunicorn src.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000