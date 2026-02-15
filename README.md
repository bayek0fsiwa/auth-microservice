# FastAPI Authentication Microservice

A production-ready Authentication Microservice built with FastAPI, SQLModel (PostgreSQL), and Redis.

## Features

- **JWT Authentication**: Secure access and refresh token rotation with RS256 signing.
- **Role-Based Access Control (RBAC)**: Fine-grained permissions (e.g., admin vs. user).
- **Security**:
    - **CSRF Protection**: Double-submit cookie pattern.
    - **Rate Limiting**: Redis-backed distributed rate limiting.
    - **Account Lockout**: Brute-force protection.
    - **Secure Headers**: Helmet-like security headers.
- **Asynchronous**: Fully async database and Redis operations.
- **Background Tasks**: Celery worker integration for email sending (mocked).
- **Dockerized**: Ready for containerized deployment with Docker Compose.

## Tech Stack

- **Framework**: FastAPI
- **Database**: PostgreSQL (AsyncPG), SQLModel
- **Cache/Queue**: Redis
- **Task Queue**: Celery
- **Migrations**: Alembic
- **Testing**: Pytest

## Getting Started

### Prerequisites

- [Docker](https://www.docker.com/get-started) & Docker Compose
- Python 3.12+ (for local development)

### Quick Start (Docker)

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd fastapi-auth-service
    ```

2.  **Create Environment File:**
    ```bash
    cp .env.example .env
    # Edit .env and set secure values for JWT_SECRET_KEY, etc.
    ```

3.  **Generate Keys (if using RS256):**
    ```bash
    # You may need to generate private.pem and public.pem
    openssl genrsa -out private.pem 2048
    openssl rsa -in private.pem -outform PEM -pubout -out public.pem
    ```

4.  **Start Services:**
    ```bash
    docker compose up -d --build
    ```

5.  **Access the API:**
    - API: `http://localhost:8000`
    - Docs: `http://localhost:8000/docs`

### Local Development

1.  **Create Virtual Environment:**
    ```bash
    python -m venv .venv
    source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1
    ```

2.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    pip install -r requirements-dev.txt
    ```

3.  **Run with Docker Dependencies:**
    Start only DB and Redis:
    ```bash
    docker compose up -d db redis
    ```

4.  **Run Migrations:**
    ```bash
    alembic upgrade head
    ```

5.  **Start App:**
    ```bash
    uvicorn src.main:app --reload
    ```

## API Documentation

Interactive API documentation is available at `/docs` (Swagger UI) or `/redoc`.

### Key Endpoints

- `POST /api/v1/auth/register`: Register a new user.
- `POST /api/v1/auth/login`: Login and receive cookies (access/refresh/csrf).
- `POST /api/v1/auth/refresh`: Refresh access token.
- `GET /api/v1/auth/me`: Get current user profile.

## Testing

Run the test suite using pytest:

```bash
pytest
```
