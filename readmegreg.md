Dockerhub Repo: https://hub.docker.com/repository/docker/greghoff/module12_is601/general

# Running Tests Locally

## Prerequisites
- Python 3.8+ installed
- Docker and Docker Compose installed
- Project dependencies installed: `pip install -r requirements.txt`

## Test Setup
1. **Start the database container:**
   ```bash
   docker compose up --build
   ```

2. **Configure Python environment (if needed):**
   ```bash
   # Create virtual environment
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   
   # Install dependencies
   pip install -r requirements.txt
   ```

## Running Tests

### Run All Tests
```bash
pytest
```

### Run by Test Type
```bash
# Unit tests only
pytest tests/unit/

# Integration tests only
pytest tests/integration/

# End-to-end tests only
pytest tests/e2e/
```

### Run with Coverage
```bash
pytest --cov=app --cov-report=html
```

### Run Specific Test Files
```bash
pytest tests/integration/test_user_auth.py
pytest tests/unit/test_calculator.py
```

## Test Database
- Tests use a separate test database configured in `conftest.py`
- Database tables are automatically created and cleaned between tests
- No manual database setup required

## Cleanup
```bash
docker compose down
```

## Common Issues
- **Database connection errors**: Ensure Docker is running and database container is healthy
- **Import errors**: Verify all dependencies are installed and virtual environment is activated
- **Permission errors**: Check file permissions and ensure Docker has proper access
