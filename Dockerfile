FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY pii_leak_hunter ./pii_leak_hunter
COPY fixtures ./fixtures

RUN pip install --upgrade pip && pip install .

EXPOSE 8501

CMD ["pii-leak-hunter", "--help"]
