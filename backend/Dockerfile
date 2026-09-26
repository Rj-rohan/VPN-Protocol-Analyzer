FROM python:3.11-slim

# TShark without setuid dumpcap: the service only reads files, it never captures live traffic.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY alembic.ini ./
COPY migrations ./migrations
COPY app ./app

RUN useradd --system --uid 10001 --home /app analyzer \
 && mkdir -p /app/storage/pcaps /app/storage/reports /models \
 && chown -R analyzer:analyzer /app/storage
USER analyzer

ENV STORAGE_DIR=/app/storage/pcaps REPORT_DIR=/app/storage/reports MODEL_DIR=/models TSHARK_PATH=tshark
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s CMD curl -fsS http://localhost:8000/health || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
