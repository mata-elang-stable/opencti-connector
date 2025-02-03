FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
COPY event_parser.py .

RUN apt update && apt-get install -y --no-install-recommends \
    gcc \
    librdkafka-dev \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python -u ./event_parser > event_parser.log", "./event_parser.py"]
