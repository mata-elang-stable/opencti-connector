FROM python:3.12-slim AS base

WORKDIR /app

RUN apt update && apt-get install -y --no-install-recommends \
    gcc \
    librdkafka-dev \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT [ "python" ]

FROM base AS event-aggregator

COPY event-aggregator/event_aggregator.py .
COPY event-aggregator/kafka_consumer_sensor_event.py .
COPY event-aggregator/kafka_producer_opencti_event.py .
COPY event-aggregator/sensor_event_pb2.py .

CMD ["-u", "kafka_consumer_sensor_event.py"]

FROM base AS event-parser

COPY event-parser/event_parser.py ./event_parser.py

CMD ["-u", "event_parser.py"]
