#!/bin/sh

echo "Starting service: $SERVICE"

if [ "$SERVICE" = "event-aggregator" ]; then
    echo "Running Event Aggregator..."
    exec python -u kafka_consumer_sensor_event.py
elif [ "$SERVICE" = "event-parser" ]; then
    echo "Running Event Parser..."
    exec python -u event_parser.py
else
    echo "Error: Unknown or missing SERVICE environment variable!"
    exit 1
fi
