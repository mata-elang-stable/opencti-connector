import json
from confluent_kafka import Producer
import os

def produceOpenCTIEvent(event):

    KAFKA_URL = os.getenv('KAFKA_URL')

    config = {
        'bootstrap.servers': KAFKA_URL,  
        'client.id': 'opencti-produce-event'
    }

    producer = Producer(config)
    producer.produce('opencti_events', key='event_key', value=json.dumps(event))
    producer.flush()
