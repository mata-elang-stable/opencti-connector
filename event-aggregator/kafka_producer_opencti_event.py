import json
from confluent_kafka import Producer


def produceOpenCTIEvent(event):
    config = {
        'bootstrap.servers': 'localhost:9093',  
        'client.id': 'opencti-produce-event'
    }

    producer = Producer(config)
    producer.produce('opencti_events', key='event_key', value=json.dumps(event))
    producer.flush()
