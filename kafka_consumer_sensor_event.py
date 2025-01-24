from event_aggregator import eventAggregation, sendEventAggregation, STORAGE, HASH_STORAGE

import sensor_event_pb2

from confluent_kafka import Consumer
from confluent_kafka.serialization import SerializationContext, MessageField
from confluent_kafka.schema_registry.protobuf import ProtobufDeserializer

from google.protobuf.json_format import MessageToDict


protobuf_deserializer = ProtobufDeserializer(sensor_event_pb2.SensorEvent, {'use.deprecated.format': False})


def kafkaStream():
    
    config = {
        'bootstrap.servers': 'localhost:9093',
        'group.id': 'opencti',
        'auto.offset.reset': 'earliest'
    }

    consumer = Consumer(config)
    topic = "sensor_events"
    consumer.subscribe([topic])

    try:

        while True:

            message = consumer.poll(1.0)

            if message is None:
                sendEventAggregation()
                print("Data on Storage: " + str(len(STORAGE)) + ", Total Hash: " + str(len(HASH_STORAGE)))

            elif message.error():
                print("ERROR: " + message.error().decode('utf-8'))
                
            else:
                sensor_event = protobuf_deserializer(message.value(), SerializationContext(topic, MessageField.VALUE))
                data = MessageToDict(sensor_event, preserving_proto_field_name=True)
                eventAggregation(data)
                sendEventAggregation()
                

    except KeyboardInterrupt:
        print('Process interrupted. Waiting for current operation to finish...')
    finally:
        print("Closing consumer...")
        consumer.commit()
        consumer.close()


if __name__ == "__main__":
    kafkaStream()