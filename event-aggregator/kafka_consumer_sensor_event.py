from event_aggregator import eventAggregation, sendEventAggregation
import sensor_event_pb2
from confluent_kafka import Consumer
from confluent_kafka.serialization import SerializationContext, MessageField
from confluent_kafka.schema_registry.protobuf import ProtobufDeserializer
from google.protobuf.json_format import MessageToDict
import os


KAFKA_URL = os.getenv('KAFKA_URL')
KAFKA_CONSUMER_GROUP_ID = os.getenv('KAFKA_CONSUMER_GROUP_ID')
KAFKA_TOPIC = os.getenv('KAFKA_TOPIC')

protobuf_deserializer = ProtobufDeserializer(sensor_event_pb2.SensorEvent, {'use.deprecated.format': False})


def kafkaStream():
    
    config = {
        'bootstrap.servers': KAFKA_URL,
        'group.id': KAFKA_CONSUMER_GROUP_ID,
        'auto.offset.reset': 'earliest'
    }

    consumer = Consumer(config)
    topic = KAFKA_TOPIC
    consumer.subscribe([topic])

    try:

        while True:

            message = consumer.poll(1.0)

            if message is None:
                sendEventAggregation()

            elif message.error():
                print("ERROR: " + str(message.error()))
                
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