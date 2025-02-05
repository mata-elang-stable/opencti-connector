from pycti import OpenCTIApiClient
import json
from datetime import datetime
from confluent_kafka import Consumer
import base64
import hashlib
import os

OPENCTI_URL = os.getenv("OPENCTI_URL")
OPENCTI_API_KEY = os.getenv("OPENCTI_API_KEY")
KAFKA_URL = os.getenv("KAFKA_URL")
KAFKA_CONSUMER_GROUP_ID = os.getenv("KAFKA_CONSUMER_GROUP_ID")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC")

opencti_api_client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_API_KEY)

def parseTimeToISO(timestamp):
    date_time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
    iso_format = date_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    return iso_format

def createOrReadIndicator(indicator_name,reference):
    indicator_search = opencti_api_client.indicator.list(
        filters = {
            "mode": "and",
            "filters": {
                "key": "name",
                "values": [indicator_name],
                    "operator": "eq"
            },
            "filterGroups": []
        }
    )
    if len(indicator_search) > 0:
        return indicator_search[0].get('standard_id', None)
    else:
        indicator = opencti_api_client.indicator.create(
            name = indicator_name,
            pattern = "[reference:value = '" + reference + "']",
            pattern_type = "stix",
            x_opencti_main_observable_type = 'Network-Traffic'
        )
        return indicator.get('standard_id', None)

def createOrReadAttackPattern(attack_pattern):
    attack_pattern_search = opencti_api_client.attack_pattern.list(
        filters = {
            "mode": "and",
                "filters": {
                    "key": "name",
                    "values": [attack_pattern],
                            "operator": "eq"
                },
                "filterGroups": []
        }
    )
    if len(attack_pattern_search) > 0:
        return attack_pattern_search[0]['standard_id']
    else:
        attack_pattern = opencti_api_client.attack_pattern.create(
            name = attack_pattern
        )
        return attack_pattern['standard_id']

def createOrReadIPv4(ip_address):
    if ip_address == "" :
        return ""
    ipv4_search = opencti_api_client.query('''
        query stixCyberObservable {
            stixCyberObservables(
                types: ["IPv4-Addr"],
                filters: {
                    mode: and,
                    filters: {
                        key: "value",
                        values: ["'''+ip_address+'''"],
                        operator: eq
                    },
                    filterGroups: []
                }
            )
            {
                edges {
                    node {
                        standard_id
                    }
                }
            }
        }
    ''')
    if len(ipv4_search['data']['stixCyberObservables']['edges']) > 0:
        return ipv4_search['data']['stixCyberObservables']['edges'][0]['node']['standard_id']
    else:
        ipv4 = opencti_api_client.query('''
            mutation stixCyberObservableAdd {
                stixCyberObservableAdd (
                                    type: "IPv4-Addr",
                    IPv4Addr: {
                        value: "'''+ip_address+'''"
                    }
                ) {
                    standard_id
                }
            }
        ''')
        return ipv4['data']['stixCyberObservableAdd']['standard_id']

def createOrReadArtifact(base64file):
    artifact_search = opencti_api_client.query('''
        query stixCyberObservable {
            stixCyberObservables(
                types: ["Artifact"],
                filters: {
                    mode: and,
                    filters: {
                        key: "payload_bin",
                        values: ["'''+base64file+'''"],
                        operator: eq
                    },
                    filterGroups: []
                }
            )
            {
                edges {
                    node {
                        standard_id
                    }
                }
            }
        }
    ''')
    if len(artifact_search['data']['stixCyberObservables']['edges']) > 0:
        return artifact_search['data']['stixCyberObservables']['edges'][0]['node']['standard_id']
    else:
        artifact = opencti_api_client.query('''
            mutation stixCyberObservableAdd{
                stixCyberObservableAdd(
                    type: "Artifact",
                    Artifact: {
                        mime_type: "application/octet-stream",
                        payload_bin: "'''+base64file+'''"
                        hashes: [
                            {
                                algorithm: "md5",
                                hash: "'''+hashlib.md5(base64.b64decode(base64file)).hexdigest()+'''"
                            },
                            {
                                algorithm: "sha-1",
                                hash: "'''+hashlib.sha1(base64.b64decode(base64file)).hexdigest()+'''"
                            },
                            {
                                algorithm: "sha-256",
                                hash: "'''+hashlib.sha256(base64.b64decode(base64file)).hexdigest()+'''"
                            },
                            {
                                algorithm: "sha-512",
                                hash: "'''+hashlib.sha512(base64.b64decode(base64file)).hexdigest()+'''"
                            }
                        ]
                    }
                ) {
                    standard_id
                }
            }
        ''')
        return artifact['data']['stixCyberObservableAdd']['standard_id']

def createNetworkTraffic(start_time, end_time, src_ip_id, src_port, dst_ip_id, dst_port, protocol):
    network_traffic = opencti_api_client.query('''
        mutation stixCyberObservableAdd {
            stixCyberObservableAdd (
                type: "Network-Traffic",
                NetworkTraffic: {
                    start: "'''+str(start_time)+'''",
                    end: "'''+str(end_time)+'''",
                    networkSrc: "'''+src_ip_id+'''",
                    networkDst: "'''+dst_ip_id+'''",
                    src_port: '''+src_port+''',
                    dst_port: '''+dst_port+''',
                    protocols: ["'''+protocol+'''"]
                }
            ) {
                standard_id
            }
        }
    ''')
    return network_traffic['data']['stixCyberObservableAdd']['standard_id']

def createOrReadLabel(priority):
    if priority == "1":
        label = opencti_api_client.label.create(
            value="High",
            color="#FF0000",
        )
    elif priority == "2":
        label = opencti_api_client.label.create(
            value="Medium",
            color="#FF8C00",
        )
    elif priority == "3":
        label = opencti_api_client.label.create(
            value="Low",
            color="#FFFF00",
        )
    elif priority == "4":
        label = opencti_api_client.label.create(
            value="Informational",
            color="#C0C0C0",
        )
    return label

def createOpenCTIObject(data):

    # create objects to opencti
    start_time_iso = parseTimeToISO(data['start'])
    end_time_iso = parseTimeToISO(data['end'])

    src_port = str(data['src_port']) if data.get('src_port') else "0"
    dst_port = str(data['dst_port']) if data.get('dst_port') else "0"

    source_ip_id = createOrReadIPv4(data['src_address'])
    destination_ip_id = createOrReadIPv4(data['dst_address'])
    indicator_id = createOrReadIndicator(data['message'], data['reference'])
    attack_pattern_id = createOrReadAttackPattern(data['classification'])

    arr_artifact_id = []
    for base64_file in data['base64']:
        if base64_file != "":
            artifact_id = createOrReadArtifact(base64_file)
            arr_artifact_id.append(artifact_id)

    network_traffic_id = createNetworkTraffic(
        start_time_iso,
        end_time_iso,
        source_ip_id,
        src_port,
        destination_ip_id,
        dst_port,
        data['protocol']
        )

    # create label and adding label to objects opencti
    prior_label_id = createOrReadLabel(data['priority'])
    opencti_api_client.stix_domain_object.add_label(id=indicator_id, label_id=prior_label_id["standard_id"])
    opencti_api_client.stix_domain_object.add_label(id=attack_pattern_id, label_id=prior_label_id["standard_id"])
    opencti_api_client.stix_cyber_observable.add_label(id=network_traffic_id, label_id=prior_label_id["standard_id"])

    # define relations between objects
    opencti_api_client.stix_core_relationship.create(
        fromId = indicator_id,
        fromTypes = ["Indicator"],
        toId = attack_pattern_id,
        toTypes = ["Attack-Pattern"],
        relationship_type = "indicates"
    )

    opencti_api_client.stix_core_relationship.create(
        fromId = indicator_id,
        fromTypes = ["Indicator"],
        toId = network_traffic_id,
        toTypes = ["Network-Traffic"],
        relationship_type = "related-to"
    )

    if source_ip_id != "":
        opencti_api_client.stix_core_relationship.create(
            fromId = indicator_id,
            fromTypes = ["Indicator"],
            toId = source_ip_id,
            toTypes = ["IPv4-Addr"],
            relationship_type = "related-to"
        )

    for artifact_id in arr_artifact_id:
        opencti_api_client.stix_core_relationship.create(
            fromId = network_traffic_id,
            fromTypes = ["Network-Traffic"],
            toId = artifact_id,
            toTypes = ["Artifact"],
            relationship_type = "related-to"
        )

def kafkaStream():
    config = {
        'bootstrap.servers': KAFKA_URL,
        'group.id':          KAFKA_CONSUMER_GROUP_ID,
        'auto.offset.reset': 'earliest'
    }

    consumer = Consumer(config)
    topic = KAFKA_TOPIC
    consumer.subscribe([topic])

    try:
        while True:
            message = consumer.poll(1.0)
            if message is None:
                print("Waiting...")
            elif message.error():
                print("ERROR: " + str(message.error()))
            else:
                data = json.loads(message.value())
                print(data)
                createOpenCTIObject(data)
    except KeyboardInterrupt:
        print('Process interrupted. Waiting for current operation to finish...')
    finally:
        print("Closing consumer...")
        consumer.commit()
        consumer.close()

if __name__ == "__main__":
    kafkaStream()

