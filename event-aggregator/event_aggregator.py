from datetime import datetime
from hashlib import sha256
from kafka_producer_opencti_event import produceOpenCTIEvent


MAX_HOLD = 30


STORAGE = {}
HASH_STORAGE = set()


def sendEventAggregation():
    deleted_key = []

    for key, value in STORAGE.items():
        if int(datetime.now().timestamp()) - value['last_updated'] > MAX_HOLD:
            event = {}
            event['src_address'] = value['src_address']
            event['src_port'] = value['src_port']
            event['dst_address'] = value['dst_address']
            event['dst_port'] = value['dst_port']
            event['protocol'] = value['protocol']
            event['message'] = value['message']
            event['classification'] = value['classification']
            event['priority'] = value['priority']
            event['reference'] = value['reference']
            event['start'] = str(datetime.fromtimestamp(value['start']))
            event['end'] = str(datetime.fromtimestamp(value['end']))
            event['base64'] = list(value['base64'])
            event['count'] = value['count']
            
            produceOpenCTIEvent(event)
            
            deleted_key.append(key)

    if len(deleted_key) > 0:
        for key in deleted_key:
            del STORAGE[key]

        combination_hashes = set([key.split(":")[0] for key in deleted_key])

        for combination_hash in combination_hashes:
            list_key = [key for key in STORAGE if key.startswith(combination_hash)]
            if len(list_key) == 0:
                HASH_STORAGE.remove(combination_hash)


def checkAggregatableEvent(event):    
    combination = (event['src_address'], event['src_port'], event['dst_address'], event['dst_port'], event['protocol'], event['message'], event['classification'], event['priority'])
    combination_hash = sha256(str(combination).encode()).hexdigest()

    if combination_hash not in HASH_STORAGE:
        return False
    
    list_key = [key for key in STORAGE if key.startswith(combination_hash)]

    for key in list_key:
        if event['timestamp'] >= STORAGE[key]['start'] - 60 and event['timestamp'] <= STORAGE[key]['end'] + 60:
            STORAGE[key]['base64'].add(event['base64_data'])
            STORAGE[key]['count'] += 1
            STORAGE[key]['last_updated'] = int(datetime.now().timestamp())
            STORAGE[key]['start'] = min(event['timestamp'], STORAGE[key]['start'])
            STORAGE[key]['end'] = max(event['timestamp'], STORAGE[key]['end'])
            return key
    
    return False
    

def createNewEvent(event):
    # Change event 'timestamp' with event 'start' and event 'end'
    event['start'] = event['timestamp']
    event['end'] = event.pop('timestamp')

    # Change base64 data from 'str' to 'set of str'
    event['base64'] = {event.pop('base64_data')}

    # Set the count of the event to 1
    event['count'] = 1

    # Set 'last_updated' to now()
    event['last_updated'] = int(datetime.now().timestamp())

    # Create combination hash from the event
    combination = (event['src_address'], event['src_port'], event['dst_address'], event['dst_port'], event['protocol'], event['message'], event['classification'], event['priority'])
    combination_hash = sha256(str(combination).encode()).hexdigest()
    # Create the key for the event
    hash_start_end = combination_hash + ":" + str(event['start']) + ":" + str(event['end'])

    # Save the event in the STORAGE
    STORAGE[hash_start_end] = event

    # Save the hash in the HASH_STORAGE
    HASH_STORAGE.add(combination_hash)  


def updateKeyEvent(event_key):
    updated_event = STORAGE.pop(event_key)
    new_key = event_key.split(":")[0] + ":" + str(updated_event['start']) + ":" + str(updated_event['end'])
    STORAGE[new_key] = updated_event


def eventAggregation(metrics):
    for metric in metrics['metrics']:
        event = {}
        event['timestamp'] = int(metrics['snort_seconds'])
        event['src_address'] = metric.get('snort_src_address', '')
        event['src_port'] = metric['snort_src_ap'].split(":")[1] if 'snort_src_ap' in metric else 0
        event['dst_address'] = metric.get('snort_dst_address', '')
        event['dst_port'] = metric['snort_dst_ap'].split(":")[1] if 'snort_dst_ap' in metric else 0
        event['base64_data'] = metric.get('snort_base64_data', '')
        event['protocol'] = metrics['snort_protocol']
        event['message'] = metrics['snort_message']
        event['classification'] = metrics['snort_classification']
        event['priority'] = metrics['snort_priority']
        event['reference'] = "https://www.snort.org/rule_docs/" + metrics['snort_rule_gid'] + "-" + metrics['snort_rule_sid']

        found_event_key = checkAggregatableEvent(event)
        
        if not found_event_key:
            createNewEvent(event)
        
        elif STORAGE[found_event_key]['start'] != found_event_key.split(":")[1] or STORAGE[found_event_key]['end'] != found_event_key.split(":")[2]:
            updateKeyEvent(found_event_key)