import json
from datetime import datetime


STORAGE = {}
STORAGE_KAFKA = []


def sendEventAggregation(timestamp):

    delete_storage = []

    for combination, events in STORAGE.items():
        for event in events[:]:
            # if (timestamp - event['time']).total_seconds() > 60:
            if int(timestamp) - int(event['time']) > 60:
                object = {}
                object['src_address'] = combination[0]
                object['src_port'] = combination[1]
                object['dst_address'] = combination[2]
                object['dst_port'] = combination[3]
                object['protocol'] = combination[4]
                object['message'] = combination[5]
                object['classification'] = combination[6]
                object['priority'] = combination[7]
                object['start'] = event['start']
                object['end'] = event['end']
                object['base64'] = event['base64']
                object['count'] = event['count']
                STORAGE_KAFKA.append(object)
                events.remove(event)
            
        if len(events) == 0:
            delete_storage.append(combination)
    
    for combination in delete_storage:
        del STORAGE[combination]
     

def eventAggregation(metric):
    for data in metric['metrics']:

        timestamp = datetime.strptime(data['snort_timestamp'], "%d/%m/%y-%H:%M:%S.%f")
        
        source_address = data['snort_src_address']
        source_port = data['snort_src_ap'][data['snort_src_ap'].find(":") + 1::]
        dest_address = data['snort_dst_address']
        dest_port = data['snort_dst_ap'][data['snort_dst_ap'].find(":") + 1::]
        combination = (source_address, source_port, dest_address, dest_port, metric['snort_protocol'], metric['snort_message'], metric['snort_classification'], metric['snort_priority'])

        if combination in STORAGE:
            for event in STORAGE[combination]:
                include = False
                if (timestamp - event['start']).total_seconds() < 60:
                    if timestamp > event['end']:
                        event['end'] = timestamp
                    
                    event['base64'].add(data['snort_base64_data'])

                    # event['time'] = datetime.now()
                    event['time'] = metric['snort_seconds']
                    event['count'] += 1

                    include = True
                    break

            if include == False:
                event = {}
                # event['time'] = datetime.now()
                event['time'] = metric['snort_seconds']
                event['start'] = timestamp
                event['end'] = timestamp
                event['base64'] = {data['snort_base64_data']}
                event['count'] = 1
                STORAGE[combination].append(event)

        else:
            STORAGE[combination] = []
            event = {}
            # event['time'] = datetime.now()
            event['time'] = metric['snort_seconds']
            event['start'] = timestamp
            event['end'] = timestamp
            event['count'] = 1
            event['base64'] = {data['snort_base64_data']}
            STORAGE[combination].append(event)
        

def testing():
    delete_storage = []

    for combination, events in STORAGE.items():
        for event in events[:]:
            # if (timestamp - event['time']).total_seconds() > 60:
            # if int(timestamp) - int(event['time']) > 60:
            object = {}
            object['src_address'] = combination[0]
            object['src_port'] = combination[1]
            object['dst_address'] = combination[2]
            object['dst_port'] = combination[3]
            object['protocol'] = combination[4]
            object['message'] = combination[5]
            object['classification'] = combination[6]
            object['priority'] = combination[7]
            object['start'] = event['start']
            object['end'] = event['end']
            object['base64'] = event['base64']
            object['count'] = event['count']
            STORAGE_KAFKA.append(object)
            events.remove(event)
            
        if len(events) == 0:
            delete_storage.append(combination)
    
    for combination in delete_storage:
        del STORAGE[combination]

    for i in STORAGE_KAFKA:
        for key, value in i.items():
            print(str(key) + ": " + str(value))
        
        print(" ")
    

if __name__ == "__main__":
    # kafkaStream()
    with open("data-test.json") as f:
        metrics = json.load(f)
        for metric in metrics:
            eventAggregation(metric)
            # sendEventAggregation(datetime.now())
            sendEventAggregation(metric['snort_seconds'])

    print(STORAGE)

    print(" ")

    testing()

    
