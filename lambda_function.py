import json
import urllib.parse
import boto3
import json
from neo4j.v1 import GraphDatabase
import socket
from datetime import timedelta
from datetime import datetime

print('Loading function')

s3 = boto3.client('s3')

# 잘못된 포맷 고쳐서 올리는것
def timeFormat(line):
    ts = datetime.strptime(line, "%Y-%m-%d_%I-%M-%S-%p")
    ts = datetime.strftime(ts, "%Y-%m-%d %H:%M:%S")
    return ts

# 일분전 찾기
def get_date(time):
    minute_ago = datetime.strptime(time, "%Y-%m-%d %H:%M:%S") - timedelta(minutes=1)
    return datetime.strftime(minute_ago, "%Y-%m-%d %H:%M:%S")

"""
" 파이썬은 클래스를 정의할때 object 최상위 객체를 상속받음
" 데이터베이스에 접속 및 질의를 수행하는 클래스
" 네트워크 노드와 노드간의 관계(패킷)을 생성하는 기능, 패킷의 정보를 입력하면 내부에서 Cypher 쿼리를 생성함
"""
class DataAccessObject(object):
    # 생성자
    def __init__(self, uri, user, password):
        self._driver = GraphDatabase.driver(uri, auth=(user, password))
    # closer
    def close(self):
        self._driver.close()
    # 노드가 존재하고 있는지 조회
    def is_exist(self, message, label):
        with self._driver.session() as session:
            greeting = session.write_transaction(self._is_exist, message, label)
            print(greeting)
            return greeting
    # 새로운 노드를 하나 생성
    def make_node(self, message, label):
        try:
            dns = socket.gethostbyaddr(message)[0]
        except:
            dns = "Unknown Host"
        with self._driver.session() as session:
            greeting = session.write_transaction(self._make_node, message, dns, label)
            print(greeting)
    # 이미 존재하는 노드 간 관계를 생성
    def make_relation(self, message):
        with self._driver.session() as session:
            # cnt_mean
            greeting = session.write_transaction(self._count_mean, message)
            if greeting == "0" or greeting == None:
                message.append("0")
            else:
                message.append(greeting)
            # cnt_max
            greeting = session.write_transaction(self._count_max, message)
            if greeting == "0" or greeting == None:
                message.append("0")
            else:
                message.append(greeting)
            # cnt_max_divide_mean
            greeting = session.write_transaction(self._count_max_divide_mean, message)
            if greeting == "0" or greeting == None:
                message.append("0")
            else:
                message.append(greeting)
            # minus_Min_Max
            greeting = session.write_transaction(self._minute_count, message)
            if greeting == "0" or greeting == None:
                message.append("0")
            else:
                message.append(greeting)
            # ip_len_count
            greeting = session.write_transaction(self._minus_Min_Max, message)
            if greeting == "0" or greeting == None:
                message.append("0")
            else:
                message.append(greeting)
            # std
            greeting = session.write_transaction(self._std, message)
            if greeting == "0" or greeting == None:
                message.append("0")
            else:
                message.append(greeting)

            greeting = session.write_transaction(self._make_relation, message)
            print(greeting)
    # 해당 노드 간에 동일한 관계가 존재하는지 조회
    def is_relation(self, message):
        with self._driver.session() as session:
            greeting = session.write_transaction(self._is_relation, message)
            print(greeting)
            return greeting
    # 해당 관계(패킷)이 몇번 발생하였는지 조회
    def get_count(self, message):
        with self._driver.session() as session:
            greeting = session.write_transaction(self._get_count, message)
            print(greeting)
            return greeting
    # 이미 존재하는 관계(패킷)이 다시 발생한 경우 count를 증가시킴, 기존 count값을 parameter로 넣어줌
    def set_count(self, message, count):
        with self._driver.session() as session:
            greeting = session.write_transaction(self._set_count, message, count)
            print(greeting)

    def test(self, message):
        with self._driver.session() as session:
            greeting = session.write_transaction(self._minute_count, message)
            print(greeting)
            greeting = session.write_transaction(self._minute_mean, message)
            print(greeting)

    """
    " 이하 static method
    " 위의 공개된 method의 이름에 _ 하나 붙어있음
    """
    @staticmethod #
    def _set_count(tx, message, count):
        result = tx.run("MATCH (:"+message[8]+" {ip:$sourceIp})-[r]->(:"+message[8]+" {ip:$destIp}) "
                        "WHERE r.proto=$protocol and r.length=$length and r.sourcePort=$sourcePort and r.destPort=$destPort and r.timestamp=$timestamp "
                        "SET r.count = $count "
                        "RETURN r.count", sourceIp=message[1], destIp=message[2], protocol=message[3], length=message[6], count=count, sourcePort=message[4], destPort=message[5], timestamp=message[0])
        return result.single()[0]

    @staticmethod #
    def _get_count(tx, message):
        result = tx.run("MATCH (:"+message[8]+" {ip:$sourceIp})-[r]->(:"+message[8]+" {ip:$destIp}) "
                        "WHERE r.proto=$protocol and r.length=$length and r.sourcePort=$sourcePort and r.destPort=$destPort and r.timestamp=$timestamp "
                        "RETURN r.count", sourceIp=message[1], destIp=message[2], protocol=message[3], length=message[6], sourcePort=message[4], destPort=message[5], timestamp=message[0])
        return result.single()[0]

    @staticmethod #
    def _is_relation(tx, message):
        result = tx.run("MATCH (:"+message[8]+" {ip:$sourceIp})-[r]->(:"+message[8]+" {ip:$destIp}) "
                        "WHERE r.proto=$protocol and r.length=$length and r.sourcePort=$sourcePort and r.destPort=$destPort and r.timestamp=$timestamp "
                        "RETURN count(r)", sourceIp=message[1], destIp=message[2], protocol=message[3], length=message[6], sourcePort=message[4], destPort=message[5], timestamp=message[0])
        return result.single()[0]

    @staticmethod #
    def _make_node(tx, message, dns, label):
        result = tx.run("CREATE (a:"+label+"{dns: $dns, ip: $targetIp}) RETURN a.dns", targetIp=message, dns=dns)
        return result.single()[0]

    @staticmethod #
    def _is_exist(tx, message, label):
        result = tx.run("MATCH (a:"+label+") "
                        "WHERE a.ip= $targetIp "
                        "RETURN count(a)", targetIp=message)
        return result.single()[0]

    @staticmethod #
    def _make_relation(tx, message):
        result = tx.run("MATCH (a:"+message[8]+") "
                        "WHERE a.ip= $sourceIp "
                        "MATCH (b:"+message[8]+") "
                        "WHERE b.ip= $destIp "
                        "CREATE (a)-[r:SEND {sourceIp: $sourceIp, sourcePort: $sourcePort, destPort: $destPort, destIp: $destIp, timestamp: $timestamp, proto: $protocol, count: 1, length: $length, cnt_mean: $cnt_mean, cnt_max: $cnt_max, cnt_max_divide_mean: $cnt_max_divide_mean, minus_Min_Max: $minus_Min_Max, ip_len_count: $ip_len_count, std: $std}]->(b) "
                        "RETURN type(r), r.name", sourceIp=message[1], destIp=message[2], protocol=message[3], timestamp=message[0], length=message[6], sourcePort=message[4], destPort=message[5], cnt_mean=message[9], cnt_max=message[10], cnt_max_divide_mean=message[11], minus_Min_Max=message[12], ip_len_count=message[13], std=message[14])
        return result.single()[0]

    @staticmethod #
    def _minute_count(tx, message):
        result = tx.run("MATCH(:" + message[8] + ")-[r]-() "
                        "WHERE r.timestamp < $timestamp AND r.timestamp > $minute_ago AND r.destIp = $destIp "
                        "RETURN count(r)", timestamp=message[0], minute_ago=get_date(message[0]), destIp=message[2])
        return result.single()[0]

    @staticmethod #
    def _minute_mean(tx, message):
        result = tx.run("MATCH(:" + message[8] + ")-[r]-() "
                        "WHERE r.timestamp < $timestamp AND r.timestamp > $minute_ago AND r.destIp = $destIp "
                        "RETURN avg(toInteger(r.length))", timestamp=message[0], minute_ago=get_date(message[0]), destIp=message[2])
        return result.single()[0]

    @staticmethod #
    def _count_mean(tx, message):
        result = tx.run("MATCH(:" + message[8] + ")-[r]-() "
                        "WHERE r.timestamp < $timestamp AND r.timestamp > $minute_ago AND r.destIp = $destIp "
                        "RETURN avg(toInteger(r.count))", timestamp=message[0], minute_ago=get_date(message[0]), destIp=message[2])
        return result.single()[0]

    @staticmethod #
    def _count_max(tx, message):
        result = tx.run("MATCH(:" + message[8] + ")-[r]-() "
                        "WHERE r.timestamp < $timestamp AND r.timestamp > $minute_ago AND r.destIp = $destIp "
                        "RETURN max(toInteger(r.count))", timestamp=message[0], minute_ago=get_date(message[0]), destIp=message[2])
        return result.single()[0]

    @staticmethod #
    def _count_max_divide_mean(tx, message):
        result = tx.run("MATCH(:" + message[8] + ")-[r]-() "
                        "WHERE r.timestamp < $timestamp AND r.timestamp > $minute_ago AND r.destIp = $destIp "
                        "RETURN max(toInteger(r.count)) / avg(toInteger(r.count))", timestamp=message[0], minute_ago=get_date(message[0]), destIp=message[2])
        return result.single()[0]

    @staticmethod #
    def _minus_Min_Max(tx, message):
        result = tx.run("MATCH(:" + message[8] + ")-[r]-() "
                        "WHERE r.destIp = $destIp "
                        "RETURN max(toInteger(r.length)) - min(toInteger(r.length)) "
                        "LIMIT 60", timestamp=message[0], destIp=message[2])
        return result.single()[0]

    @staticmethod #
    def _std(tx, message):
        result = tx.run("MATCH(:" + message[8] + ")-[r]-() "
                        "WHERE r.destIp = $destIp "
                        "RETURN stDev(toInteger(r.count)) "
                        "LIMIT 10", timestamp=message[0], destIp=message[2])
        return result.single()[0]
    

def lambda_handler(event, context):
    #print("Received event: " + json.dumps(event, indent=2))

    # Get the object from the event and show its content type
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'], encoding='utf-8')
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        print("CONTENT TYPE: " + response['ContentType'])
        body = (response['Body'].read()).decode('utf-8')
        body = body.replace("'",'"')
        body = body.replace('\n', '')
        body = body.replace('\r', '')
        body = body.replace('},]', '}]')

        #print(body)
        b = json.loads(body)
        #print(b[0])
        # db communicator instance 생성
        # Singleton 적용 할것, 아이디 비번 관련 보안 처리
        neo4j = DataAccessObject("address", "id", "password")
        i = 0

        # pcap 파일을 바이너리 읽기 형태로 오픈
        # line format 'Source', 'Destination', 'Protocol', 'Source Geo IP', 'Destination Geo IP', 'Timetamp', 'Length'
        for line in b:
            line = [timeFormat(line['Timestamp']), line['Source IP'], line['Destination IP'], line['Protocol'], line['Source Port'], line['Destination Port'], line['Length'], line['Payload'], line['Index']]
            print(line)
            if not neo4j.is_exist(line[1], line[8]):
                print("New node - " + line[1])
                neo4j.make_node(line[1], line[8])

            if not neo4j.is_exist(line[2], line[8]):
                print("New node - " + line[2])
                neo4j.make_node(line[2], line[8])

            if neo4j.is_relation(line):
                print("count up")
                print(line[1] + " -> " + line[2])
                temp = neo4j.get_count(line)
                print("temp = " + str(temp))
                neo4j.set_count(line, temp+1)
            else:
                print("New Relation")
                print(line[1] + " -> " + line[2])
                neo4j.make_relation(line)
 
        return response['ContentType']
    except Exception as e:
        print(e)
        print('Error getting object {} from bucket {}. Make sure they exist and your bucket is in the same region as this function.'.format(key, bucket))
        raise e
