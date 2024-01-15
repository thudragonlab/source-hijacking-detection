from datetime import datetime
import threading
from confluent_kafka import Producer
from kafka.errors import KafkaError
from utils.BGPElement import BGPelement
from tqdm import tqdm
import hashlib

partition_mapping = {
    'c': 0,
    'a': 1,
    '9': 2,
    '0': 3,
    '1': 4,
    '3': 5,
    'e': 6,
    'f': 7,
    '5': 8,
    'd': 9,
    '2': 10,
    '8': 11,
    '6': 12,
    '7': 13,
    'b': 14,
    '4': 15,
}

class KafkaProducer:
    """
    生产模块：根据不同的key，区分消息
    """

    def __init__(self, _kafka_config, _logger, index, opt_queue,msg_queue,result_queue):
        self.kafka_topic = _kafka_config["topic"]
        self.queue = msg_queue
        self.__id = self.make_producer_id(index)
        
        self.msg_count = 0
        self._logger = _logger
        self.opt_queue = opt_queue
        self.result_queue = result_queue
        self.stop_listening_queue = False
        self.producer = Producer({
            'bootstrap.servers':
            _kafka_config["addresses"][0],
            'compression.type':
            'gzip',
            'acks':
            0,
            'api.version.request.timeout.ms':
            5 * 60 * 1000,
            'batch.size':
            1024 * 1024,
            'linger.ms':
            1000,
            'request.timeout.ms':
            1000 * 60 * 5,
        })
        self.start_listening_queue()
        self.start_listening_opt_queue()


    def make_producer_id(self,id):
        print(f'Create producer{id}')
        return f'Producer{id}'

    def start_listening_queue(self):

        def _listening_queue():
            msg_count = 0
            while True:
                queue_data = self.queue.get()
                if queue_data:
                    raw_msg, key = queue_data
                    raw_msg = raw_msg
                    try:
                        self.producer.poll(0)
                        msg, p_index = self.__processing_msg(raw_msg)
                        if msg is not None and not msg.skip:
                            self.producer.produce(
                                self.kafka_topic,
                                str(msg),
                                f'{key}-{self.__id}',
                                p_index,
                                callback=self.delivery_report)
                            msg_count += 1

                        if msg_count > 10000:
                            self.producer.flush()
                            msg_count = 0
                    except KafkaError as e:
                        raise e
                        self._logger.error(e)

        t2 = threading.Thread(target=_listening_queue)
        t2.start()

    def start_listening_opt_queue(self):

        def _listening_opt_queue():
            while True:
                data = self.opt_queue.get()
                if data:
                    method_name, *args = data
                    if hasattr(self, method_name):
                        # self._logger.debug(f'[{self.__id}] Do {method_name}')
                        getattr(self, method_name)(*args)

        t = threading.Thread(target=_listening_opt_queue)
        t.start()


    def sendjsondata(self, data, file_name, key):
        self.stop_listening_queue = True
        producer = self.producer
        msg_count = 0
        try:
            for ii in tqdm(data, total=len(data), desc=f'{file_name}'):
                self.producer.poll(0)
                msg, p_index = self.__processing_msg(ii)

                if msg is not None and not msg.skip and p_index != -1:
                    self.producer.produce(self.kafka_topic,
                                          str(msg),
                                          f'{key}-{self.__id}',
                                          p_index,
                                          callback=self.delivery_report)
                    msg_count += 1

                if msg_count > 10000:
                    producer.flush()
                    msg_count = 0
            producer.flush()
        except KafkaError as e:
            self._logger.error(e)
        self.result_queue.put(self.__id)
        self.stop_listening_queue = False

    # def do_flush(self):
    #     while True:
    #         if self.queue.qsize() == 0:
    #             self.producer.flush()
    #             self.result_queue.put(self.__id)
    #             # print(f'[{self.__id}] flush {self.msg_count} data')
    #             break
    #         # else:
    #         #     time.sleep(0.1)

    def __processing_msg(self, msg: str):
        elm = BGPelement(msg)
        if elm.skip:
            return elm, -1
        hash_0 = ''
        self.msg_count += 1
        if elm.version == 4:
            hash_0 = hashlib.md5(
                elm.prefix.split('.')[0].encode()).hexdigest()[0]
        else:
            hash_0 = hashlib.md5(
                elm.prefix.split(':')[0].encode()).hexdigest()[0]
        return elm, partition_mapping[hash_0]

    def delivery_report(self, err, msg):
        """ Called once for each message produced to indicate delivery result.
                   Triggered by poll() or flush(). """
        if err is not None:
            self._logger.error('Message delivery failed: {} {}'.format(
                err, msg))

