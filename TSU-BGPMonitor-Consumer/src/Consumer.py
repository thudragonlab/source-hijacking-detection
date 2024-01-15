import datetime
from multiprocessing import Pool
import os
import time
import traceback
from confluent_kafka import Consumer, TopicPartition
from src.HijackDetector import HijackDetector
from utils.BGPElement import BGPelement
from utils.reason_util import Reason, get_reason
from utils.config_util import get_config,get_start_datetime
from utils.common_util import exception_happen
from utils.log_util import get_logger
from tqdm import tqdm
import atexit
import math
import sys
import threading
from utils.legal_moas_util import update_legal_moas

kafka_config = get_config('kafka_config')
kafka_hosts = kafka_config["addresses"]
kafka_topic = kafka_config["topic"]
consumer_hash_key = kafka_config["consumer_hash_key"]
start_datetime = get_start_datetime()
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


def ec(e):
    raise e


class MyConsumer:

    def __init__(self, logger, topic, hash_0):
        self.__consumer = None
        self.__topic = topic
        self.__hash_0 = hash_0
        self.__partition = partition_mapping[hash_0]
        self.__tp = TopicPartition(self.__topic, self.__partition)
        self.new_consumer()
        self.__logger = logger
        self.current_ts = datetime.datetime.strptime(start_datetime, "%Y-%m-%d %H:%M").timestamp()
        self.last_ts = datetime.datetime.strptime(start_datetime, "%Y-%m-%d %H:%M").timestamp()
        self.__running = True
        self.load_ongoing_data = get_config('load_ongoing_data')
        self.__update_count = 0
        self.__hijack_detector = HijackDetector(hash_0)
        self.__pb = tqdm(
            total=self.__consumer.get_watermark_offsets(self.__tp)[1],
            desc=f'partition {self.__partition}',
            bar_format=
            '{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}] \n'
        )
        self.get_lag()
        
        if self.load_ongoing_data:
            self.__logger.debug(
                f"[LOAD CONFIG] load_ongoing_data => {self.load_ongoing_data}"
            )
            self.__hijack_detector.load_onging_data()
        self.scan_runnning_dict()
        self.write_event_to_file()

    def scan_runnning_dict(self):
        try:
            self.__logger.debug(f'[ONGOING] Start scan Ongoing Events')
            reason = get_reason(Reason.DURATION_GT_48)
            now = self.current_ts
            MAX_HOURS = 48
            event_manager = self.__hijack_detector.event_manager
            moas_dict = event_manager.running_moas_dict.copy()
            submoas_dict = event_manager.running_submoas_dict.copy()
            self.__logger.debug(f'[ONGOING] moas_dict len {len(moas_dict)}')
            for pfx in moas_dict:
                if now - moas_dict[pfx][
                        'start_timestamp'] >= MAX_HOURS * 60 * 60:
                    update_legal_moas(
                        f'{moas_dict[pfx]["moas_set"][0]} {moas_dict[pfx]["moas_set"][1]} {pfx}',
                        reason)
                    self.__hijack_detector.event_manager.end_moas_event_manual(
                        pfx, now, reason)

            for pfx_key in submoas_dict:
                if now - submoas_dict[pfx_key][
                        'start_timestamp'] >= MAX_HOURS * 60 * 60:
                    update_legal_moas(
                        f'{submoas_dict[pfx_key]["before_as"]} {submoas_dict[pfx_key]["suspicious_as"]} {pfx_key}',
                        reason)
                    self.__hijack_detector.event_manager.end_submoas_event_manual(
                        pfx_key, now, reason)

            self.__logger.debug(f'[ONGOING] End scan Events => {self.__hash_0}')
        except Exception as e:
            exception_happen(e)

    def show_routing_table_info(self):
        print(self.__topic,
              len(self.__hijack_detector.routing_table.prefix_dict))
        threading.Timer(5, self.show_routing_table_info).start()

    def write_event_to_file(self):
        try:
            self.__hijack_detector.event_manager.write_event_to_file()
        except Exception as e:
            exception_happen(e)
        threading.Timer(60 * 5, self.write_event_to_file).start()

    def get_lag(self):
        tp = self.__consumer.position(
            [TopicPartition(self.__topic, self.__partition)])[0]
        self.__pb.total = self.__consumer.get_watermark_offsets(self.__tp)[1]
        if tp.offset != -1001:
            self.__pb.n = tp.offset
        if self.__pb.n > self.__pb.total:
            self.__pb.n = self.__pb.total - 10
        self.__pb.update()
        threading.Timer(30, self.get_lag).start()

    def new_consumer(self):
        self.__consumer = Consumer({
            "bootstrap.servers": kafka_hosts[0],
            "auto.offset.reset": 'earliest',
            "enable.auto.commit": True,
            "api.version.request": False,
            "client.id": '%s' % (self.__topic),
            "session.timeout.ms":30 * 1000,
            "heartbeat.interval.ms": 10 * 1000,
            "queued.min.messages": 5000,
            "max.poll.interval.ms": 5 * 60 * 1000,
            "group.id": f'{self.__topic}-{self.__partition}'
        })
        self.__consumer.assign([self.__tp])

    def __process_message_list(self, msg):
        key = msg.key().decode('utf-8')
        rec = BGPelement(msg.value().decode('utf-8'))

        if 'bview' in key:
            if not rec.skip:
                self.__hijack_detector.routing_table.add_entry(rec)
        elif 'update' in key:
            self.__update_count += 1
            self.__hijack_detector.run(rec)
            if self.__update_count % 10000 == 0:
                self.__hijack_detector.event_manager.logging(
                    rec.timestamp, self.__hijack_detector.update_counter,
                    self.__hijack_detector.rib_prefixes)
        

    def do_listening(self):

        if self.__consumer is not None:
            while self.__running:
                try:
                    if self.current_ts - self.last_ts > 8 * 60 * 60:
                        self.scan_runnning_dict()
                        self.last_ts = self.current_ts 

                    msg = self.__consumer.poll(1.0)
                    if msg is None:
                        continue

                    if msg.error():
                        if msg.error().code() == 1:
                            # End of partition event
                            sys.stderr.write(
                                '%% %s [%d] reached end at offset %d\n' %
                                (msg.topic(), msg.partition(), msg.offset()))
                        elif msg.error():
                            print(msg.error())
                            raise Exception(msg.error())
                    else:
                        if '{' in str(msg) or '}' in str(msg):
                            continue
                        self.__process_message_list(msg)

                except Exception as e:
                    self.__logger.error(e)
                    self.__logger.error(traceback.format_exc())
                    if self.__consumer is not None:
                        self.__consumer.close()
                    self.__consumer = None
                    self.new_consumer()
                    exception_happen(e)
                    pass


def start_consumer(
    logger,
    topic,
    hash_0,
):
    try:
        c = MyConsumer(logger, topic, hash_0)
        c.do_listening()
    except Exception as e:
        exception_happen(e)
        raise e


def pre_start_consumer():
    logger = get_logger()
    thread_pool_size = len(consumer_hash_key)
    pool = Pool(thread_pool_size)
    atexit.register(pool.terminate)
    for hash_0 in consumer_hash_key:
        pool.apply_async(start_consumer, (logger,kafka_topic,hash_0,),error_callback=ec)

    pool.close()
    pool.join()