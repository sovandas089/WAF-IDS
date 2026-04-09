import threading
from scapy.all import sniff
from backend.analyzer import process_packet
import logging

class PacketSniffer:
    def __init__(self):
        self.stop_event = threading.Event()
        self.sniff_thread = None

    def _sniff_loop(self):
        logging.info("Sniffer started...")
        # Start sniffing
        # prn applies process_packet to each packet
        # stop_filter stops sniffing when stop_event is set
        sniff(
            prn=process_packet,
            store=False,
            stop_filter=lambda x: self.stop_event.is_set()
        )
        logging.info("Sniffer stopped...")

    def start(self):
        self.stop_event.clear()
        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()

    def stop(self):
        self.stop_event.set()
        if self.sniff_thread:
            self.sniff_thread.join()
