#!/usr/bin/env python3
import asyncio
import ipaddress
import socket
import json
import time
import multiprocessing
import sys
import platform

CIDR_RANGES = [
    "37.120.160.0/19", "5.45.96.0/20", "37.120.160.0/20", "46.38.224.0/20",
    "152.53.128.0/20", "188.68.32.0/20", "202.61.224.0/20", "37.120.184.0/21",
    "37.221.192.0/21", "46.38.232.0/21", "46.224.0.0/15", "78.46.0.0/15",
    "5.9.0.0/16", "37.27.0.0/16", "46.4.0.0/16", "49.12.0.0/16",
    "49.13.0.0/16", "65.21.0.0/16", "65.108.0.0/16", "65.109.0.0/16",
]

TARGET_PORT = 25565
TIMEOUT = 0.4 
BATCH_SIZE = 3000 
HANDSHAKE_BYTES = b'\x0f\x00\x2f\x09\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x63\xdd\x01' + b'\x01\x00'

async def scan_ip(ip, semaphore, stats_queue):
    try:
        conn = asyncio.open_connection(ip, TARGET_PORT)
        reader, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)

        writer.write(HANDSHAKE_BYTES)

        data = await asyncio.wait_for(reader.read(4096), timeout=TIMEOUT)
        
        writer.close()

        if data and b'{' in data:
            json_start = data.find(b'{')
            try:
                json_str = data[json_start:].decode('utf-8', errors='ignore')
                info = json.loads(json_str)
                
                version = info.get('version', {}).get('name', '?')
                online = info.get('players', {}).get('online', 0)
                max_p = info.get('players', {}).get('max', 0)
                
                stats_queue.put(f"[HIT] {ip} | Ver: {version} | {online}/{max_p}")
            except:
                pass
    except:
        pass

async def worker_process(cidrs, stats_queue):
    if platform.system() == 'Windows':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    semaphore = asyncio.Semaphore(BATCH_SIZE)
    
    tasks = []
    
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            
            current_batch = []
            
            for ip in net.hosts():
                current_batch.append(scan_ip(str(ip), semaphore, stats_queue))
                
                if len(current_batch) >= BATCH_SIZE:
                    await asyncio.gather(*current_batch, return_exceptions=True)
                    current_batch = []
            
            if current_batch:
                await asyncio.gather(*current_batch, return_exceptions=True)
                
        except ValueError:
            pass

def start_async_worker(cidrs, q):
    try:
        asyncio.run(worker_process(cidrs, q))
    except KeyboardInterrupt:
        pass

def run_scanner():
    multiprocessing.freeze_support()

    cpu_count = multiprocessing.cpu_count()
    
    worker_loads = [[] for _ in range(cpu_count)]
    for i, cidr in enumerate(CIDR_RANGES):
        worker_loads[i % cpu_count].append(cidr)

    manager = multiprocessing.Manager()
    stats_queue = manager.Queue()

    start_time = time.time()
    processes = []

    for i in range(cpu_count):
        if not worker_loads[i]: continue
        p = multiprocessing.Process(target=start_async_worker, args=(worker_loads[i], stats_queue))
        p.start()
        processes.append(p)

    try:
        hits = 0
        while any(p.is_alive() for p in processes) or not stats_queue.empty():
            while not stats_queue.empty():
                msg = stats_queue.get()
                print(msg)
                hits += 1
            time.sleep(0.2)
            
    except KeyboardInterrupt:
        print("\n[!] Abbruch!")
        for p in processes:
            p.terminate()

    elapsed = time.time() - start_time
    print(f"\n[*] Fertig in {elapsed:.2f}s | Gefunden: {hits}")

if __name__ == "__main__":
    run_scanner()
