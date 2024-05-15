import socket
import struct
import time
import threading
import json
import os

dns_cache = {}
reverse_dns_cache = {}

CACHE_FILE = "dns_cache.json"

LOCK = threading.Lock()

def load_cache():
    global dns_cache, reverse_dns_cache
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            cache_data = json.load(f)
            dns_cache = cache_data.get("dns_cache", {})
            reverse_dns_cache = cache_data.get("reverse_dns_cache", {})
        current_time = time.time()
        dns_cache = {k: v for k, v in dns_cache.items() if v["ttl"] > current_time}
        reverse_dns_cache = {k: v for k, v in reverse_dns_cache.items() if v["ttl"] > current_time}
        save_cache()

def save_cache():
    with LOCK:
        cache_data = {
            "dns_cache": dns_cache,
            "reverse_dns_cache": reverse_dns_cache
        }
        with open(CACHE_FILE, "w") as f:
            json.dump(cache_data, f)

def handle_request(data, addr, sock):
    try:
        query_id = data[:2]
        query_params = data[2:12]
        query_name = data[12:]

        domain_name = ""
        i = 0
        while True:
            length = query_name[i]
            if length == 0:
                break
            domain_name += query_name[i+1:i+1+length].decode() + "."
            i += length + 1

        # Проверяем кэш
        if domain_name in dns_cache:
            response = dns_cache[domain_name]["response"]
        else:
            response = recursive_query(data)
            if response:
                cache_response(domain_name, response)
            else:
                response = query_id + struct.pack(">H", 0x8183) + query_params + query_name + struct.pack(">H", 0)
        sock.sendto(response, addr)
    except Exception as e:
        print(f"Ошибка обработки запроса: {e}")

def recursive_query(data):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(data, ('8.8.8.8', 53))
        response, _ = sock.recvfrom(512)
        return response
    except socket.timeout:
        return None
    except socket.error as e:
        print(f"Ошибка при связи с старшим сервером: {e}")
        return None

def cache_response(domain_name, response):
    with LOCK:
        current_time = time.time()
        num_rrs = struct.unpack_from(">H", response, offset=6)[0]
        offset = 12
        answers = []

        while num_rrs > 0:
            while response[offset] != 0:
                offset += 1
            offset += 5
            ttl = struct.unpack_from(">L", response, offset+2)[0]
            ttl += current_time
            data_len = struct.unpack_from(">H", response, offset+6)[0]
            rdata = response[offset+8:offset+8+data_len]
            offset += 8 + data_len
            num_rrs -= 1
            answers.append((ttl, rdata))

        dns_cache[domain_name] = {"ttl": ttl, "response": response}

        for answer in answers:
            ip_address = socket.inet_ntop(socket.AF_INET, answer[1])
            reverse_dns_cache[ip_address] = {"ttl": answer[0], "response": response}

        save_cache()

def cache_cleanup():
    while True:
        current_time = time.time()
        with LOCK:
            dns_cache = {k: v for k, v in dns_cache.items() if v["ttl"] > current_time}
            reverse_dns_cache = {k: v for k, v in reverse_dns_cache.items() if v["ttl"] > current_time}
            save_cache()
        time.sleep(60)

def main():
    load_cache()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 53))

    cleanup_thread = threading.Thread(target=cache_cleanup, daemon=True)
    cleanup_thread.start()

    try:
        while True:
            data, addr = sock.recvfrom(512)
            threading.Thread(target=handle_request, args=(data, addr, sock)).start()
    except KeyboardInterrupt:
        print("Остановка сервера...")
        save_cache()
    except Exception as e:
        print(f"Ошибка основной функции: {e}")

if __name__ == '__main__':
    main()