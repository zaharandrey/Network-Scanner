import socket
from scapy.all import ARP, Ether, srp
import concurrent.futures
import json

# Функція для ARP-сканування активних хостів
def scan_active_hosts(ip_range):
    """Повертає список активних хостів у заданому діапазоні IP."""
    print(f"Сканування активних хостів у діапазоні {ip_range}...")
    active_hosts = []
    arp_request = ARP(pdst=ip_range)
    ether_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether_broadcast / arp_request
    result = srp(packet, timeout=2, verbose=False)[0]

    for sent, received in result:
        active_hosts.append({'ip': received.psrc, 'mac': received.hwsrc})

    print(f"Знайдено {len(active_hosts)} активних хостів.")
    return active_hosts

# Функція для сканування портів на хості
def scan_ports(ip, ports):
    """Повертає список відкритих портів для заданого IP."""
    print(f"Сканування портів для {ip}...")
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
    return open_ports

# Функція для отримання банера сервісу на порту
def get_service_banner(ip, port):
    """Зчитує банер сервісу на вказаному порту."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect((ip, port))
            sock.sendall(b'\n')
            banner = sock.recv(1024).decode().strip()
            return banner
    except:
        return "Unknown"

# Основна функція сканування мережі
def network_scan(ip_range, ports):
    results = []

    # Сканування активних хостів
    active_hosts = scan_active_hosts(ip_range)

    # Сканування портів та визначення сервісів
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_host = {
            executor.submit(scan_ports, host['ip'], ports): host for host in active_hosts
        }

        for future in concurrent.futures.as_completed(future_to_host):
            host = future_to_host[future]
            try:
                open_ports = future.result()
                services = []
                for port in open_ports:
                    banner = get_service_banner(host['ip'], port)
                    services.append({'port': port, 'banner': banner})

                results.append({'ip': host['ip'], 'mac': host['mac'], 'services': services})
            except Exception as e:
                print(f"Помилка сканування {host['ip']}: {e}")

    # Збереження результатів у файл
    with open('scan_results.json', 'w') as f:
        json.dump(results, f, indent=4)

    print("Сканування завершено. Результати збережено у 'scan_results.json'.")
    return results

if __name__ == "__main__":
    ip_range = input("Введіть діапазон IP (наприклад, 192.168.1.0/24): ")
    ports = input("Введіть діапазон портів (наприклад, 20-100): ")

    # Перетворення діапазону портів у список
    start_port, end_port = map(int, ports.split('-'))
    ports = list(range(start_port, end_port + 1))

    # Запуск сканування
    network_scan(ip_range, ports)

