import json
import base64
import uuid
import time
import socket
import requests
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs

class ConfigToSingbox:
    def __init__(self):
        self.output_file = 'main'
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

    def get_location_from_ip_api(self, ip: str) -> Tuple[str, str]:
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', headers=self.headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success' and data.get('countryCode'):
                    return data['countryCode'].lower(), data['country']
        except Exception:
            pass
        return '', ''

    def get_location_from_ipapi_co(self, ip: str) -> Tuple[str, str]:
        try:
            response = requests.get(f'https://ipapi.co/{ip}/json/', headers=self.headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('country_code') and data.get('country_name'):
                    return data['country_code'].lower(), data['country_name']
        except Exception:
            pass
        return '', ''

    def get_location_from_ipwhois(self, ip: str) -> Tuple[str, str]:
        try:
            response = requests.get(f'https://ipwhois.app/json/{ip}', headers=self.headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('country_code') and data.get('country'):
                    return data['country_code'].lower(), data['country']
        except Exception:
            pass
        return '', ''

    def get_location(self, address: str) -> tuple:
        try:
            ip = socket.gethostbyname(address)
            apis = [
                self.get_location_from_ip_api,
                self.get_location_from_ipapi_co,
                self.get_location_from_ipwhois,
            ]
            for api_func in apis:
                country_code, country = api_func(ip)
                if country_code and country and len(country_code) == 2:
                    flag = ''.join(chr(ord('🇦') + ord(c.upper()) - ord('A')) for c in country_code)
                    time.sleep(1)
                    return flag, country
            time.sleep(1)
        except Exception:
            pass
        return "🏳️", "Unknown"

    def decode_vmess(self, config: str) -> Optional[Dict]:
        try:
            encoded = config.replace('vmess://', '')
            decoded = base64.b64decode(encoded).decode('utf-8')
            return json.loads(decoded)
        except Exception:
            return None

    def parse_vless(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme.lower() != 'vless' or not url.hostname:
                return None
            netloc = url.netloc.split('@')[-1]
            address, port = netloc.split(':') if ':' in netloc else (netloc, '443')
            params = parse_qs(url.query)
            return {
                'uuid': url.username,
                'address': address,
                'port': int(port),
                'flow': params.get('flow', [''])[0],
                'sni': params.get('sni', [address])[0],
                'type': params.get('type', ['tcp'])[0],
                'path': params.get('path', [''])[0],
                'host': params.get('host', [address])[0],
                'security': params.get('security', ['none'])[0]
            }
        except Exception:
            return None

    def parse_trojan(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme.lower() != 'trojan' or not url.hostname:
                return None
            port = url.port or 443
            params = parse_qs(url.query)
            return {
                'password': url.username,
                'address': url.hostname,
                'port': port,
                'sni': params.get('sni', [url.hostname])[0],
                'alpn': params.get('alpn', [''])[0],
                'type': params.get('type', ['tcp'])[0],
                'path': params.get('path', [''])[0],
                'host': params.get('host', [url.hostname])[0]
            }
        except Exception:
            return None

    def parse_hysteria2(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme.lower() not in ['hysteria2', 'hy2'] or not url.hostname or not url.port:
                return None
            query = dict(pair.split('=') for pair in url.query.split('&')) if url.query else {}
            return {
                'address': url.hostname,
                'port': url.port,
                'password': url.username or query.get('password', ''),
                'sni': query.get('sni', url.hostname)
            }
        except Exception:
            return None

    def parse_shadowsocks(self, config: str) -> Optional[Dict]:
        try:
            parts = config.replace('ss://', '').split('@')
            if len(parts) != 2:
                return None
            method_pass = base64.b64decode(parts[0]).decode('utf-8')
            method, password = method_pass.split(':')
            server_parts = parts[1].split('#')[0]
            host, port = server_parts.split(':')
            return {
                'method': method,
                'password': password,
                'address': host,
                'port': int(port)
            }
        except Exception:
            return None

    def convert_to_singbox(self, config: str, index: int, protocol_type: str) -> Optional[Dict]:
        try:
            config_lower = config.lower()
            if config_lower.startswith('vmess://'):
                data = self.decode_vmess(config)
                if not data or not all(k in data for k in ['add', 'port', 'id']):
                    return None
                flag, country = self.get_location(data['add'])
                tag = f"{flag} {index} - {protocol_type} - {country} : {data['port']}"
                transport = {}
                if data.get('net') == 'ws':
                    transport = {"type": "ws", "path": data.get('path', '/'), "headers": {"Host": data.get('host', data['add'])}}
                tls = {}
                if data.get('tls') == 'tls':
                    tls = {"enabled": True, "server_name": data.get('sni', data['add']), "insecure": False, "alpn": ["http/1.1"], "utls": {"enabled": True, "fingerprint": "chrome"}}
                else:
                    tls = {"enabled": False}
                return {"type": "vmess", "tag": tag, "server": data['add'], "server_port": int(data['port']), "uuid": data['id'], "security": data.get('scy', 'auto'), "alter_id": int(data.get('aid', 0)), "transport": transport, "tls": tls}
            elif config_lower.startswith('vless://'):
                data = self.parse_vless(config)
                if not data: return None
                flag, country = self.get_location(data['address'])
                tag = f"{flag} {index} - {protocol_type} - {country} : {data['port']}"
                transport = {}
                if data['type'] == 'ws':
                    transport = {"type": "ws", "path": data.get('path', '/'), "headers": {"Host": data.get('host', data['address'])}}
                tls_enabled = data['security'] == 'tls' or data['port'] in [443, 2053, 2083, 2087, 2096, 8443]
                tls = {}
                if tls_enabled:
                    tls = {"enabled": True, "server_name": data['sni'], "insecure": False, "alpn": ["http/1.1"], "utls": {"enabled": True, "fingerprint": "chrome"}}
                else:
                    tls = {"enabled": False}
                return {"type": "vless", "tag": tag, "server": data['address'], "server_port": data['port'], "uuid": data['uuid'], "flow": data.get('flow', ''), "tls": tls, "transport": transport}
            elif config_lower.startswith('trojan://'):
                data = self.parse_trojan(config)
                if not data: return None
                flag, country = self.get_location(data['address'])
                tag = f"{flag} {index} - {protocol_type} - {country} : {data['port']}"
                transport = {}
                if data['type'] == 'ws':
                    transport = {"type": "ws", "path": data.get('path', '/'), "headers": {"Host": data.get('host', data['address'])}}
                tls = {"enabled": True, "server_name": data['sni'], "insecure": False, "alpn": ["http/1.1"], "utls": {"enabled": True, "fingerprint": "chrome"}}
                return {"type": "trojan", "tag": tag, "server": data['address'], "server_port": data['port'], "password": data['password'], "tls": tls, "transport": transport}
            elif config_lower.startswith(('hysteria2://', 'hy2://')):
                data = self.parse_hysteria2(config)
                if not data: return None
                flag, country = self.get_location(data['address'])
                tag = f"{flag} {index} - {protocol_type} - {country} : {data['port']}"
                return {"type": "hysteria2", "tag": tag, "server": data['address'], "server_port": data['port'], "password": data['password'], "tls": {"enabled": True, "insecure": True, "server_name": data['sni']}}
            elif config_lower.startswith('ss://'):
                data = self.parse_shadowsocks(config)
                if not data: return None
                flag, country = self.get_location(data['address'])
                tag = f"{flag} {index} - {protocol_type} - {country} : {data['port']}"
                return {"type": "shadowsocks", "tag": tag, "server": data['address'], "server_port": data['port'], "method": data['method'], "password": data['password']}
            return None
        except Exception:
            return None

    def process_configs(self):
        try:
            with open('configs/proxy_configs.txt', 'r', encoding='utf-8') as f:
                configs = [line for line in f.read().strip().split('\n') if line.strip() and not line.strip().startswith('//')]

            outbounds, valid_tags = [], []
            counters = {"VLESS": 1, "Trojan": 1, "VMess": 1, "SS": 1, "Hysteria2": 1}
            protocol_map = {'vless': 'VLESS', 'trojan': 'Trojan', 'vmess': 'VMess', 'ss': 'SS', 'hysteria2': 'Hysteria2', 'hy2': 'Hysteria2'}

            for config in configs:
                protocol_key = config.split('://')[0].lower()
                protocol_name = protocol_map.get(protocol_key)
                if protocol_name:
                    converted = self.convert_to_singbox(config, counters[protocol_name], protocol_name)
                    if converted:
                        tag = converted['tag']
                        if "🇺🇸" in tag or "🇨🇦" in tag or "🏳️" in tag:
                            continue 

                        outbounds.append(converted)
                        valid_tags.append(converted['tag'])
                        counters[protocol_name] += 1

            if not outbounds:
                print("No valid configurations found.")
                return


            final_config = {
  "log": {
    "level": "fatal"
  },
  "dns": {
    "servers": [
      {
        "type": "local"
      }
    ]
  },
    "rules": [
      {
        "outbound": "any",
        "server": "local"
      }
    ]
  },
  "inbounds": [
    {
     "type": "tproxy",
      "tag": "in",
     "listen": "0.0.0.0",
     "listen_port": 7895,
     "domain_strategy": "prefer_ipv4",
     "tcp_fast_open": True,
     "sniff": True,
     "sniff_override_destination": False
    },
{
  "type": "socks",
  "tag": "socksin",
  "listen": "127.0.0.1",
  "listen_port": 20170,
  "sniff": False,
  "sniff_override_destination": False
}
  ],
"outbounds": [
  {
    "type": "selector",
    "tag": "proxy",
    "outbounds": ["Best-Ping"] + valid_tags + ["direct"]
  },
  {
    "type": "urltest",
    "tag": "Best-Ping",
    "outbounds": valid_tags,
    "url": "http://cp.cloudflare.com/",
    "interval": "15m",
    "tolerance": 120
  }
] + outbounds + [
  {
    "type": "direct",
    "tag": "direct"
  },
  {
    "type": "block",
    "tag": "block"
  }
],

  "route": {
    "rules": [
      {
        "network": "udp",
        "port": [
          19302
        ],
        "outbound": "proxy"
      },
      {
        "rule_set": [
          "geosite-ir"
        ],
        "outbound": "direct"
      },
      {
        "domain_suffix": [
          "deserver.top"
      ],
        "outbound": "direct"
      },
      {
        "inbound": ["socksin"],
        "outbound": "proxy"
      }
    ],
    "rule_set": [
              {
        "type": "remote",
        "tag": "geosite-ir",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/refs/heads/rule-set/geosite-ir.srs",
        "download_detour": "direct"
      },
      {
        "type": "remote",
        "tag": "geosite-steam",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/refs/heads/rule-set/geosite-steam.srs",
        "download_detour": "direct"
      }
    ],
    "final": "proxy",
    "default_mark": 666
  },
  "experimental": {
    "clash_api": {
      "external_controller": "0.0.0.0:9090",
      "external_ui": "zashboard",
      "external_ui_download_url": "https://github.com/Zephyruso/zashboard/archive/refs/heads/gh-pages.zip",
      "external_ui_download_detour": "direct",
      "secret": "",
      "default_mode": "rule"
    }
  }
}

            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(final_config, f, indent=4, ensure_ascii=False)
            
            print(f"Configuration successfully generated at: {self.output_file}")

        except Exception as e:
            print(f"Error processing configs: {str(e)}")

def main():
    converter = ConfigToSingbox()
    converter.process_configs()

if __name__ == '__main__':
    main()
