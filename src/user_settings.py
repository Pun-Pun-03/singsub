# Please modify the settings below according to your needs.

# List of source URLs to fetch proxy configurations from.
# Add or remove URLs as needed. All URLs in this list are automatically enabled.
SOURCE_URLS = [
   #"https://drive.google.com/uc?id=1t6JEHK87a0U-jTzw3n_M7u_fKA2N1LTY&export=download#%E2%AD%90%EF%B8%8FFreeXrayVPN%E2%AD%90%EF%B8%8F"
   "https://raw.githubusercontent.com/miladtahanian/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt"
   "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs_tested.txt"
   #"https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt"
   "https://t.me/s/v2rayngvpn",
   "https://t.me/s/unlimited_v2ray_ng",
   #"https://t.me/s/manVPN",
   #"https://t.me/s/entryNET",
   #"https://t.me/s/V2raysCollector",
   #"https://t.me/s/NETMelliAnti",
   #"https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mci/sub_1.txt"
   # Add more URLs here if you want to include additional sources.
]

# Set to True to fetch the maximum possible number of configurations.
# If True, SPECIFIC_CONFIG_COUNT will be ignored.
USE_MAXIMUM_POWER = False

# Desired number of configurations to fetch.
# This is used only if USE_MAXIMUM_POWER is False.
SPECIFIC_CONFIG_COUNT = 400

# Dictionary of protocols to enable or disable.
# Set each protocol to True to enable, False to disable.
ENABLED_PROTOCOLS = {
    "wireguard://": False,
    "hysteria2://": False,
    "vless://": True,
    "vmess://": True,
    "ss://": True,
    "trojan://": True,
    "tuic://": False,
}

# Maximum age of configurations in days.
# Configurations older than this will be considered invalid.
MAX_CONFIG_AGE_DAYS = 30
