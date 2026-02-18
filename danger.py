# danger.py
from flask import Flask, request, Response
import json
import threading
import requests
from google.protobuf.json_format import MessageToJson
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
from collections import OrderedDict
import danger_count_pb2
import danger_generator_pb2
from byte import Encrypt_ID, encrypt_api
import re # Добавили модуль для поиска имени в тексте

app = Flask(__name__)

# Region configuration mapping
REGION_CONFIG = {
    'ind': {'domain': 'client.ind.freefiremobile.com', 'token_file': 'tokens_ind.json'},
    'br': {'domain': 'client.us.freefiremobile.com', 'token_file': 'tokens_br.json'},
    'us': {'domain': 'client.us.freefiremobile.com', 'token_file': 'tokens_us.json'},
    'na': {'domain': 'client.us.freefiremobile.com', 'token_file': 'tokens_na.json'},
    'sac': {'domain': 'client.us.freefiremobile.com', 'token_file': 'tokens_sac.json'},
    'pk': {'domain': 'clientbp.ggpolarbear.com', 'token_file': 'tokens_pk.json'},
    'sg': {'domain': 'clientbp.ggpolarbear.com', 'token_file': 'tokens_sg.json'},
    'bd': {'domain': 'clientbp.ggpolarbear.com', 'token_file': 'tokens_bd.json'},
    'vn': {'domain': 'clientbp.ggpolarbear.com', 'token_file': 'tokens_vn.json'},
    'me': {'domain': 'clientbp.ggpolarbear.com', 'token_file': 'tokens_me.json'},
    'eu': {'domain': 'clientbp.ggpolarbear.com', 'token_file': 'tokens_eu.json'},
    'id': {'domain': 'clientbp.ggpolarbear.com', 'token_file': 'tokens_id.json'},
    'th': {'domain': 'clientbp.ggpolarbear.com', 'token_file': 'tokens_th.json'},
    'tw': {'domain': 'clientbp.ggpolarbear.com', 'token_file': 'tokens_tw.json'},
    'cis': {'domain': 'clientbp.ggpolarbear.com', 'token_file': 'tokens_cis.json'},
    'ru': {'domain': 'clientbp.ggpolarbear.com', 'token_file': 'tokens_ru.json'}
}

def load_tokens(region):
    """Load tokens for specific region"""
    try:
        config = REGION_CONFIG.get(region)
        if not config:
            return None
            
        with open(config['token_file'], "r") as f:
            return json.load(f)
    except:
        return None

def encrypt_message(plaintext_bytes):
    """AES encryption for all regions"""
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext_bytes, AES.block_size)
    encrypted = cipher.encrypt(padded)
    return binascii.hexlify(encrypted).decode('utf-8')

def create_uid_protobuf(uid):
    """Create protobuf message for UID"""
    msg = danger_generator_pb2.danger_generator()
    msg.saturn_ = int(uid)
    msg.garena = 1
    return msg.SerializeToString()

def enc(uid):
    """Encrypt UID for API request"""
    pb = create_uid_protobuf(uid)
    return encrypt_message(pb)

def decode_player_info(binary):
    """Decode player info from protobuf"""
    info = danger_count_pb2.Danger_ff_like()
    info.ParseFromString(binary)
    return info

def get_player_info(uid, region):
    """Get player info from specific region"""
    tokens = load_tokens(region)
    # Если токены не загрузились, возвращаем заглушку, но не None
    if tokens is None:
        return f"Игрок {uid}", uid, region

    token = tokens[0]['token']
    config = REGION_CONFIG.get(region)
    url = f"https://{config['domain']}/GetPlayerPersonalShow"

    encrypted_uid = enc(uid)
    edata = bytes.fromhex(encrypted_uid)

    headers = {
        'User-Agent': "Dalvik/2.1.0",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB52"
    }

    try:
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=10)

        player_name = None

        if response.status_code == 200:
            # 1. Попытка через Protobuf
            try:
                info = danger_count_pb2.Danger() # Используем базовый класс
                info.ParseFromString(response.content)
                data = json.loads(MessageToJson(info))
                
                # Ищем ник в разных местах JSON
                player_name = data.get("PlayerNickname")
                if not player_name:
                    player_name = data.get("AccountInfo", {}).get("PlayerNickname")
            except:
                pass

            # 2. Попытка через Regex (если Protobuf не сработал)
            if not player_name:
                try:
                    raw_text = response.content.decode('utf-8', errors='ignore')
                    # Ищем текстовый паттерн ника (буквы, цифры, пробелы, длина от 3 до 14)
                    match = re.search(r'\b[A-Za-z0-9\s_]{3,14}\b', raw_text)
                    if match:
                        candidate = match.group(0)
                        # Фильтруем технические слова
                        if "OB52" not in candidate and "Unity" not in candidate:
                            player_name = candidate
                except:
                    pass

        # Если имя так и не нашли, ставим ID
        if not player_name or player_name == "Unknown":
            player_name = f"Игрок {uid}"

        return player_name, uid, region

    except Exception as e:
        print(f"Error getting info: {e}")
        return f"Игрок {uid}", uid, region

def send_friend_request(uid, token, domain, results, lock):
    """Send friend request to specific domain"""
    try:
        encrypted_id = Encrypt_ID(uid)
        payload = f"08a7c4839f1e10{encrypted_id}1801"
        encrypted_payload = encrypt_api(payload)
        
        url = f"https://{domain}/RequestAddingFriend"

        headers = {
            "Authorization": f"Bearer {token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB52",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0"
        }

        response = requests.post(url, data=bytes.fromhex(encrypted_payload), headers=headers, timeout=10)

        with lock:
            if response.status_code == 200:
                results['success'] += 1
            else:
                results['failed'] += 1

    except:
        with lock:
            results['failed'] += 1

@app.route("/send_requests", methods=["GET"])
def handle_friend_request():
    """Handle friend requests with region support"""
    uid = request.args.get("uid")
    region = request.args.get("region", "ind")  # Default to IND if not specified

    if not uid:
        return Response(json.dumps({"error": "uid required"}), mimetype="application/json")

    # Validate region
    if region not in REGION_CONFIG:
        return Response(json.dumps({"error": f"Invalid region. Supported: {', '.join(REGION_CONFIG.keys())}"}), 
                       mimetype="application/json")

    tokens = load_tokens(region)
    if tokens is None:
        return Response(json.dumps({"error": f"Token file for region {region} not found"}), 
                       mimetype="application/json")

    # Получаем имя игрока (теперь функция безопасна)
    player_name, player_uid, region = get_player_info(uid, region)

    config = REGION_CONFIG.get(region)
    domain = config['domain']

    results = {"success": 0, "failed": 0}
    lock = threading.Lock()
    threads = []

    # Запускаем потоки для спама
    for i in range(min(100, len(tokens))):
        token = tokens[i]['token']
        thread = threading.Thread(target=send_friend_request, args=(uid, token, domain, results, lock))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    output = OrderedDict([
        ("PlayerName", player_name),
        ("UID", uid),
        ("Region", region.upper()),
        ("Success", results["success"]),
        ("Failed", results["failed"]),
        ("Status", 1 if results["success"] > 0 else 2)
    ])

    return Response(json.dumps(output), mimetype="application/json")

@app.route("/regions", methods=["GET"])
def list_regions():
    """List all available regions"""
    regions = [{"code": code, "domain": config['domain'], "token_file": config['token_file']} 
               for code, config in REGION_CONFIG.items()]
    return Response(json.dumps({"regions": regions}), mimetype="application/json")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
