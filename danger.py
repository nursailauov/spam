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
import re

app = Flask(__name__)

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
    try:
        config = REGION_CONFIG.get(region)
        with open(config['token_file'], "r") as f:
            return json.load(f)
    except:
        return None

def encrypt_message(plaintext_bytes):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext_bytes, AES.block_size)
    encrypted = cipher.encrypt(padded)
    return binascii.hexlify(encrypted).decode('utf-8')

def create_uid_protobuf(uid):
    msg = danger_generator_pb2.danger_generator()
    msg.saturn_ = int(uid)
    msg.garena = 1
    return msg.SerializeToString()

def enc(uid):
    pb = create_uid_protobuf(uid)
    return encrypt_message(pb)

def get_player_info(uid, region):
    tokens = load_tokens(region)
    if not tokens:
        return f"Игрок {uid}", uid, region

    token = tokens[0]['token']
    config = REGION_CONFIG.get(region)
    url = f"https://{config['domain']}/GetPlayerPersonalShow"

    # Шифруем UID цели
    encrypted_payload = enc(uid)
    edata = bytes.fromhex(encrypted_payload)

    headers = {
        'User-Agent': "Dalvik/2.1.0",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'ReleaseVersion': "OB52"
    }

    try:
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=10)
        player_name = None

        if response.status_code == 200:
            try:
                # Декодируем информацию о цели (UID)
                info = danger_count_pb2.Danger()
                info.ParseFromString(response.content)
                data = json.loads(MessageToJson(info))
                
                # Ищем ник цели
                player_name = data.get("PlayerNickname")
            except:
                # Резервный поиск через Regex
                raw_text = response.content.decode('utf-8', errors='ignore')
                match = re.search(r'[\w\s]{3,15}', raw_text)
                if match:
                    player_name = match.group(0).strip()

        if not player_name or len(player_name) < 2:
            player_name = f"Игрок {uid}"

        return player_name, uid, region
    except:
        return f"Игрок {uid}", uid, region

def send_friend_request(uid, token, domain, results, lock):
    try:
        encrypted_id = Encrypt_ID(uid)
        payload = f"08a7c4839f1e10{encrypted_id}1801"
        encrypted_payload = encrypt_api(payload)
        
        url = f"https://{domain}/RequestAddingFriend"
        headers = {
            "Authorization": f"Bearer {token}",
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
    uid = request.args.get("uid")
    region = request.args.get("region", "cis")

    if not uid:
        return Response(json.dumps({"error": "uid required"}), mimetype="application/json")

    tokens = load_tokens(region)
    if not tokens:
        return Response(json.dumps({"error": "No tokens"}), mimetype="application/json")

    # Получаем никнейм цели (nur sailauov)
    player_name, player_uid, region = get_player_info(uid, region)

    config = REGION_CONFIG.get(region)
    results = {"success": 0, "failed": 0}
    lock = threading.Lock()
    threads = []

    for i in range(min(100, len(tokens))):
        t = threading.Thread(target=send_friend_request, args=(uid, tokens[i]['token'], config['domain'], results, lock))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    output = OrderedDict([
        ("PlayerName", player_name),
        ("UID", uid),
        ("Region", region.upper()),
        ("Success", results["success"]),
        ("Failed", results["failed"]),
        ("Status", 1 if results["success"] > 0 else 2)
    ])

    return Response(json.dumps(output), mimetype="application/json")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
