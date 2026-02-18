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
    'cis': {'domain': 'clientbp.ggpolarbear.com', 'token_file': 'tokens_cis.json'},
    'sg': {'domain': 'clientbp.ggpolarbear.com', 'token_file': 'tokens_sg.json'},
    'ru': {'domain': 'clientbp.ggpolarbear.com', 'token_file': 'tokens_ru.json'}
}

def load_tokens(region):
    try:
        config = REGION_CONFIG.get(region, REGION_CONFIG['cis'])
        with open(config['token_file'], "r") as f:
            return json.load(f)
    except:
        return None

def encrypt_message(plaintext_bytes):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext_bytes, AES.block_size)
    return binascii.hexlify(cipher.encrypt(padded)).decode('utf-8')

def get_player_info(uid, region):
    tokens = load_tokens(region)
    if not tokens: return f"Игрок {uid}", uid, region
    
    token = tokens[0]['token']
    config = REGION_CONFIG.get(region, REGION_CONFIG['cis'])
    
    # Подготовка данных для ника
    msg = danger_generator_pb2.danger_generator()
    msg.saturn_ = int(uid)
    msg.garena = 1
    edata = bytes.fromhex(encrypt_message(msg.SerializeToString()))

    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11)",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded"
    }

    try:
        res = requests.post(f"https://{config['domain']}/GetPlayerPersonalShow", data=edata, headers=headers, timeout=5)
        if res.status_code == 200:
            info = danger_count_pb2.Danger()
            info.ParseFromString(res.content)
            name = json.loads(MessageToJson(info)).get("PlayerNickname")
            if name: return name, uid, region
    except:
        pass
    return f"Игрок {uid}", uid, region

def send_friend_request(uid, token, domain, results, lock):
    try:
        # Важно: используем функции из byte.py
        encrypted_id = Encrypt_ID(uid)
        payload = f"08a7c4839f1e10{encrypted_id}1801"
        edata = bytes.fromhex(encrypt_api(payload))
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0"
        }

        response = requests.post(f"https://{domain}/RequestAddingFriend", data=edata, headers=headers, timeout=10)
        
        with lock:
            if response.status_code == 200:
                results['success'] += 1
            else:
                results['failed'] += 1
    except:
        with lock: results['failed'] += 1

@app.route("/send_requests", methods=["GET"])
def handle():
    uid = request.args.get("uid")
    region = request.args.get("region", "cis").lower()

    if not uid: return Response("No UID", status=400)

    tokens = load_tokens(region)
    if not tokens: return Response("No Tokens", status=400)

    # 1. Получаем ник
    player_name, _, _ = get_player_info(uid, region)

    # 2. Спам
    config = REGION_CONFIG.get(region, REGION_CONFIG['cis'])
    results = {"success": 0, "failed": 0}
    lock = threading.Lock()
    threads = []

    for i in range(min(100, len(tokens))):
        t = threading.Thread(target=send_friend_request, args=(uid, tokens[i]['token'], config['domain'], results, lock))
        t.start()
        threads.append(t)

    for t in threads: t.join()

    return Response(json.dumps(OrderedDict([
        ("PlayerName", player_name),
        ("UID", uid),
        ("Region", region.upper()),
        ("Success", results["success"]),
        ("Failed", results["failed"]),
        ("Status", 1 if results["success"] > 0 else 2)
    ])), mimetype="application/json")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
