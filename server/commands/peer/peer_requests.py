import json
import os
import pickle
import time
from datetime import datetime, timezone
from uuid import uuid4

import base
import config
import requests
from base import bot, db_privilege
from telebot.types import InlineKeyboardButton, InlineKeyboardMarkup, ReplyKeyboardRemove

DATA_DIR = "./data"
PENDING_FILE = os.path.join(DATA_DIR, "peer_pending.pkl")

try:
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(PENDING_FILE, "rb") as f:
        _pending_requests = pickle.load(f)
    if not isinstance(_pending_requests, dict):
        _pending_requests = {}
except BaseException:
    _pending_requests = {}


def _save_pending_requests():
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(PENDING_FILE, "wb") as f:
        pickle.dump(_pending_requests, f)


def _generate_request_id():
    while True:
        request_id = uuid4().hex[:8]
        if request_id not in _pending_requests:
            return request_id


def add_pending_request(peer_info, info_text, requester_chat_id):
    request_id = _generate_request_id()
    stored_peer_info = dict(peer_info)
    _pending_requests[request_id] = {
        "id": request_id,
        "asn": peer_info["ASN"],
        "region": peer_info["Region"],
        "requester_chat_id": requester_chat_id,
        "created_at": int(time.time()),
        "peer_info": stored_peer_info,
        "info_text": info_text,
    }
    _save_pending_requests()
    return request_id


def notify_privileged_of_request(request_id, peer_info, info_text):
    created_at = datetime.fromtimestamp(_pending_requests[request_id]["created_at"], tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )
    region = base.servers.get(peer_info["Region"], peer_info["Region"])
    requester = _pending_requests[request_id]["requester_chat_id"]
    text = (
        "*[Privilege]*\n"
        "New peer request pending verification\n"
        f"ID: {request_id}\n"
        f"ASN: AS{peer_info['ASN']}\n"
        f"Region: {region}\n"
        f"From chat: {requester}\n"
        f"Time: {created_at}\n"
        f"```PeerInfo\n{info_text}```\n"
        "Use /peer_request allow <id> or /peer_request deny <id>.\n"
        "使用 /peer_request allow <id> 或 /peer_request deny <id>。"
    )
    for chat_id in db_privilege:
        bot.send_message(chat_id, text, parse_mode="Markdown")


def _format_pending_list():
    if not _pending_requests:
        return "No pending peer requests.\n暂无待审核 Peer 请求。"
    lines = []
    for request_id, data in sorted(_pending_requests.items(), key=lambda i: i[1]["created_at"]):
        created_at = datetime.fromtimestamp(data["created_at"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        region = base.servers.get(data["region"], data["region"])
        header = f"{request_id}  AS{data['asn']}  {region}  {created_at}  chat:{data['requester_chat_id']}"
        info_text = data.get("info_text", "").strip()
        if info_text:
            lines.append(f"{header}\n{info_text}")
        else:
            lines.append(header)
    table_header = "ID        ASN          Region               Time                   Chat"
    return "```PendingPeerRequests\n" + table_header + "\n" + "\n---------------\n".join(lines) + "\n```"


def _approve_request(message, request_id):
    pending = _pending_requests.get(request_id)
    if not pending:
        bot.send_message(
            message.chat.id,
            "Request not found.\n未找到该请求。",
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    peer_info = dict(pending["peer_info"])
    peer_info.pop("Verify", None)
    if peer_info["Region"] in config.HOSTS:
        api = config.HOSTS[peer_info["Region"]]
    else:
        api = f"{peer_info['Region']}.{config.ENDPOINT}"
    try:
        r = requests.post(
            f"http://{api}:{config.API_PORT}/peer",
            data=json.dumps(peer_info),
            headers={"X-DN42-Bot-Api-Secret-Token": config.API_TOKEN},
            timeout=10,
        )
    except BaseException:
        bot.send_message(
            message.chat.id,
            "Agent request failed, please try again later.\nAgent 请求失败，请稍后重试。",
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    if r.status_code == 503:
        bot.send_message(
            message.chat.id,
            (
                "This node is not open for peer, or has reached its maximum peer capacity.\n"
                "该节点暂未开放 Peer，或已达最大 Peer 容量。"
            ),
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    if r.status_code != 200:
        bot.send_message(
            message.chat.id,
            "Agent returned error.\nAgent 返回错误。",
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    _pending_requests.pop(request_id, None)
    _save_pending_requests()
    bot.send_message(
        message.chat.id,
        f"Approved request {request_id}.\n已批准请求 {request_id}。",
        reply_markup=ReplyKeyboardRemove(),
    )
    markup = InlineKeyboardMarkup()
    markup.row_width = 1
    markup.add(
        InlineKeyboardButton(
            "Show info | 查看信息",
            url=f"https://t.me/{bot.get_me().username}?start=info_{peer_info['ASN']}_{peer_info['Region']}",
        )
    )
    bot.send_message(
        pending["requester_chat_id"],
        "Your peer request has been approved and created.\n你的 Peer 请求已通过并建立。",
        reply_markup=markup,
    )


def _deny_request(message, request_id, reason):
    pending = _pending_requests.get(request_id)
    if not pending:
        bot.send_message(
            message.chat.id,
            "Request not found.\n未找到该请求。",
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    _pending_requests.pop(request_id, None)
    _save_pending_requests()
    bot.send_message(
        message.chat.id,
        f"Denied request {request_id}.\n已拒绝请求 {request_id}。",
        reply_markup=ReplyKeyboardRemove(),
    )
    text = "Your peer request was denied.\n你的 Peer 请求被拒绝。"
    if reason:
        text += f"\nReason: {reason}\n原因：{reason}"
    bot.send_message(pending["requester_chat_id"], text, reply_markup=ReplyKeyboardRemove())


@bot.message_handler(commands=["peer_request", "peer_requests"], is_private_chat=True)
def peer_request_command(message):
    if message.chat.id not in db_privilege:
        bot.send_message(
            message.chat.id,
            "You are not allowed to use this command.\n你无权使用此命令。",
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    parts = message.text.strip().split()
    if len(parts) == 1:
        bot.send_message(
            message.chat.id,
            (
                "Usage:\n"
                "  /peer_request list\n"
                "  /peer_request allow <id>\n"
                "  /peer_request deny <id> [reason]\n"
                "用法：\n"
                "  /peer_request list\n"
                "  /peer_request allow <id>\n"
                "  /peer_request deny <id> [reason]"
            ),
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    if parts[1].lower() in {"list", "ls"}:
        bot.send_message(
            message.chat.id,
            _format_pending_list(),
            parse_mode="Markdown",
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    action = parts[1].lower()
    if action in {"allow", "approve", "accept"} and len(parts) >= 3:
        request_id = parts[2].lower()
        _approve_request(message, request_id)
        return
    if action in {"deny", "reject"} and len(parts) >= 3:
        request_id = parts[2].lower()
        reason = " ".join(parts[3:]).strip()
        _deny_request(message, request_id, reason)
        return
    bot.send_message(
        message.chat.id,
        (
            "Usage:\n"
            "  /peer_request list\n"
            "  /peer_request allow <id>\n"
            "  /peer_request deny <id> [reason]\n"
            "用法：\n"
            "  /peer_request list\n"
            "  /peer_request allow <id>\n"
            "  /peer_request deny <id> [reason]"
        ),
        reply_markup=ReplyKeyboardRemove(),
    )
