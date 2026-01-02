import os
import pickle
import re
import shlex
import subprocess
from functools import partial

import config
import tools
from base import bot, db, db_privilege
from telebot.types import KeyboardButton, ReplyKeyboardMarkup, ReplyKeyboardRemove
from tools import registry


def get_email(asn):
    """获取 ASN 关联的所有 email 地址
    
    支持递归查找：如果 admin-c 指向 role/organisation，会继续查找其 admin-c/tech-c
    
    Args:
        asn: AS号
        
    Returns:
        set: email 地址集合
    """
    def extract_emails_from_text(text):
        """从文本中提取所有 email 地址"""
        emails = set()
        for line in text.splitlines():
            if line.startswith("e-mail:") or line.startswith("abuse-mailbox:"):
                email = line.split(":", 1)[1].strip()
                if re.fullmatch(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", email):
                    emails.add(email)
            elif line.startswith("contact:"):
                # contact 字段也可能包含 email
                email = line.split(":", 1)[1].strip()
                if re.fullmatch(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", email):
                    emails.add(email)
        return emails
    
    def extract_contacts_from_text(text):
        """从文本中提取 admin-c 和 tech-c"""
        contacts = set()
        for line in text.splitlines():
            if line.startswith("admin-c:") or line.startswith("tech-c:"):
                contact = line.split(":", 1)[1].strip()
                if contact:
                    contacts.add(contact)
        return contacts
    
    def get_contact_text(contact_id):
        """获取 contact 的 whois 信息"""
        text = registry.get_whois_info_from_registry(contact_id)
        if text:
            return text
        # Fallback to whois command
        try:
            return subprocess.check_output(
                shlex.split(f"whois -h {config.WHOIS_ADDRESS} {contact_id}"),
                timeout=3
            ).decode("utf-8")
        except BaseException:
            return None
    
    def recursive_get_emails(contact_id, visited=None, depth=0):
        """递归获取 contact 及其子 contact 的所有 email"""
        if visited is None:
            visited = set()
        
        # 防止无限递归和循环引用
        if contact_id in visited or depth > 5:
            return set()
        visited.add(contact_id)
        
        contact_text = get_contact_text(contact_id)
        if not contact_text:
            return set()
        
        emails = extract_emails_from_text(contact_text)
        
        # 如果当前 contact 没有 email，继续查找其 admin-c/tech-c
        if not emails:
            sub_contacts = extract_contacts_from_text(contact_text)
            for sub_contact in sub_contacts:
                emails.update(recursive_get_emails(sub_contact, visited, depth + 1))
        
        return emails
    
    try:
        # 从本地 registry 获取 ASN 信息
        whois_text = registry.get_whois_info_from_registry(str(asn))
        
        if not whois_text:
            # Fallback to whois command
            whois_text = subprocess.check_output(
                shlex.split(f"whois -h {config.WHOIS_ADDRESS} {asn}"),
                timeout=3
            ).decode("utf-8")
        
        # 收集 admin-c 和 tech-c
        contacts = extract_contacts_from_text(whois_text)
        
        if not contacts:
            return set()
        
        # 递归获取所有 email
        emails = set()
        visited = set()
        for contact in contacts:
            emails.update(recursive_get_emails(contact, visited))
        
        return emails
    except BaseException:
        return set()


def get_auth(asn):
    """获取 ASN 对应的 mntner 的认证方式 (auth)
    
    auth 字段存储在 mntner 文件中，而非 aut-num 文件中。
    需要先从 aut-num 获取 mnt-by，然后从 mntner 获取 auth。
    """
    try:
        # 首先获取 ASN 的 mnt-by 字段
        whois_text = registry.get_whois_info_from_registry(str(asn))
        
        if whois_text:
            whois = whois_text.splitlines()
        else:
            whois = (
                subprocess.check_output(shlex.split(f"whois -h {config.WHOIS_ADDRESS} {asn}"), timeout=3)
                .decode("utf-8")
                .splitlines()[3:]
            )
        
        # 从 ASN 信息中获取 mnt-by
        mnt_by = None
        for line in whois:
            if line.startswith("mnt-by:"):
                mnt_by = line.split(":")[1].strip()
                break
        
        if not mnt_by:
            return set()
        
        # 从 mntner 获取 auth 字段
        mntner_text = registry.get_whois_info_from_registry(mnt_by)
        
        if mntner_text:
            mntner_whois = mntner_text.splitlines()
        else:
            mntner_whois = (
                subprocess.check_output(shlex.split(f"whois -h {config.WHOIS_ADDRESS} {mnt_by}"), timeout=3)
                .decode("utf-8")
                .splitlines()[3:]
            )
        
        auths = set()
        for line in mntner_whois:
            if line.startswith("auth:"):
                # auth 字段格式可能是 "auth: ssh-ed25519 AAAA..." 或 "auth: pgpkey-XXXX"
                # 需要保留完整的值（冒号后的所有内容）
                auth = line.split(":", 1)[1].strip()
                auths.add(auth)
        return auths
    except BaseException:
        return set()

@bot.message_handler(commands=["login"], is_private_chat=True)
def start_login(message):
    if message.chat.id in db:
        bot.send_message(
            message.chat.id,
            (
                f"You are already logged in as `{tools.get_asn_mnt_text(db[message.chat.id])}`, please use /logout to log out.\n"
                f"你已经以 `{tools.get_asn_mnt_text(db[message.chat.id])}` 的身份登录了，请使用 /logout 退出。"
            ),
            parse_mode="Markdown",
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    if len(message.text.split()) == 2:
        login_input_asn(message.text.split()[1], message)
        return
    msg = bot.send_message(
        message.chat.id,
        "Enter your ASN\n请输入你的 ASN",
        reply_markup=ReplyKeyboardRemove(),
    )
    bot.register_next_step_handler(msg, partial(login_input_asn, None))


def login_input_asn(exist_asn, message):
    raw = str(exist_asn) if exist_asn else message.text.strip()
    if raw == "/cancel":
        bot.send_message(
            message.chat.id,
            "Current operation has been cancelled.\n当前操作已被取消。",
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    if asn := tools.extract_asn(raw):
        # 进入验证方式选择
        markup = ReplyKeyboardMarkup(resize_keyboard=True)
        markup.row_width = 1
        markup.add(
            KeyboardButton("📧 Email Verification 邮箱验证"),
            KeyboardButton("🔐 Signature Challenge 签名挑战")
        )
        msg = bot.send_message(
            message.chat.id,
            (
                "Choose authentication method. Use /cancel to interrupt the operation.\n"
                "选择验证方式。使用 /cancel 终止操作。"
            ),
            reply_markup=markup,
        )
        bot.register_next_step_handler(msg, partial(login_choose_auth_method, asn))
    elif exist_asn:
        msg = bot.send_message(
            message.chat.id,
            "Input is not a registered DN42 ASN, please try again.\n输入不是已注册的 DN42 ASN，请重试。",
            reply_markup=ReplyKeyboardRemove(),
        )
    else:
        msg = bot.send_message(
            message.chat.id,
            (
                "Input is not a registered DN42 ASN, please try again. Use /cancel to interrupt the operation.\n"
                "输入不是已注册的 DN42 ASN，请重试。使用 /cancel 终止操作。"
            ),
            reply_markup=ReplyKeyboardRemove(),
        )
        bot.register_next_step_handler(msg, partial(login_input_asn, None))


def login_choose_auth_method(asn, message):
    """选择验证方式"""
    if message.text.strip() == "/cancel":
        bot.send_message(
            message.chat.id,
            "Current operation has been cancelled.\n当前操作已被取消。",
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    
    choice = message.text.strip()
    
    # 邮箱验证
    if "Email" in choice or "邮箱" in choice:
        login_start_email_verification(asn, message)
    # 签名挑战（自动检测GPG/SSH）
    elif "Signature" in choice or "签名" in choice:
        login_signature_challenge(asn, message)
    else:
        msg = bot.send_message(
            message.chat.id,
            (
                "Invalid choice. Please select a valid authentication method. Use /cancel to interrupt the operation.\n"
                "无效的选择。请选择有效的验证方式。使用 /cancel 终止操作。"
            ),
            reply_markup=ReplyKeyboardRemove(),
        )
        bot.register_next_step_handler(msg, partial(login_choose_auth_method, asn))


def login_start_email_verification(asn, message):
    """开始邮箱验证流程"""
    emails = get_email(asn)

    markup = ReplyKeyboardMarkup(resize_keyboard=True)
    markup.row_width = 1
    if emails:
        markup.add(*(KeyboardButton(email) for email in emails))
    markup.add(KeyboardButton("None of the above 以上都不是"))
    msg = bot.send_message(
        message.chat.id,
        (
            "Select the email address to receive the verification code. Use /cancel to interrupt the operation.\n"
            "选择接收验证码的邮箱。使用 /cancel 终止操作。"
        ),
        reply_markup=markup,
    )
    bot.register_next_step_handler(msg, partial(login_choose_email, asn, emails, msg.message_id))


def login_signature_challenge(asn, message):
    """签名挑战验证
    
    自动从 registry 中获取用户的认证方式（GPG/SSH）
    
    Args:
        asn: AS号
        message: 消息对象
    """
    # 检查 PRIVILEGE_CODE
    if (
        config.PRIVILEGE_CODE
        and (not (config.SINGLE_PRIVILEGE and db_privilege))
        and message.text.strip() == config.PRIVILEGE_CODE
    ):
        db[message.chat.id] = asn
        db_privilege.add(message.chat.id)
        data_dir = "./data"
        os.makedirs(data_dir, exist_ok=True)
        with open(os.path.join(data_dir, "user_db.pkl"), "wb") as f:
            pickle.dump((db, db_privilege), f)
        bot.send_message(
            message.chat.id,
            (
                "*[Privilege]*\n"
                f"Welcome! `{tools.get_asn_mnt_text(asn)}`\n"
                f"欢迎你！`{tools.get_asn_mnt_text(asn)}`"
            ),
            parse_mode="Markdown",
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    
    # 获取认证方式
    auths = get_auth(asn)
    
    if not auths:
        bot.send_message(
            message.chat.id,
            (
                "No authentication method found in the registry.\n"
                "在 Registry 中未找到认证方式。\n"
                "\n"
                "Please use email verification instead. You can use /login to try again.\n"
                "请改用邮箱验证。你可以使用 /login 重试。"
            ),
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    
    # 解析认证方式，查找 GPG 指纹和 SSH 密钥
    gpg_fingerprints = []
    ssh_keys = []
    
    for auth in auths:
        auth_upper = auth.upper()
        if auth_upper.startswith("PGPKEY-"):
            # GPG 格式1: pgpkey-<fingerprint>
            fingerprint = auth[7:]  # 去掉 "pgpkey-" 前缀
            gpg_fingerprints.append(fingerprint)
        elif auth_upper.startswith("PGP-FINGERPRINT "):
            # GPG 格式2: pgp-fingerprint <fingerprint>
            fingerprint = auth[16:]  # 去掉 "pgp-fingerprint " 前缀
            gpg_fingerprints.append(fingerprint)
        elif auth_upper.startswith("SSH-"):
            # SSH 格式: ssh-<algo> <key>
            ssh_keys.append(auth)
    
    if not gpg_fingerprints and not ssh_keys:
        bot.send_message(
            message.chat.id,
            (
                "No GPG or SSH authentication found in the registry.\n"
                "在 Registry 中未找到 GPG 或 SSH 认证方式。\n"
                "\n"
                "Please use email verification instead. You can use /login to try again.\n"
                "请改用邮箱验证。你可以使用 /login 重试。"
            ),
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    
    # 如果同时有 GPG 和 SSH，让用户选择
    if gpg_fingerprints and ssh_keys:
        markup = ReplyKeyboardMarkup(resize_keyboard=True)
        markup.row_width = 1
        markup.add(
            KeyboardButton("🔐 GPG Signature GPG 签名"),
            KeyboardButton("🔑 SSH Signature SSH 签名")
        )
        msg = bot.send_message(
            message.chat.id,
            (
                "Multiple authentication methods found. Please choose one.\n"
                "发现多种认证方式，请选择一种。\n"
                "\n"
                "Use /cancel to interrupt the operation.\n"
                "使用 /cancel 终止操作。"
            ),
            reply_markup=markup,
        )
        bot.register_next_step_handler(msg, partial(login_choose_signature_type, asn, gpg_fingerprints, ssh_keys))
    elif gpg_fingerprints:
        # 只有 GPG
        login_start_gpg_challenge(asn, gpg_fingerprints, message)
    else:
        # 只有 SSH
        login_start_ssh_challenge(asn, ssh_keys, message)


def login_choose_signature_type(asn, gpg_fingerprints, ssh_keys, message):
    """选择签名类型（GPG 或 SSH）"""
    if message.text.strip() == "/cancel":
        bot.send_message(
            message.chat.id,
            "Current operation has been cancelled.\n当前操作已被取消。",
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    
    choice = message.text.strip()
    
    if "GPG" in choice:
        login_start_gpg_challenge(asn, gpg_fingerprints, message)
    elif "SSH" in choice:
        login_start_ssh_challenge(asn, ssh_keys, message)
    else:
        markup = ReplyKeyboardMarkup(resize_keyboard=True)
        markup.row_width = 1
        markup.add(
            KeyboardButton("🔐 GPG Signature GPG 签名"),
            KeyboardButton("🔑 SSH Signature SSH 签名")
        )
        msg = bot.send_message(
            message.chat.id,
            (
                "Invalid choice. Please select GPG or SSH. Use /cancel to interrupt.\n"
                "无效的选择。请选择 GPG 或 SSH。使用 /cancel 终止操作。"
            ),
            reply_markup=markup,
        )
        bot.register_next_step_handler(msg, partial(login_choose_signature_type, asn, gpg_fingerprints, ssh_keys))


def login_start_gpg_challenge(asn, gpg_fingerprints, message):
    """开始 GPG 签名挑战"""
    # 如果有多个 GPG 指纹，让用户选择
    if len(gpg_fingerprints) > 1:
        markup = ReplyKeyboardMarkup(resize_keyboard=True)
        markup.row_width = 1
        for fp in gpg_fingerprints:
            # 显示指纹的前8位和后8位，方便识别
            display_fp = f"{fp[:8]}...{fp[-8:]}" if len(fp) > 16 else fp
            markup.add(KeyboardButton(f"🔐 {display_fp}"))
        
        fingerprint_list = "\n".join([f"- `{fp}`" for fp in gpg_fingerprints])
        msg = bot.send_message(
            message.chat.id,
            (
                "Multiple GPG keys found. Please choose one.\n"
                "发现多个 GPG 密钥，请选择一个。\n"
                "\n"
                f"Available fingerprints / 可用指纹：\n"
                f"{fingerprint_list}\n"
                "\n"
                "Use /cancel to interrupt the operation.\n"
                "使用 /cancel 终止操作。"
            ),
            parse_mode="Markdown",
            reply_markup=markup,
        )
        bot.register_next_step_handler(msg, partial(login_choose_gpg_key, asn, gpg_fingerprints))
    else:
        # 只有一个指纹，直接开始挑战
        login_do_gpg_challenge(asn, gpg_fingerprints[0], message)


def login_choose_gpg_key(asn, gpg_fingerprints, message):
    """选择 GPG 密钥"""
    if message.text.strip() == "/cancel":
        bot.send_message(
            message.chat.id,
            "Current operation has been cancelled.\n当前操作已被取消。",
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    
    choice = message.text.strip()
    
    # 从选择中提取指纹
    selected_fp = None
    for fp in gpg_fingerprints:
        display_fp = f"{fp[:8]}...{fp[-8:]}" if len(fp) > 16 else fp
        if display_fp in choice or fp in choice:
            selected_fp = fp
            break
    
    if selected_fp:
        login_do_gpg_challenge(asn, selected_fp, message)
    else:
        markup = ReplyKeyboardMarkup(resize_keyboard=True)
        markup.row_width = 1
        for fp in gpg_fingerprints:
            display_fp = f"{fp[:8]}...{fp[-8:]}" if len(fp) > 16 else fp
            markup.add(KeyboardButton(f"🔐 {display_fp}"))
        
        msg = bot.send_message(
            message.chat.id,
            (
                "Invalid choice. Please select a GPG key. Use /cancel to interrupt.\n"
                "无效的选择。请选择一个 GPG 密钥。使用 /cancel 终止操作。"
            ),
            reply_markup=markup,
        )
        bot.register_next_step_handler(msg, partial(login_choose_gpg_key, asn, gpg_fingerprints))


def login_do_gpg_challenge(asn, gpg_fingerprint, message):
    """执行 GPG 签名挑战"""
    challenge = tools.gen_random_code(32)
    
    msg = bot.send_message(
        message.chat.id,
        (
            "🔐 GPG Signature Challenge\n"
            "🔐 GPG 签名挑战\n"
            "\n"
            f"Selected GPG Fingerprint / 选择的 GPG 指纹：\n"
            f"- `{gpg_fingerprint}`\n"
            "\n"
            f"Challenge String / 挑战字符串:\n"
            f"`{challenge}`\n"
            "\n"
            "Please sign the challenge string with your GPG private key and send the signature.\n"
            "请使用你的 GPG 私钥对挑战字符串进行签名，并发送签名结果。\n"
            "\n"
            "Command / 命令:\n"
            f"`echo -n '{challenge}' | gpg --clearsign`\n"
            "\n"
            "Send the complete signed message (including headers). Use /cancel to interrupt.\n"
            "发送完整的签名消息（包括头部）。使用 /cancel 终止操作。"
        ),
        parse_mode="Markdown",
        reply_markup=ReplyKeyboardRemove(),
    )
    # 只用选择的指纹进行验证
    bot.register_next_step_handler(msg, partial(login_signature_verify_gpg, asn, challenge, [gpg_fingerprint]))


def login_start_ssh_challenge(asn, ssh_keys, message):
    """开始 SSH 签名挑战"""
    # 如果有多个 SSH 密钥，让用户选择
    if len(ssh_keys) > 1:
        markup = ReplyKeyboardMarkup(resize_keyboard=True)
        markup.row_width = 1
        for i, key in enumerate(ssh_keys):
            # 提取密钥类型和部分指纹
            parts = key.split()
            key_type = parts[0] if parts else "ssh"
            # 显示密钥类型和公钥的前20个字符
            key_preview = parts[1][:20] + "..." if len(parts) > 1 and len(parts[1]) > 20 else (parts[1] if len(parts) > 1 else "")
            markup.add(KeyboardButton(f"🔑 {i+1}. {key_type} {key_preview}"))
        
        ssh_key_list = "\n".join([f"{i+1}. `{key[:60]}...`" if len(key) > 60 else f"{i+1}. `{key}`" for i, key in enumerate(ssh_keys)])
        msg = bot.send_message(
            message.chat.id,
            (
                "Multiple SSH keys found. Please choose one.\n"
                "发现多个 SSH 密钥，请选择一个。\n"
                "\n"
                f"Available keys / 可用密钥：\n"
                f"{ssh_key_list}\n"
                "\n"
                "Use /cancel to interrupt the operation.\n"
                "使用 /cancel 终止操作。"
            ),
            parse_mode="Markdown",
            reply_markup=markup,
        )
        bot.register_next_step_handler(msg, partial(login_choose_ssh_key, asn, ssh_keys))
    else:
        # 只有一个密钥，直接开始挑战
        login_do_ssh_challenge(asn, ssh_keys[0], message)


def login_choose_ssh_key(asn, ssh_keys, message):
    """选择 SSH 密钥"""
    if message.text.strip() == "/cancel":
        bot.send_message(
            message.chat.id,
            "Current operation has been cancelled.\n当前操作已被取消。",
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    
    choice = message.text.strip()
    
    # 从选择中提取序号
    selected_key = None
    for i, key in enumerate(ssh_keys):
        if f"{i+1}." in choice or f"{i+1}. " in choice:
            selected_key = key
            break
        # 也检查密钥内容匹配
        parts = key.split()
        if len(parts) > 1 and parts[1][:20] in choice:
            selected_key = key
            break
    
    if selected_key:
        login_do_ssh_challenge(asn, selected_key, message)
    else:
        markup = ReplyKeyboardMarkup(resize_keyboard=True)
        markup.row_width = 1
        for i, key in enumerate(ssh_keys):
            parts = key.split()
            key_type = parts[0] if parts else "ssh"
            key_preview = parts[1][:20] + "..." if len(parts) > 1 and len(parts[1]) > 20 else (parts[1] if len(parts) > 1 else "")
            markup.add(KeyboardButton(f"🔑 {i+1}. {key_type} {key_preview}"))
        
        msg = bot.send_message(
            message.chat.id,
            (
                "Invalid choice. Please select an SSH key. Use /cancel to interrupt.\n"
                "无效的选择。请选择一个 SSH 密钥。使用 /cancel 终止操作。"
            ),
            reply_markup=markup,
        )
        bot.register_next_step_handler(msg, partial(login_choose_ssh_key, asn, ssh_keys))


def login_do_ssh_challenge(asn, ssh_key, message):
    """执行 SSH 签名挑战"""
    challenge = tools.gen_random_code(32)
    
    # 格式化显示密钥
    ssh_key_display = f"`{ssh_key[:60]}...`" if len(ssh_key) > 60 else f"`{ssh_key}`"
    
    msg = bot.send_message(
        message.chat.id,
        (
            "🔑 SSH Signature Challenge\n"
            "🔑 SSH 签名挑战\n"
            "\n"
            f"Selected SSH Public Key / 选择的 SSH 公钥：\n"
            f"- {ssh_key_display}\n"
            "\n"
            f"Challenge String / 挑战字符串:\n"
            f"`{challenge}`\n"
            "\n"
            "Please sign the challenge string with your SSH private key and send the signature.\n"
            "请使用你的 SSH 私钥对挑战字符串进行签名，并发送签名结果。\n"
            "\n"
            "Command / 命令:\n"
            f"`echo -n '{challenge}' | ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n file`\n"
            "\n"
            "Send the output signature. Use /cancel to interrupt.\n"
            "发送输出的签名内容。使用 /cancel 终止操作。"
        ),
        parse_mode="Markdown",
        reply_markup=ReplyKeyboardRemove(),
    )
    # 只用选择的密钥进行验证
    bot.register_next_step_handler(msg, partial(login_signature_verify_ssh, asn, challenge, [ssh_key]))


def login_signature_verify_gpg(asn, challenge, gpg_fingerprints, message):
    """验证 GPG 签名
    
    Args:
        asn: AS号
        challenge: 挑战字符串
        gpg_fingerprints: GPG 指纹列表
        message: 消息对象（包含用户发送的签名）
    """
    if message.text.strip() == "/cancel":
        bot.send_message(
            message.chat.id,
            "Current operation has been cancelled.\n当前操作已被取消。",
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    
    signed_message = message.text.strip()
    
    # 验证签名
    try:
        # 将签名消息写入临时文件
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.asc', delete=False) as f:
            f.write(signed_message)
            temp_file = f.name
        
        try:
            # 使用 gpg --verify 验证签名
            result = subprocess.run(
                ['gpg', '--verify', temp_file],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # 检查验证结果
            stderr = result.stderr
            
            # 从输出中提取指纹
            signature_fingerprint = None
            for line in stderr.split('\n'):
                if 'Primary key fingerprint:' in line or 'fingerprint:' in line.lower():
                    # 提取指纹（移除空格和冒号）
                    parts = line.split(':')
                    if len(parts) > 1:
                        signature_fingerprint = parts[-1].strip().replace(' ', '').upper()
                        break
                # GPG 输出中也可能是 "gpg: Good signature from"
                if 'using' in line.lower() and 'key' in line.lower():
                    # 尝试提取十六进制指纹
                    words = line.split()
                    for word in words:
                        if len(word) >= 16 and all(c in '0123456789ABCDEFabcdef' for c in word):
                            signature_fingerprint = word.upper()
                            break
            
            # 验证签名的指纹是否在注册的指纹列表中
            fingerprints_upper = [fp.replace(' ', '').upper() for fp in gpg_fingerprints]
            
            if signature_fingerprint and any(sig_fp in fp or fp in sig_fp for sig_fp in [signature_fingerprint] for fp in fingerprints_upper):
                # 验证挑战字符串
                # 使用 gpg --decrypt 获取原文
                decrypt_result = subprocess.run(
                    ['gpg', '--decrypt', temp_file],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                decrypted_text = decrypt_result.stdout.strip()
                
                if challenge in decrypted_text:
                    # 签名验证成功，执行登录
                    db[message.chat.id] = asn
                    data_dir = "./data"
                    os.makedirs(data_dir, exist_ok=True)
                    with open(os.path.join(data_dir, "user_db.pkl"), "wb") as f:
                        pickle.dump((db, db_privilege), f)
                    
                    bot.send_message(
                        message.chat.id,
                        (
                            f"✅ Signature verified successfully!\n"
                            f"✅ 签名验证成功！\n"
                            "\n"
                            f"Welcome! `{tools.get_asn_mnt_text(asn)}`\n"
                            f"欢迎你！`{tools.get_asn_mnt_text(asn)}`"
                        ),
                        parse_mode="Markdown",
                        reply_markup=ReplyKeyboardRemove(),
                    )
                else:
                    raise ValueError("Challenge string mismatch")
            else:
                raise ValueError("Fingerprint not matched")
                
        finally:
            # 清理临时文件
            os.unlink(temp_file)
            
    except Exception as e:
        bot.send_message(
            message.chat.id,
            (
                "❌ Signature verification failed!\n"
                "❌ 签名验证失败！\n"
                "\n"
                f"Error: {str(e)}\n"
                f"错误: {str(e)}\n"
                "\n"
                "Please try to avoid signing in Windows command line, which may cause line ending issues.\n"
                "请尽量不要在 Windows 命令行中进行签名，这可能会导致换行符问题。\n"
                "\n"
                "You can use /login to retry.\n"
                "你可以使用 /login 重试。"
            ),
            reply_markup=ReplyKeyboardRemove(),
        )


def login_signature_verify_ssh(asn, challenge, ssh_keys, message):
    """验证 SSH 签名
    
    Args:
        asn: AS号
        challenge: 挑战字符串
        ssh_keys: SSH 公钥列表
        message: 消息对象（包含用户发送的签名）
    """
    if message.text.strip() == "/cancel":
        bot.send_message(
            message.chat.id,
            "Current operation has been cancelled.\n当前操作已被取消。",
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    
    signature = message.text.strip()
    
    # 验证签名
    try:
        import tempfile
        
        # 创建临时目录
        temp_dir = tempfile.mkdtemp()
        challenge_file = os.path.join(temp_dir, "challenge.txt")
        signature_file = os.path.join(temp_dir, "challenge.txt.sig")
        allowed_signers_file = os.path.join(temp_dir, "allowed_signers")
        
        try:
            # 写入挑战字符串（不带换行符，命令使用 echo -n）
            with open(challenge_file, 'w') as f:
                f.write(challenge)
            
            # 写入签名
            with open(signature_file, 'w') as f:
                f.write(signature)
            
            # 尝试每个 SSH 公钥进行验证
            verified = False
            for ssh_key in ssh_keys:
                # 创建 allowed_signers 文件
                # 格式: principal key-type key-data
                with open(allowed_signers_file, 'w') as f:
                    f.write(f"user@dn42 {ssh_key}\n")
                
                # 使用 ssh-keygen -Y verify 验证签名
                try:
                    result = subprocess.run(
                        [
                            'ssh-keygen', '-Y', 'verify',
                            '-f', allowed_signers_file,
                            '-I', 'user@dn42',
                            '-n', 'file',
                            '-s', signature_file
                        ],
                        stdin=open(challenge_file, 'r'),
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    # 检查返回码和输出（Good 可能在 stdout 或 stderr）
                    if result.returncode == 0 and ('Good' in result.stdout or 'Good' in result.stderr):
                        verified = True
                        break
                except Exception:
                    continue
            
            if verified:
                # 签名验证成功，执行登录
                db[message.chat.id] = asn
                data_dir = "./data"
                os.makedirs(data_dir, exist_ok=True)
                with open(os.path.join(data_dir, "user_db.pkl"), "wb") as f:
                    pickle.dump((db, db_privilege), f)
                
                bot.send_message(
                    message.chat.id,
                    (
                        f"✅ Signature verified successfully!\n"
                        f"✅ 签名验证成功！\n"
                        "\n"
                        f"Welcome! `{tools.get_asn_mnt_text(asn)}`\n"
                        f"欢迎你！`{tools.get_asn_mnt_text(asn)}`"
                    ),
                    parse_mode="Markdown",
                    reply_markup=ReplyKeyboardRemove(),
                )
            else:
                raise ValueError("SSH signature verification failed")
                
        finally:
            # 清理临时文件
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
            
    except Exception as e:
        bot.send_message(
            message.chat.id,
            (
                "❌ Signature verification failed!\n"
                "❌ 签名验证失败！\n"
                "\n"
                f"Error: {str(e)}\n"
                f"错误: {str(e)}\n"
                "\n"
                "Please try to avoid signing in Windows command line, which may cause line ending issues.\n"
                "请尽量不要在 Windows 命令行中进行签名，这可能会导致换行符问题。\n"
                "\n"
                "You can use /login to retry.\n"
                "你可以使用 /login 重试。"
            ),
            reply_markup=ReplyKeyboardRemove(),
        )


def login_choose_email(asn, emails, last_msg_id, message):
    if message.text.strip() == "/cancel":
        bot.send_message(
            message.chat.id,
            "Current operation has been cancelled.\n当前操作已被取消。",
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    if (
        config.PRIVILEGE_CODE
        and (not (config.SINGLE_PRIVILEGE and db_privilege))
        and message.text.strip() == config.PRIVILEGE_CODE
    ):
        db[message.chat.id] = asn
        db_privilege.add(message.chat.id)
        data_dir = "./data"
        os.makedirs(data_dir, exist_ok=True)
        with open(os.path.join(data_dir, "user_db.pkl"), "wb") as f:
            pickle.dump((db, db_privilege), f)
        bot.delete_message(message.chat.id, message.message_id)
        bot.delete_message(message.chat.id, last_msg_id)
        bot.send_message(
            message.chat.id,
            (
                "*[Privilege]*\n"
                f"Welcome! `{tools.get_asn_mnt_text(asn)}`\n"
                f"欢迎你！`{tools.get_asn_mnt_text(asn)}`"
            ),
            parse_mode="Markdown",
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    if message.text.strip() not in emails:
        bot.send_message(
            message.chat.id,
            (
                "Sorry. For now, you can only use the email address you registered in the DN42 Registry to authenticate.\n"
                "抱歉。暂时只能使用您在 DN42 Registry 中登记的邮箱完成验证。\n"
                f"Please contact {config.CONTACT} for manual handling.\n"
                f"请联系 {config.CONTACT} 人工处理。"
            ),
            parse_mode="Markdown",
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    msg = bot.send_message(
        message.chat.id,
        (
            "Sending verification code...\n"
            "正在发送验证码...\n"
            "\n"
            "Hold on, this may take up to 2 minutes to send successfully.\n"
            "稍安勿躁，最多可能需要 2 分钟才能成功发送。"
        ),
        reply_markup=ReplyKeyboardRemove(),
    )
    bot.send_chat_action(chat_id=message.chat.id, action="typing")
    code = tools.gen_random_code(16)
    try:
        config.send_email(asn, tools.get_whoisinfo_by_asn(asn), code, message.text.strip())
    except RuntimeError:
        bot.delete_message(message.chat.id, msg.message_id)
        bot.send_message(
            message.chat.id,
            (
                "Sorry, we are unable to send the verification code to your email address at this time. Please try again later.\n"
                "抱歉，暂时无法发送验证码至您的邮箱。请稍后再试。\n"
                f"Please contact {config.CONTACT} if it keeps failing.\n"
                f"如果一直发送失败请联系 {config.CONTACT} 处理。"
            ),
            parse_mode="Markdown",
            reply_markup=ReplyKeyboardRemove(),
        )
    else:
        bot.delete_message(message.chat.id, msg.message_id)
        msg = bot.send_message(
            message.chat.id,
            (
                "Verification code has been sent to your email.\n"
                "验证码已发送至您的邮箱。\n"
                f"Please contact {config.CONTACT} if you can not receive it.\n"
                f"如果无法收到请联系 {config.CONTACT}\n"
                "\n"
                "Enter your verification code:\n"
                "请输入验证码："
            ),
            parse_mode="Markdown",
            reply_markup=ReplyKeyboardRemove(),
        )
        bot.register_next_step_handler(msg, partial(login_verify_code, asn, code))


def login_verify_code(asn, code, message):
    if message.text.strip() == "/cancel":
        bot.send_message(
            message.chat.id,
            "Current operation has been cancelled.\n当前操作已被取消。",
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    if message.text.strip().lower() == code.lower():
        db[message.chat.id] = asn
        data_dir = "./data"
        os.makedirs(data_dir, exist_ok=True)
        with open(os.path.join(data_dir, "user_db.pkl"), "wb") as f:
            pickle.dump((db, db_privilege), f)
        bot.send_message(
            message.chat.id,
            (f"Welcome! `{tools.get_asn_mnt_text(asn)}`\n" f"欢迎你！`{tools.get_asn_mnt_text(asn)}`"),
            parse_mode="Markdown",
            reply_markup=ReplyKeyboardRemove(),
        )
    else:
        bot.send_message(
            message.chat.id,
            ("Verification code error!\n" "验证码错误！\n" "You can use /login to retry.\n" "你可以使用 /login 重试。"),
            reply_markup=ReplyKeyboardRemove(),
        )
