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
    try:
        # Try to get from local registry first
        admin_c = None
        whois1_text = registry.get_whois_info_from_registry(str(asn))
        
        if whois1_text:
            whois1 = whois1_text.splitlines()
        else:
            # Fallback to whois command
            whois1 = (
                subprocess.check_output(shlex.split(f"whois -h {config.WHOIS_ADDRESS} {asn}"), timeout=3)
                .decode("utf-8")
                .splitlines()[3:]
            )
        
        for line in whois1:
            if line.startswith("admin-c:"):
                admin_c = line.split(":")[1].strip()
                break
        
        # Return early if no admin-c found
        if not admin_c:
            return set()
        
        # Try to get admin-c info from local registry
        whois2_text = registry.get_whois_info_from_registry(admin_c)
        
        if whois2_text:
            whois2 = whois2_text.splitlines()
        else:
            # Fallback to whois command
            whois2 = (
                subprocess.check_output(shlex.split(f"whois -h {config.WHOIS_ADDRESS} {admin_c}"), timeout=3)
                .decode("utf-8")
                .splitlines()[3:]
            )
        
        emails = set()
        for line in whois2:
            if line.startswith("e-mail:"):
                email = line.split(":")[1].strip()
                if re.fullmatch(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", email):
                    emails.add(email)
        for line in whois2:
            if line.startswith("contact:"):
                email = line.split(":")[1].strip()
                if re.fullmatch(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", email):
                    emails.add(email)
        return emails
    except BaseException:
        return set()


def get_auth(asn):
    try:
        whois_text = registry.get_whois_info_from_registry(str(asn))
        
        if whois_text:
            whois = whois_text.splitlines()
        else:
            whois = (
                subprocess.check_output(shlex.split(f"whois -h {config.WHOIS_ADDRESS} {asn}"), timeout=3)
                .decode("utf-8")
                .splitlines()[3:]
            )
        
        auths = set()
        for line in whois:
            if line.startswith("auth:"):
                auth = line.split(":")[1].strip()
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
    
    # 解析认证方式，查找 GPG 指纹
    gpg_fingerprints = []
    ssh_keys = []
    
    for auth in auths:
        auth_upper = auth.upper()
        if auth_upper.startswith("PGPKEY-"):
            # GPG 格式: pgpkey-<fingerprint>
            fingerprint = auth[7:]  # 去掉 "pgpkey-" 前缀
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
    
    # 优先使用 GPG
    if gpg_fingerprints:
        # 生成挑战字符串
        challenge = tools.gen_random_code(32)
        
        fingerprint_list = "\n".join([f"- `{fp}`" for fp in gpg_fingerprints])
        
        msg = bot.send_message(
            message.chat.id,
            (
                "🔐 GPG Signature Challenge\n"
                "🔐 GPG 签名挑战\n"
                "\n"
                f"Registry GPG Fingerprints:\n"
                f"Registry 中的 GPG 指纹：\n"
                f"{fingerprint_list}\n"
                "\n"
                f"Challenge String / 挑战字符串:\n"
                f"`{challenge}`\n"
                "\n"
                "Please sign the challenge string with your GPG private key and send the signature.\n"
                "请使用你的 GPG 私钥对挑战字符串进行签名，并发送签名结果。\n"
                "\n"
                "Command / 命令:\n"
                f"`echo '{challenge}' | gpg --clearsign`\n"
                "\n"
                "Send the complete signed message (including headers). Use /cancel to interrupt.\n"
                "发送完整的签名消息（包括头部）。使用 /cancel 终止操作。"
            ),
            parse_mode="Markdown",
            reply_markup=ReplyKeyboardRemove(),
        )
        bot.register_next_step_handler(msg, partial(login_signature_verify_gpg, asn, challenge, gpg_fingerprints))
    else:
        # SSH 签名挑战
        challenge = tools.gen_random_code(32)
        
        # 格式化 SSH 公钥列表
        ssh_key_list = "\n".join([f"- `{key[:50]}...`" if len(key) > 50 else f"- `{key}`" for key in ssh_keys])
        
        msg = bot.send_message(
            message.chat.id,
            (
                "🔑 SSH Signature Challenge\n"
                "🔑 SSH 签名挑战\n"
                "\n"
                f"Registry SSH Public Keys:\n"
                f"Registry 中的 SSH 公钥：\n"
                f"{ssh_key_list}\n"
                "\n"
                f"Challenge String / 挑战字符串:\n"
                f"`{challenge}`\n"
                "\n"
                "Please sign the challenge string with your SSH private key and send the signature.\n"
                "请使用你的 SSH 私钥对挑战字符串进行签名，并发送签名结果。\n"
                "\n"
                "Commands / 命令:\n"
                f"`echo '{challenge}' > challenge.txt`\n"
                f"`ssh-keygen -Y sign -f ~/.ssh/id_rsa -n file challenge.txt`\n"
                "\n"
                "Send the content of challenge.txt.sig file. Use /cancel to interrupt.\n"
                "发送 challenge.txt.sig 文件的内容。使用 /cancel 终止操作。"
            ),
            parse_mode="Markdown",
            reply_markup=ReplyKeyboardRemove(),
        )
        bot.register_next_step_handler(msg, partial(login_signature_verify_ssh, asn, challenge, ssh_keys))


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
            # 写入挑战字符串
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
                    
                    # 检查返回码和输出
                    if result.returncode == 0 and 'Good' in result.stderr:
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
