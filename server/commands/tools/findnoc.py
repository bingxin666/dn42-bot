import re
import shlex
import subprocess

import config
import tools
from base import bot
from tools import registry


def get_asn_name(asn):
    """
    获取 ASN 的名称 (as-name 字段)
    
    Args:
        asn: AS号
        
    Returns:
        str: ASN 名称，如果未找到则返回 None
    """
    try:
        # 从本地 registry 获取
        whois_text = registry.get_whois_info_from_registry(str(asn))
        
        if whois_text:
            for line in whois_text.splitlines():
                if line.startswith("as-name:"):
                    return line.split(":", 1)[1].strip()
        
        return None
    except BaseException:
        return None


def get_noc_emails(asn):
    """
    获取 ASN 关联的所有 email 地址
    
    支持递归查找：如果 admin-c/tech-c 指向 role/organisation，会继续查找其 admin-c/tech-c
    同时支持 e-mail、abuse-mailbox、contact 等字段
    
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
        
        # 继续查找子 contact 的 email（即使当前有 email 也继续查找）
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
                shlex.split(f"whois -h {config.WHOIS_ADDRESS} AS{asn}"),
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


@bot.message_handler(commands=["findnoc"])
def findnoc(message):
    """处理 /findnoc 命令，查找 ASN 的 NOC 信息"""
    if len(message.text.split()) < 2:
        bot.reply_to(
            message,
            "Usage: /findnoc [ASN]\n用法：/findnoc [ASN]",
            reply_markup=tools.gen_peer_me_markup(message),
        )
        return
    
    raw_asn = message.text.split()[1]
    
    # 提取并标准化 ASN
    asn = tools.extract_asn(raw_asn)
    
    if not asn:
        bot.reply_to(
            message,
            "Invalid ASN or ASN not found in DN42 registry.\nASN 无效或在 DN42 注册表中未找到。",
            reply_markup=tools.gen_peer_me_markup(message),
        )
        return
    
    # 获取 ASN 名称
    asn_name = get_asn_name(asn)
    if not asn_name:
        asn_name = "Unknown"
    
    # 获取 email 列表
    emails = get_noc_emails(asn)
    
    if emails:
        email_text = "\n".join(f"Email: {email}" for email in sorted(emails))
    else:
        email_text = "Email: Not found / 未找到"
    
    result = (
        f"ASN: AS{asn}\n"
        f"ASN Name: {asn_name}\n"
        f"{email_text}"
    )
    
    bot.reply_to(
        message,
        result,
        reply_markup=tools.gen_peer_me_markup(message),
    )
