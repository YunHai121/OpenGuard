"""Curated 45+ secret detection rules with deterministic structural validators."""

from __future__ import annotations

import base64
import json
import re
import zlib
from dataclasses import dataclass
from typing import Callable, List, Optional, Pattern

from openguard.models import Severity

_BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


@dataclass(frozen=True)
class SecretRule:
    """Definition of a single secret / credential / PII detection rule."""

    rule_id: str
    name: str
    pattern: Pattern[str]
    severity: Severity
    category_tag: str
    min_entropy: float = 0.0
    requires_secret_context: bool = False
    validator: Optional[Callable[[str], bool]] = None
    checksum_verifier: Optional[Callable[[str], bool]] = None
    remediation: str = "撤销泄露凭据并通过环境变量或密钥管理服务注入。"
    cwe_id: str = "CWE-798"
    extract_group: int = 0


def _to_base62(num: int, width: int = 6) -> str:
    if num == 0:
        return "0" * width
    chars: List[str] = []
    n = num
    while n > 0:
        n, rem = divmod(n, 62)
        chars.append(_BASE62_ALPHABET[rem])
    return "".join(reversed(chars)).rjust(width, "0")


def validate_github_token_crc32(token: str) -> bool:
    """Offline CRC32 Base62 checksum validator for GitHub (ghp/gho/ghu/ghs/ghr) and npm (npm_) tokens.

    Inspired by GitHub Secret Scanning & GitGuardian offline cryptographic verification:
    Format is `<prefix>_<30-char-body><6-char-base62-crc32>`.
    """
    s = token.strip()
    if "_" not in s:
        return False
    _, payload = s.split("_", 1)
    if len(payload) != 36:
        return False
    body, expected_b62 = payload[:30], payload[30:]
    crc = zlib.crc32(body.encode("ascii", errors="ignore")) & 0xFFFFFFFF
    return _to_base62(crc, width=6) == expected_b62


def validate_jwt(token: str) -> bool:
    """Validate that a JWT string decodes cleanly into JSON header & payload."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return False
    try:
        header_b64 = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
        payload_b64 = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64).decode("utf-8"))
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
        return isinstance(header, dict) and isinstance(payload, dict) and ("alg" in header or "typ" in header)
    except Exception:
        return False


def validate_chinese_id(id_str: str) -> bool:
    """Validate Chinese 18-digit Resident ID card using ISO 7064 MOD 11-2 checksum."""
    s = id_str.strip().upper()
    if not re.fullmatch(r"[1-8]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9X]", s):
        return False
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check_codes = "10X98765432"
    total = sum(int(s[i]) * weights[i] for i in range(17))
    return check_codes[total % 11] == s[17]


def validate_luhn(digits_str: str) -> bool:
    """Validate payment/bank card number using the Luhn mod-10 checksum."""
    digits = [int(ch) for ch in digits_str if ch.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    # Reject trivial repeating digits
    if len(set(digits)) <= 2:
        return False
    checksum = 0
    parity = len(digits) % 2
    for idx, d in enumerate(digits):
        if idx % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def build_builtin_secret_rules() -> List[SecretRule]:
    """Return the complete built-in set of 46 high-signal secret detection rules."""
    return [
        # --- 1. Cloud Providers (9 rules) ---
        SecretRule(
            rule_id="OG-SEC-001",
            name="AWS Access Key ID",
            pattern=re.compile(r"\b((?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16})\b"),
            severity=Severity.CRITICAL,
            category_tag="cloud",
            min_entropy=2.8,
            remediation="立即在 AWS IAM 控制台禁用并轮换该 Access Key，改用 IAM Role 或环境变量注入。",
        ),
        SecretRule(
            rule_id="OG-SEC-002",
            name="AWS Secret Access Key",
            pattern=re.compile(
                r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*[\"']([A-Za-z0-9/+=]{40})[\"']"
            ),
            severity=Severity.CRITICAL,
            category_tag="cloud",
            min_entropy=4.0,
            extract_group=1,
            remediation="立即轮换 AWS Secret Key 并清除代码仓中的硬编码赋值。",
        ),
        SecretRule(
            rule_id="OG-SEC-003",
            name="Aliyun AccessKey ID",
            pattern=re.compile(r"\b(LTAI[A-Za-z0-9]{12,22})\b"),
            severity=Severity.CRITICAL,
            category_tag="cloud",
            min_entropy=3.0,
            remediation="立即登录阿里云 RAM 控制台禁用该 AccessKey 并重新生成，改用 STS 临时凭证。",
        ),
        SecretRule(
            rule_id="OG-SEC-004",
            name="Aliyun AccessKey Secret",
            pattern=re.compile(
                r"(?i)(?:aliyun_?(?:access_?)?secret|oss_?(?:access_?)?secret)\s*[:=]\s*[\"']([A-Za-z0-9]{24,36})[\"']"
            ),
            severity=Severity.CRITICAL,
            category_tag="cloud",
            min_entropy=3.4,
            extract_group=1,
            remediation="立即轮换阿里云 AccessKey Secret，禁止在代码中明文配置。",
        ),
        SecretRule(
            rule_id="OG-SEC-005",
            name="Tencent Cloud SecretId",
            pattern=re.compile(r"\b(AKID[A-Za-z0-9]{24,36})\b"),
            severity=Severity.CRITICAL,
            category_tag="cloud",
            min_entropy=3.2,
            remediation="在腾讯云 CAM 访问管理中禁用泄露的 SecretId 并改用环境变量。",
        ),
        SecretRule(
            rule_id="OG-SEC-006",
            name="Tencent Cloud SecretKey",
            pattern=re.compile(
                r"(?i)(?:tencent_?secret_?key|qcloud_?secret_?key|cos_?secret_?key)\s*[:=]\s*[\"']([A-Za-z0-9]{28,40})[\"']"
            ),
            severity=Severity.CRITICAL,
            category_tag="cloud",
            min_entropy=3.4,
            extract_group=1,
            remediation="立即在腾讯云 CAM 轮换 SecretKey。",
        ),
        SecretRule(
            rule_id="OG-SEC-007",
            name="Huawei Cloud AK/SK Assignment",
            pattern=re.compile(
                r"(?i)(?:huawei_?(?:ak|sk|access_key|secret_key)|obs_?(?:ak|sk))\s*[:=]\s*[\"']([A-Za-z0-9]{18,44})[\"']"
            ),
            severity=Severity.CRITICAL,
            category_tag="cloud",
            min_entropy=3.2,
            extract_group=1,
            remediation="登录华为云 IAM 撤销相关 AK/SK 并使用托管环境变量。",
        ),
        SecretRule(
            rule_id="OG-SEC-008",
            name="Google Cloud API Key",
            pattern=re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
            severity=Severity.HIGH,
            category_tag="cloud",
            min_entropy=3.5,
            remediation="在 GCP Console 撤销或限制该 API Key 的调用来源域名/IP。",
        ),
        SecretRule(
            rule_id="OG-SEC-009",
            name="Azure Storage Connection String",
            pattern=re.compile(
                r"(DefaultEndpointsProtocol=https?;AccountName=[^;\s\"']+?;AccountKey=[A-Za-z0-9+/=]{32,})"
            ),
            severity=Severity.CRITICAL,
            category_tag="cloud",
            min_entropy=3.8,
            extract_group=1,
            remediation="在 Azure Portal 轮换 Storage AccountKey 并使用 Key Vault。",
        ),
        # --- 2. AI & LLM API Keys (8 rules) ---
        SecretRule(
            rule_id="OG-SEC-010",
            name="OpenAI Project / Service Key",
            pattern=re.compile(r"\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9\-_]{24,})\b"),
            severity=Severity.CRITICAL,
            category_tag="ai",
            min_entropy=3.6,
            remediation="立即在 OpenAI Platform 撤销该 API Key，并通过 `OPENAI_API_KEY` 环境变量加载。",
        ),
        SecretRule(
            rule_id="OG-SEC-011",
            name="OpenAI / DeepSeek / DashScope Legacy Token",
            pattern=re.compile(r"\b(sk-[A-Za-z0-9]{32,64})\b"),
            severity=Severity.CRITICAL,
            category_tag="ai",
            min_entropy=3.5,
            remediation="立即吊销对应的模型平台 API Key，避免产生盗刷账单。",
        ),
        SecretRule(
            rule_id="OG-SEC-012",
            name="Anthropic Claude API Key",
            pattern=re.compile(r"\b(sk-ant-(?:api03-)?[A-Za-z0-9\-_]{28,})\b"),
            severity=Severity.CRITICAL,
            category_tag="ai",
            min_entropy=3.6,
            remediation="立即在 Anthropic Console 轮换该 API Key。",
        ),
        SecretRule(
            rule_id="OG-SEC-013",
            name="HuggingFace User Access Token",
            pattern=re.compile(r"\b(hf_[A-Za-z0-9]{30,42})\b"),
            severity=Severity.HIGH,
            category_tag="ai",
            min_entropy=3.4,
            remediation="立即在 HuggingFace Settings -> Access Tokens 吊销并重新生成。",
        ),
        SecretRule(
            rule_id="OG-SEC-014",
            name="Groq API Key",
            pattern=re.compile(r"\b(gsk_[A-Za-z0-9]{36,})\b"),
            severity=Severity.HIGH,
            category_tag="ai",
            min_entropy=3.6,
            remediation="立即在 Groq Console 删除泄露的 API Key。",
        ),
        SecretRule(
            rule_id="OG-SEC-015",
            name="Replicate API Token",
            pattern=re.compile(r"\b(r8_[A-Za-z0-9]{32,45})\b"),
            severity=Severity.HIGH,
            category_tag="ai",
            min_entropy=3.4,
            remediation="立即撤销 Replicate API Token 并使用环境变量读取。",
        ),
        SecretRule(
            rule_id="OG-SEC-016",
            name="ModelScope / DashScope / Zhipu / Qianfan Contextual Key",
            pattern=re.compile(
                r"(?i)(?:dashscope|deepseek|zhipu|glm|qianfan|ernie|moonshot|kimi|baichuan|minimax|gemini|siliconflow)"
                r"[A-Za-z0-9_]*?(?:api_?key|token|secret)\s*[:=]\s*[\"']([A-Za-z0-9.\-_]{20,90})[\"']"
            ),
            severity=Severity.CRITICAL,
            category_tag="ai",
            min_entropy=3.3,
            extract_group=1,
            remediation="立即重置对应大模型平台 API Key，并迁移至 `.env`（加入 `.gitignore`）。",
        ),
        SecretRule(
            rule_id="OG-SEC-017",
            name="GCP Service Account Private Key JSON Field",
            pattern=re.compile(r"\"private_key\"\s*:\s*\"(-----BEGIN PRIVATE KEY-----[^\"]{32,})\""),
            severity=Severity.CRITICAL,
            category_tag="ai",
            min_entropy=3.5,
            extract_group=1,
            remediation="立即删除服务账号 JSON 密钥文件并在控制台吊销对应私钥 ID。",
        ),
        # --- 3. SCM, Package Registry & Domestic IM Webhooks (13 rules) ---
        SecretRule(
            rule_id="OG-SEC-018",
            name="GitHub Personal Access Token (Classic)",
            pattern=re.compile(r"\b(ghp_[A-Za-z0-9]{36})\b"),
            severity=Severity.CRITICAL,
            category_tag="scm",
            min_entropy=3.6,
            checksum_verifier=validate_github_token_crc32,
            remediation="立即在 GitHub Developer Settings 中撤销该 PAT，并检查仓库异常活动。",
        ),
        SecretRule(
            rule_id="OG-SEC-019",
            name="GitHub Fine-Grained PAT",
            pattern=re.compile(r"\b(github_pat_[A-Za-z0-9_]{40,90})\b"),
            severity=Severity.CRITICAL,
            category_tag="scm",
            min_entropy=3.6,
            remediation="立即在 GitHub 撤销 Fine-Grained PAT 并使用 GitHub Actions Secrets。",
        ),
        SecretRule(
            rule_id="OG-SEC-020",
            name="GitHub OAuth / App / Refresh Token",
            pattern=re.compile(r"\b((?:gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b"),
            severity=Severity.CRITICAL,
            category_tag="scm",
            min_entropy=3.6,
            checksum_verifier=validate_github_token_crc32,
            remediation="立即轮换 GitHub OAuth / App Token。",
        ),
        SecretRule(
            rule_id="OG-SEC-021",
            name="GitLab Personal Access Token",
            pattern=re.compile(r"\b(glpat-[A-Za-z0-9\-_]{20,}(?:\.[A-Za-z0-9\-_]+)*)\b"),
            severity=Severity.CRITICAL,
            category_tag="scm",
            min_entropy=3.3,
            remediation="立即在 GitLab（如 git.hust.edu.cn）个人设置中撤销该 Access Token。",
        ),
        SecretRule(
            rule_id="OG-SEC-022",
            name="Gitee Access Token Assignment",
            pattern=re.compile(
                r"(?i)(?:gitee_?(?:access_?)?token|gitee_?private_?token)\s*[:=]\s*[\"']([a-f0-9A-Za-z]{28,64})[\"']"
            ),
            severity=Severity.CRITICAL,
            category_tag="scm",
            min_entropy=3.2,
            extract_group=1,
            remediation="立即在 Gitee 私人令牌页面删除并重建 Token。",
        ),
        SecretRule(
            rule_id="OG-SEC-023",
            name="PyPI Upload API Token",
            pattern=re.compile(r"\b(pypi-AgEI[A-Za-z0-9\-_]{32,})\b"),
            severity=Severity.CRITICAL,
            category_tag="scm",
            min_entropy=3.8,
            remediation="立即在 PyPI Account Settings 移除该上传 Token，改用 Trusted Publishing (OIDC)。",
        ),
        SecretRule(
            rule_id="OG-SEC-024",
            name="npm Registry Access Token",
            pattern=re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"),
            severity=Severity.CRITICAL,
            category_tag="scm",
            min_entropy=3.6,
            checksum_verifier=validate_github_token_crc32,
            remediation="立即在 npmjs.com 吊销该 Access Token。",
        ),
        SecretRule(
            rule_id="OG-SEC-025",
            name="Docker Hub Personal Access Token",
            pattern=re.compile(r"\b(dckr_pat_[A-Za-z0-9\-_]{24,})\b"),
            severity=Severity.HIGH,
            category_tag="scm",
            min_entropy=3.4,
            remediation="立即在 Docker Hub 撤销该 PAT。",
        ),
        SecretRule(
            rule_id="OG-SEC-026",
            name="Slack Bot / User Token",
            pattern=re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9A-Za-z\-]{18,})\b"),
            severity=Severity.HIGH,
            category_tag="webhook",
            min_entropy=3.4,
            remediation="在 Slack App 管理页面重新生成 Token。",
        ),
        SecretRule(
            rule_id="OG-SEC-027",
            name="Slack Incoming Webhook URL",
            pattern=re.compile(r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)"),
            severity=Severity.HIGH,
            category_tag="webhook",
            min_entropy=3.2,
            extract_group=1,
            remediation="轮换 Slack Incoming Webhook 地址避免群聊告警被恶意伪造。",
        ),
        SecretRule(
            rule_id="OG-SEC-028",
            name="Feishu (Lark) Custom Bot Webhook",
            pattern=re.compile(r"(https://open\.feishu\.cn/open-apis/bot/v2/hook/[0-9a-fA-F\-]{24,})"),
            severity=Severity.HIGH,
            category_tag="webhook",
            min_entropy=3.0,
            extract_group=1,
            remediation="立即在飞书群机器人设置中重置 Webhook 地址并启用签名校验。",
        ),
        SecretRule(
            rule_id="OG-SEC-029",
            name="DingTalk Robot Webhook with Access Token",
            pattern=re.compile(r"(https://oapi\.dingtalk\.com/robot/send\?access_token=[A-Za-z0-9]{32,})"),
            severity=Severity.HIGH,
            category_tag="webhook",
            min_entropy=3.3,
            extract_group=1,
            remediation="立即重置钉钉群机器人 Webhook 并开启加签安全设置。",
        ),
        SecretRule(
            rule_id="OG-SEC-030",
            name="WeCom (Enterprise WeChat) Bot Webhook",
            pattern=re.compile(r"(https://qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=[0-9a-fA-F\-]{24,})"),
            severity=Severity.HIGH,
            category_tag="webhook",
            min_entropy=3.0,
            extract_group=1,
            remediation="立即重新生成企业微信机器人 Webhook Key。",
        ),
        # --- 4. Private Keys, Certificates & Auth Headers (7 rules) ---
        SecretRule(
            rule_id="OG-SEC-031",
            name="RSA / EC / OpenSSH / PGP Private Key Block",
            pattern=re.compile(
                r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----)"
            ),
            severity=Severity.CRITICAL,
            category_tag="private_key",
            min_entropy=2.5,
            extract_group=1,
            remediation="立即从仓库及历史中彻底清除私钥并吊销对应公钥证书，重新生成密钥对。",
            cwe_id="CWE-321",
        ),
        SecretRule(
            rule_id="OG-SEC-032",
            name="JSON Web Token (JWT) Hardcoded Credential",
            pattern=re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"),
            severity=Severity.HIGH,
            category_tag="auth",
            min_entropy=3.8,
            validator=validate_jwt,
            remediation="避免在代码或测试用例中提交真实 JWT Token，改用运行时动态签发或 Mock 占位符。",
        ),
        SecretRule(
            rule_id="OG-SEC-033",
            name="Hardcoded HTTP Bearer Authorization Header",
            pattern=re.compile(r"(?i)[\"']Authorization[\"']\s*:\s*[\"']Bearer\s+([A-Za-z0-9\-_.~+/=]{20,})[\"']"),
            severity=Severity.HIGH,
            category_tag="auth",
            min_entropy=3.4,
            extract_group=1,
            remediation="将 Bearer Token 移出源码，改为从运行时安全配置读取。",
        ),
        SecretRule(
            rule_id="OG-SEC-034",
            name="Hardcoded HTTP Basic Authorization Header",
            pattern=re.compile(r"(?i)[\"']Authorization[\"']\s*:\s*[\"']Basic\s+([A-Za-z0-9+/=]{16,})[\"']"),
            severity=Severity.HIGH,
            category_tag="auth",
            min_entropy=3.2,
            extract_group=1,
            remediation="移除 Base64 编码的 Basic 认证凭据并轮换对应账号密码。",
        ),
        SecretRule(
            rule_id="OG-SEC-035",
            name="OAuth Client Secret Assignment",
            pattern=re.compile(
                r"(?i)(?:client_secret|oauth_secret|app_secret|webhook_secret)\s*[:=]\s*[\"']([A-Za-z0-9\-_.]{14,80})[\"']"
            ),
            severity=Severity.HIGH,
            category_tag="auth",
            min_entropy=3.1,
            extract_group=1,
            remediation="将 OAuth/App Secret 迁移至环境变量或 KMS 密钥托管服务。",
        ),
        SecretRule(
            rule_id="OG-SEC-036",
            name="JWT Signing Secret / Flask SECRET_KEY",
            pattern=re.compile(
                r"(?i)(?:jwt_?secret(?:_?key)?|secret_?key|session_?secret|signing_?key)\s*[:=]\s*[\"']([^\s\"']{10,80})[\"']"
            ),
            severity=Severity.HIGH,
            category_tag="auth",
            min_entropy=2.9,
            extract_group=1,
            remediation="绝不在代码仓库中硬编码签名密钥，改由 `os.getenv` 从部署环境读取。",
        ),
        SecretRule(
            rule_id="OG-SEC-037",
            name="Stripe / Payment Secret Key",
            pattern=re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{20,})\b"),
            severity=Severity.CRITICAL,
            category_tag="payment",
            min_entropy=3.5,
            remediation="立即在支付网关控制台滚动更新生产环境 Secret Key。",
        ),
        # --- 5. Databases, Infrastructure & Generic Passwords (5 rules) ---
        SecretRule(
            rule_id="OG-SEC-038",
            name="Database / Broker URI with Embedded Password",
            pattern=re.compile(
                r"\b((?:postgres(?:ql)?|mysql(?:\+\w+)?|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:\s\"']+:[^\s\"']{6,}@[A-Za-z0-9._\-]+(?::\d+)?[^\s\"']*)"
            ),
            severity=Severity.CRITICAL,
            category_tag="database",
            min_entropy=2.5,
            extract_group=1,
            remediation="立即修改数据库密码，连接串中的账号密码须通过环境变量拼接注入。",
        ),
        SecretRule(
            rule_id="OG-SEC-039",
            name="Hardcoded Password Assignment",
            pattern=re.compile(
                r"(?i)\b(?:db_?password|admin_?password|root_?password|smtp_?password|redis_?password|mysql_?password|user_?password|password|passwd|pwd)\s*[:=]\s*[\"']([^\s\"']{8,64})[\"']"
            ),
            severity=Severity.HIGH,
            category_tag="password",
            min_entropy=2.6,
            extract_group=1,
            remediation="移除明文密码字面量并轮换相关服务口令。",
        ),
        SecretRule(
            rule_id="OG-SEC-040",
            name="Generic High-Entropy API Key Assignment",
            pattern=re.compile(
                r"(?i)\b(?:api_?key|apikey|access_?token|auth_?token|private_?token|bearer_?token)\s*[:=]\s*[\"']([A-Za-z0-9\-_.+/=]{16,96})[\"']"
            ),
            severity=Severity.HIGH,
            category_tag="generic_secret",
            min_entropy=3.3,
            extract_group=1,
            remediation="避免硬编码通用 API Key / Token，统一通过 `.env` 或密钥管理中心注入。",
        ),
        SecretRule(
            rule_id="OG-SEC-041",
            name="Telegram Bot Token",
            pattern=re.compile(r"\b(\d{8,11}:AA[A-Za-z0-9_-]{30,36})\b"),
            severity=Severity.HIGH,
            category_tag="webhook",
            min_entropy=3.5,
            remediation="通过 @BotFather `/revoke` 命令重新生成 Telegram Bot Token。",
        ),
        SecretRule(
            rule_id="OG-SEC-042",
            name="SendGrid / Mailgun / Twilio API Credential",
            pattern=re.compile(r"\b(SG\.[A-Za-z0-9\-_]{16,32}\.[A-Za-z0-9\-_]{24,48})\b"),
            severity=Severity.HIGH,
            category_tag="cloud",
            min_entropy=3.7,
            remediation="立即在邮件服务后台撤销该 SendGrid API Key。",
        ),
        # --- 6. PII & Campus/Enterprise Sensitive Data (4 rules) ---
        SecretRule(
            rule_id="OG-PII-001",
            name="Chinese Resident ID Card Number (ISO 7064 MOD 11-2 Verified)",
            pattern=re.compile(r"\b([1-8]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx])\b"),
            severity=Severity.HIGH,
            category_tag="pii",
            min_entropy=0.0,
            validator=validate_chinese_id,
            remediation="开源仓库禁止包含真实公民身份证号，请立即脱敏或替换为随机测试构造数据。",
            cwe_id="CWE-359",
        ),
        SecretRule(
            rule_id="OG-PII-002",
            name="Bank Card Number in Payment Context (Luhn Verified)",
            pattern=re.compile(
                r"(?i)(?:card_?no|bank_?card|account_?no|pan|银行卡|卡号)\s*[:=]\s*[\"']([3-6]\d{14,18})[\"']"
            ),
            severity=Severity.HIGH,
            category_tag="pii",
            min_entropy=0.0,
            extract_group=1,
            validator=validate_luhn,
            remediation="删除源码或测试样本中的真实银行卡号，改用脱敏占位数据。",
            cwe_id="CWE-359",
        ),
        SecretRule(
            rule_id="OG-PII-003",
            name="Hardcoded Mainland China Phone Number in User/PII Context",
            pattern=re.compile(
                r"(?i)(?:phone|mobile|tel|contact|手机号|联系电话)\s*[:=]\s*[\"'](1[3-9]\d{9})[\"']"
            ),
            severity=Severity.MEDIUM,
            category_tag="pii",
            min_entropy=0.0,
            extract_group=1,
            remediation="将真实个人手机号移出开源测试样例，避免隐私泄露。",
            cwe_id="CWE-359",
        ),
        SecretRule(
            rule_id="OG-NET-001",
            name="Internal / Private IP Address with Admin Port or Auth Context",
            pattern=re.compile(
                r"(?i)(?:internal_?host|admin_?url|db_?host|redis_?host|intranet|内网)\s*[:=]\s*[\"'](https?://(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}(?::\d+)?)[\"']"
            ),
            severity=Severity.LOW,
            category_tag="internal_net",
            min_entropy=0.0,
            extract_group=1,
            remediation="将内网拓扑 IP 与运维端口抽离至本地环境配置文件，避免暴露内网架构。",
            cwe_id="CWE-200",
        ),
    ]
