# Bingxin DN42 Bot

**这是 [Potat0000/dn42-bot](https://github.com/Potat0000/dn42-bot) 的 Fork 版本**，根据我自己的需求添加了部分功能。

欢迎在 Telegram 中使用 [@baka_lg_bot](t.me/baka_lg_bot) 和我进行 Peer！

## 新增功能
 - 支持了 [Docker 部署](DOCKER.md)
 - 支持了通过 SSH / GPG 进行 ASN 登录
 - 支持了非 DN42 ASN 的自助 Peer
 - 支持了 `findnoc` 指令
 - 修改了部分 whois 请求为本地拉取仓库进行遍历
 - 修改了默认数据存放位置
 - 修改了 `login` 的相关逻辑以支持 Org 类的 ASN 登录
 - 新增了部分参数

## 新增配置
`server/config.py`：
| Config Key          | Description                                                                                    |
| ------------------- | ---------------------------------------------------------------------------------------------- |
| DIG_ADDRESS         | The address of /dig                                                                            |

## TODO
 - [x] 支持节点审批

## 注意事项
 - 使用特权码登录时，请按照输入 `/login <ASN>` - 选择 `📧 Email Verification 邮箱验证` - 输入特权码的步骤登录。
 - 由于 Telegram API 的限制，需要设置 Webhook 才能正确响应当用户手动发送 `GPG 公钥` 时的请求，否则由于消息接收顺序的问题，可能会导致登录失败。

以下为原 README 内容：

# Yet Another Telegram DN42 Bot

## Features

- Tools
  - [x] Ping
  - [x] TCPing
  - [x] Traceroute
  - [x] Route
  - [x] Path
  - [x] Whois
  - [x] Dig / NSLookup
- User Manage
  - [x] Login
  - [x] Logout
  - [x] Whoami
- Peer
  - [x] New peer
  - [x] Modify peer
  - [x] Remove peer
  - [x] Peer info
- Statistics
  - [x] DN42 global ranking
  - [x] DN42 user basic info & statistics
  - [x] Peer situation of a user
  - [x] Preferred routes ranking
- Blacklist
  - [x] Block / Unblock an ASN
  - [x] Get blocked ASN list

## Deployment

The project is divided into two parts: server and agent, which can be deployed separately and have independent `requirements.txt`.

### Server

The server directory contains the code for the tg-bot server.

#### Config

Config items are located at `server/config.py`.

| Config Key          | Description                                                                                    |
| ------------------- | ---------------------------------------------------------------------------------------------- |
| BOT_TOKEN           | Token of Telegram Bot                                                                          |
| CONTACT             | Contact information for yourself                                                               |
| DN42_ASN            | Your DN42 ASN                                                                                  |
| WELCOME_TEXT        | The text shows at the top of /help command                                                     |
| WHOIS_ADDRESS       | The address of whois server                                                                    |
| DN42_ONLY           | Whether the tool commands (ping, traceroute, etc.) only allow DN42 networks                    |
| ALLOW_NO_CLEARNET   | Whether allowed to peer with someone who has no clearnet                                       |
| ENDPOINT            | Server name domain suffixes                                                                    |
| API_PORT            | Agent API Port                                                                                 |
| API_TOKEN           | Agent API Token                                                                                |
| SERVERS             | A dict. The keys are the actual server names while the values are the display names            |
| HOSTS               | (Optional) A dict. The keys are contained in the SERVERS while the values are its custom hosts |
| WEBHOOK_URL         | (Optional) Webhook URL to regist to Telegram. Disable webhook by set it to empty string        |
| WEBHOOK_LISTEN_HOST | (Required if webhook enabled) The listen host for webhook                                      |
| WEBHOOK_LISTEN_PORT | (Required if webhook enabled) The listen port for webhook                                      |
| LG_DOMAIN           | (Optional) URL of looking glass. Support bird-lg's URL format                                  |
| PRIVILEGE_CODE      | (Optional) Privilege code                                                                      |
| SINGLE_PRIVILEGE    | (Optional) Whether to disable the privilege code when a privileged user already logs in        |
| CN_WHITELIST_IP     | (Optional) A list of IP networks that been explicitly marked as non-Chinese-Mainland           |
| SENTRY_DSN          | (Optional) Sentry DSN. Leave empty to disable Sentry exception tracking                        |

#### Email-sending function

You should implement a `send_email(asn, mnt, code, email)` function in `config.py` and do the email sending in that function. If the send meets an error, a `RuntimeError` should be raised, otherwise, the send will be considered successful.

#### Privilege code

Privilege code login is provided for network operators.

When logging in, you can enter the Privilege Code when selecting email to log in as a privileged user.

Privileged users can use `/whoami <New AS>` to directly modify their identity, unlock additional settings in `/peer`, remove some restrictions, and receive notifications when others create or delete peers.

### Agent

The agent directory contains the code for the "agent" for tg-bot server.

#### Config

Config items are located at `agent/agent_config.json`.

| Config Key                 | Description                                                  |
| -------------------------- | ------------------------------------------------------------ |
| HOST                       | API listen host                                              |
| PORT                       | API Port                                                     |
| SECRET                     | API Token                                                    |
| OPEN                       | Whether open peer                                            |
| MAX_PEERS                  | Maximum number of Peer (0 for no limit)                      |
| MIN_PEER_REQUIREMENT       | Minimum number of peers required to peer with this node      |
| NET_SUPPORT                | Net supported by this agent                                  |
| EXTRA_MSG                  | Extra message of this agent                                  |
| MY_DN42_LINK_LOCAL_ADDRESS | The DN42 IPv6 Link-Local Address of this agent               |
| MY_DN42_ULA_ADDRESS        | The DN42 IPv6 ULA Address of this agent                      |
| MY_DN42_IPv4_ADDRESS       | The DN42 IPv4 Address of this agent                          |
| MY_WG_PUBLIC_KEY           | The WireGuard Public Key of this agent                       |
| SENTRY_DSN                 | Sentry DSN. Leave empty to disable Sentry exception tracking |
| BIRD_TABLE_4               | The name of the BIRD table for IPv4                          |
| BIRD_TABLE_6               | The name of the BIRD table for IPv6                          |
| VNSTAT_AUTO_ADD            | Whether to automatically add tunnel interface to vnstat      |
| VNSTAT_AUTO_REMOVE         | Whether to automatically remove tunnel interface from vnstat |

`NET_SUPPORT` item has following subconfig items:

- `ipv4`: Whether support IPv4
- `ipv6`: Whether support IPv6
- `ipv4_nat`: Whether the IPv4 is behind NAT
- `cn`: Whether allowed to peer with Chinese Mainland

#### TCPing

You should install a `tcping` command in the system. Currently, the agent only supports [nodeseeker/tcping](https://github.com/nodeseeker/tcping). You can modify the `tcping_test()` function to use other TCPing tools.

## Have a try

My bot is deployed at [@Potat0_DN42_Bot](https://t.me/Potat0_DN42_Bot). Welcome to peer with me!



