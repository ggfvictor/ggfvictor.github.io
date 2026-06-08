#!/bin/bash

# 检查是否以 root 权限运行
if [ "$EUID" -ne 0 ]; then
  echo "请以 root 用户运行此脚本。"
  exit 1
fi

# 定义要添加的 SSH 公钥
SSH_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOpxyoQ6pQ7+ikdCPgyBg+54NTivQZlNAbJFrBqSx5Uy"

# SSH 配置文件
SSHD_CONFIG="/etc/ssh/sshd_config"
SSH_PORT="19981"

# 备份原始 sshd_config
if [ ! -f "${SSHD_CONFIG}.bak" ]; then
  cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"
  echo "已备份原始 sshd_config 到 ${SSHD_CONFIG}.bak"
fi

# 检查 /root/.ssh 目录是否存在，不存在则创建
if [ ! -d /root/.ssh ]; then
  mkdir -p /root/.ssh || { echo "无法创建 /root/.ssh 目录。"; exit 1; }
  echo "/root/.ssh 目录已创建。"
fi

# 检查 authorized_keys 文件是否存在，不存在则创建
if [ ! -f /root/.ssh/authorized_keys ]; then
  touch /root/.ssh/authorized_keys || { echo "无法创建 /root/.ssh/authorized_keys 文件。"; exit 1; }
  echo "/root/.ssh/authorized_keys 文件已创建。"
fi

# 检查公钥是否已经存在
if grep -qF "$SSH_KEY" /root/.ssh/authorized_keys; then
  echo "SSH 公钥已经存在，未进行重复添加。"
else
  echo "$SSH_KEY" >> /root/.ssh/authorized_keys || { echo "添加 SSH 公钥失败。"; exit 1; }
  echo "SSH 公钥已成功添加。"
fi

# 设置权限
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys || { echo "权限设置失败。"; exit 1; }
echo "权限设置已成功应用。"

# 通用函数：设置 sshd_config 参数
set_sshd_option() {
  local key="$1"
  local value="$2"

  if grep -qE "^[#[:space:]]*${key}[[:space:]]+" "$SSHD_CONFIG"; then
    sed -i "s|^[#[:space:]]*${key}[[:space:]].*|${key} ${value}|g" "$SSHD_CONFIG"
  else
    echo "${key} ${value}" >> "$SSHD_CONFIG"
  fi
}

# 检查当前系统防火墙是否放行指定 TCP 端口
check_firewall_port() {
  local port="$1"

  if command -v ufw >/dev/null 2>&1; then
    local ufw_status
    ufw_status=$(ufw status 2>/dev/null)
    if echo "$ufw_status" | grep -qi "Status: active"; then
      if echo "$ufw_status" | grep -Eq "(^|[[:space:]])${port}/tcp[[:space:]]+ALLOW"; then
        echo "检测结果：UFW 已放行 ${port}/tcp"
        return 0
      else
        echo "检测结果：UFW 已启用，但未放行 ${port}/tcp"
        return 1
      fi
    fi
  fi

  if command -v firewall-cmd >/dev/null 2>&1; then
    if systemctl is-active --quiet firewalld; then
      if firewall-cmd --quiet --query-port="${port}/tcp"; then
        echo "检测结果：firewalld 已放行 ${port}/tcp"
        return 0
      else
        echo "检测结果：firewalld 已启用，但未放行 ${port}/tcp"
        return 1
      fi
    fi
  fi

  if command -v nft >/dev/null 2>&1; then
    if systemctl is-active --quiet nftables 2>/dev/null || [ -n "$(nft list ruleset 2>/dev/null)" ]; then
      if nft list ruleset 2>/dev/null | grep -Eq "tcp dport (.*\{[^}]*\b${port}\b[^}]*\}|${port}\b).*accept"; then
        echo "检测结果：nftables 规则中已匹配到 ${port}/tcp 放行"
        return 0
      else
        echo "检测结果：检测到 nftables，但未匹配到 ${port}/tcp 放行规则"
        return 1
      fi
    fi
  fi

  if command -v iptables >/dev/null 2>&1; then
    if iptables -S INPUT >/dev/null 2>&1; then
      if iptables -S INPUT | grep -Eq -- "-p tcp .* --dport ${port} .* -j ACCEPT|--dport ${port} -j ACCEPT"; then
        echo "检测结果：iptables INPUT 链已放行 ${port}/tcp"
        return 0
      else
        echo "检测结果：检测到 iptables，但未匹配到 ${port}/tcp 放行规则"
        return 1
      fi
    fi
  fi

  echo "未检测到已启用的 UFW / firewalld / nftables / iptables，无法确认端口是否放行。"
  return 2
}

# 自动确保当前系统防火墙已放行指定 TCP 端口
ensure_firewall_port_allowed() {
  local port="$1"

  echo "开始检查防火墙是否已放行 TCP ${port}..."
  check_firewall_port "$port"
  local status=$?

  if [ "$status" -eq 0 ]; then
    echo "无需处理：${port}/tcp 已放行。"
    return 0
  fi

  if command -v ufw >/dev/null 2>&1; then
    local ufw_status
    ufw_status=$(ufw status 2>/dev/null)
    if echo "$ufw_status" | grep -qi "Status: active"; then
      echo "正在通过 UFW 放行 ${port}/tcp ..."
      ufw allow "${port}/tcp"
      [ $? -eq 0 ] && echo "已通过 UFW 放行 ${port}/tcp" && return 0
      echo "通过 UFW 放行 ${port}/tcp 失败"
      return 1
    fi
  fi

  if command -v firewall-cmd >/dev/null 2>&1; then
    if systemctl is-active --quiet firewalld; then
      echo "正在通过 firewalld 放行 ${port}/tcp ..."
      firewall-cmd --permanent --add-port="${port}/tcp" && firewall-cmd --reload
      [ $? -eq 0 ] && echo "已通过 firewalld 永久放行 ${port}/tcp" && return 0
      echo "通过 firewalld 放行 ${port}/tcp 失败"
      return 1
    fi
  fi

  if command -v nft >/dev/null 2>&1; then
    if systemctl is-active --quiet nftables 2>/dev/null || [ -n "$(nft list ruleset 2>/dev/null)" ]; then
      echo "正在尝试通过 nftables 放行 ${port}/tcp ..."

      if nft list chain inet filter input >/dev/null 2>&1; then
        nft add rule inet filter input tcp dport "${port}" accept
        if [ $? -eq 0 ]; then
          echo "已通过 nftables 放行 ${port}/tcp（链：inet filter input）"
          if [ -f /etc/nftables.conf ]; then
            nft list ruleset > /etc/nftables.conf 2>/dev/null && echo "已同步保存到 /etc/nftables.conf"
          else
            echo "提示：本次 nftables 规则可能仅当前运行时生效，请确认持久化配置。"
          fi
          return 0
        fi
      fi

      if nft list chain ip filter input >/dev/null 2>&1; then
        nft add rule ip filter input tcp dport "${port}" accept
        if [ $? -eq 0 ]; then
          echo "已通过 nftables 放行 ${port}/tcp（链：ip filter input）"
          if [ -f /etc/nftables.conf ]; then
            nft list ruleset > /etc/nftables.conf 2>/dev/null && echo "已同步保存到 /etc/nftables.conf"
          else
            echo "提示：本次 nftables 规则可能仅当前运行时生效，请确认持久化配置。"
          fi
          return 0
        fi
      fi

      echo "nftables 已检测到，但未找到适合自动写入的 input 链，未自动放行。"
      return 1
    fi
  fi

  if command -v iptables >/dev/null 2>&1; then
    if iptables -S INPUT >/dev/null 2>&1; then
      echo "正在尝试通过 iptables 放行 ${port}/tcp ..."
      iptables -C INPUT -p tcp --dport "${port}" -j ACCEPT >/dev/null 2>&1 || \
      iptables -I INPUT -p tcp --dport "${port}" -j ACCEPT

      if [ $? -eq 0 ]; then
        echo "已通过 iptables 放行 ${port}/tcp"

        if command -v netfilter-persistent >/dev/null 2>&1; then
          netfilter-persistent save >/dev/null 2>&1 && echo "已使用 netfilter-persistent 保存规则"
        elif command -v service >/dev/null 2>&1; then
          service iptables save >/dev/null 2>&1 && echo "已尝试保存 iptables 规则"
        else
          echo "提示：本次 iptables 规则可能仅当前运行时生效，请确认持久化保存。"
        fi
        return 0
      fi

      echo "通过 iptables 放行 ${port}/tcp 失败"
      return 1
    fi
  fi

  echo "未检测到可自动处理的防火墙，无法自动放行 ${port}/tcp。"
  echo "如果是云服务器，还请同时检查云安全组/云防火墙。"
  return 2
}

# 启用密钥认证
set_sshd_option "PubkeyAuthentication" "yes"

# 禁用密码认证
set_sshd_option "PasswordAuthentication" "no"

# 检查并设置 SSH 端口为 19981
CURRENT_PORTS=$(grep -E "^[#[:space:]]*Port[[:space:]]+" "$SSHD_CONFIG" | awk '{print $2}' | tr '\n' ' ')
if echo "$CURRENT_PORTS" | grep -qw "$SSH_PORT"; then
  echo "SSH 端口已经是 ${SSH_PORT}，无需修改。"
else
  if grep -qE "^[#[:space:]]*Port[[:space:]]+" "$SSHD_CONFIG"; then
    sed -i "s|^[#[:space:]]*Port[[:space:]].*|Port ${SSH_PORT}|g" "$SSHD_CONFIG"
  else
    echo "Port ${SSH_PORT}" >> "$SSHD_CONFIG"
  fi
  echo "已将 SSH 端口设置为 ${SSH_PORT}。"
fi

echo "已配置 SSH：允许密钥登录、禁用密码登录、端口设置为 ${SSH_PORT}。"

# 校验 sshd 配置
if command -v sshd >/dev/null 2>&1; then
  sshd -t || { echo "sshd 配置校验失败，请检查 ${SSHD_CONFIG}"; exit 1; }
  echo "sshd 配置校验通过。"
else
  echo "未找到 sshd 命令，无法校验配置。"
fi

# 先确保防火墙已放行 SSH 端口，再重启 SSH
ensure_firewall_port_allowed "$SSH_PORT"
FW_RESULT=$?

if [ "$FW_RESULT" -ne 0 ]; then
  echo "防火墙端口放行失败或无法确认，出于安全考虑，脚本停止，不重启 SSH。"
  echo "请先手动确认 ${SSH_PORT}/tcp 已放行后再执行。"
  exit 1
fi

# 重启 SSH 服务
if systemctl is-active --quiet sshd; then
  systemctl restart sshd
elif systemctl is-active --quiet ssh; then
  systemctl restart ssh
else
  echo "未检测到 systemd 管理的 ssh 服务，尝试使用 service 重启..."
  service ssh restart || service sshd restart
fi

if [ $? -eq 0 ]; then
  echo "SSH 服务已重启。"
else
  echo "SSH 服务重启失败。"
  exit 1
fi

# 重启后复查
check_firewall_port "$SSH_PORT"

echo "公钥添加完成，权限配置成功，SSH 登录策略已更新（启用密钥登录，禁用密码登录，端口=${SSH_PORT}）。"
echo "如果是云服务器，请另外确认云安全组也已放行 TCP ${SSH_PORT}。"
