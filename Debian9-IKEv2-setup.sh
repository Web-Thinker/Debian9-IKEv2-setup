#!/bin/bash -e
# Sctipt for install VPN-server protocol IKEv2
# Sctipt ver. 2.3
# Created by 2021-07-27
# Updated  2021-08-03
if [ "$EUID" -ne 0 ]
then echo "Please run script as root"
   exit
fi
echo
echo "=== Start install VPN-server... ==="
echo
#function exitBadly {
#  echo "$1"
#  exit 1
#}
#
#[[ $(id -u) -eq 0 ]] || exitBadly "Please re-run as root (e.g. sudo ./path/to/this/script)"
echo
echo "=== Start install VPN-server... ==="
echo
echo
echo "--- Upgrading and installing packages ---"
echo
apt-get update -y
apt install libcharon-extra-plugins libstrongswan-extra-plugins strongswan certbot dnsutils htop mc -y
ETH0ORSIMILAR=$(ip route get 1.1.1.1 | awk -- '{printf $5}')
IP=$(dig -4 +short myip.opendns.com @resolver1.opendns.com)
echo
echo "Your server's interface name is: ${ETH0ORSIMILAR} and ip: ${IP}"
echo
echo
echo "--- Configuration: general server settings ---"
echo
read -r -p "Email address for sysadmin (e.g. VasyaPup@example.com): " EMAILADRES
echo "** Note: Please enter the domain name of the VPN server to set up the Let's Encrypt certificate. **"
read -r -p "Domain name for VPN: " VPNHOST
VPNHOSTIP=$(dig -4 +short "${VPNHOST}")
#[[ -n "${VPNHOSTIP}" ]] || exitBadly "Cannot resolve VPN hostname: aborting"
if [[ "${IP}" != "${VPNHOSTIP}" ]]; then
  echo "Warning: ${VPNHOST} resolves to ${VPNHOSTIP}, not ${IP}"
  echo "Something went wrong because you are behind NAT. Or (for example, the hostname points to the wrong IP address, CloudFlare proxies the shenanigans, ...)"
  read -r -p "Press [Return] to continue or Ctrl-C to abort"
fi
echo
echo "=== Creation of certificates in progress... ==="
echo
echo 'rsa-key-size = 4096
pre-hook = /sbin/iptables -I INPUT -p tcp --dport 80 -j ACCEPT
post-hook = /sbin/iptables -D INPUT -p tcp --dport 80 -j ACCEPT
renew-hook = /usr/sbin/ipsec reload && /usr/sbin/ipsec secrets
' > /etc/letsencrypt/cli.ini
echo
certbot certonly --rsa-key-size 4096 --standalone --agree-tos --no-eff-email --email "${EMAILADRES}" -d "${VPNHOST}"
echo
echo "=== Under your certs dir, copy paste to ipsec ==="
echo
ln -f -s "/etc/letsencrypt/live/${VPNHOST}/cert.pem"    /etc/ipsec.d/certs/cert.pem
ln -f -s "/etc/letsencrypt/live/${VPNHOST}/privkey.pem" /etc/ipsec.d/private/privkey.pem
ln -f -s "/etc/letsencrypt/live/${VPNHOST}/chain.pem"   /etc/ipsec.d/cacerts/chain.pem
ln -f -s "/etc/letsencrypt/live/${VPNHOST}/fullchain.pem" /etc/ipsec.d/certs/fullchain.pem
VPNIPPOOL="10.0.2.0/24"
VPNIPPOOL6V="fd9d:bc11:4021::/64"
echo '
Public DNS servers include:
176.103.130.130,176.103.130.131  AdGuard               https://adguard.com/en/adguard-dns/overview.html
176.103.130.132,176.103.130.134  AdGuard Family        https://adguard.com/en/adguard-dns/overview.html
1.1.1.1,1.0.0.1                  Cloudflare/APNIC      https://1.1.1.1
84.200.69.80,84.200.70.40        DNS.WATCH             https://dns.watch
8.8.8.8,8.8.4.4                  Google                https://developers.google.com/speed/public-dns/
208.67.222.222,208.67.220.220    OpenDNS               https://www.opendns.com
208.67.222.123,208.67.220.123    OpenDNS FamilyShield  https://www.opendns.com
9.9.9.9,149.112.112.112          Quad9                 https://quad9.net
77.88.8.8,77.88.8.1              Yandex                https://dns.yandex.com
77.88.8.88,77.88.8.2             Yandex Safe           https://dns.yandex.com
77.88.8.7,77.88.8.3              Yandex Family         https://dns.yandex.com
'
read -r -p "DNS servers for VPN users (default: 77.88.8.8,77.88.8.1): " VPNDNS
VPNDNS=${VPNDNS:-'77.88.8.8,77.88.8.1'}
echo "# ipsec.conf - strongSwan IPsec configuration file
config setup
    charondebug=\"ike 2, knl 3, cfg 0\"
    uniqueids=never # allow multiple connection with per account
conn %default
    compress=no
    type=tunnel
    keyexchange=ikev2
    ike=aes128-sha1-modp1024,aes128-sha1-modp1536,aes128-sha1-modp2048,aes128-sha256-ecp256,aes128-sha256-modp1024,aes128-sha256-modp1536,aes128-sha256-modp2048,aes256-aes128-sha256-sha1-modp2048-modp4096-modp1024,aes256-sha1-modp1024,aes256-sha256-modp1024,aes256-sha256-modp1536,aes256-sha256-modp2048,aes256-sha256-modp4096,aes256-sha384-ecp384,aes256-sha384-modp1024,aes256-sha384-modp1536,aes256-sha384-modp2048,aes256-sha384-modp4096,aes256gcm16-aes256gcm12-aes128gcm16-aes128gcm12-sha256-sha1-modp2048-modp4096-modp1024,3des-sha1-modp1024!
    esp=aes128-aes256-sha1-sha256-modp2048-modp4096-modp1024,aes128-sha1,aes128-sha1-modp1024,aes128-sha1-modp1536,aes128-sha1-modp2048,aes128-sha256,aes128-sha256-ecp256,aes128-sha256-modp1024,aes128-sha256-modp1536,aes128-sha256-modp2048,aes128gcm12-aes128gcm16-aes256gcm12-aes256gcm16-modp2048-modp4096-modp1024,aes128gcm16,aes128gcm16-ecp256,aes256-sha1,aes256-sha256,aes256-sha256-modp1024,aes256-sha256-modp1536,aes256-sha256-modp2048,aes256-sha256-modp4096,aes256-sha384,aes256-sha384-ecp384,aes256-sha384-modp1024,aes256-sha384-modp1536,aes256-sha384-modp2048,aes256-sha384-modp4096,aes256gcm16,aes256gcm16-ecp384,3des-sha1!
    dpdaction=clear
    dpddelay=35s
    dpdtimeout=300s
    rekey=no
    fragmentation=yes
    forceencaps=yes
#define new ipsec connection
conn win-ios-droid
    left=%any
    leftsubnet=0.0.0.0/0
    leftcert=/etc/ipsec.d/certs/fullchain.pem
    leftid=${VPNHOST}
    leftsendcert=always
    right=%any
    rightid=%any
    rightsourceip=${VPNIPPOOL},${VPNIPPOOL6V}
    rightauth=eap-mschapv2
    rightsendcert=never
    rightdns=${VPNDNS}
    eap_identity=%identity
    auto=add
" > /etc/ipsec.conf
echo
echo "=== Create VPN Client User and Password ==="
echo
read -r -p "VPN username: " VPNUSERNAME
while true; do
read -r -s -p "VPN password (no quotes, please): " VPNPASSWORD
echo
read -r -s -p "Confirm VPN password: " VPNPASSWORD2
echo
[[ "${VPNPASSWORD}" = "${VPNPASSWORD2}" ]] && break
echo "Passwords didn't match -- please try again"
done
echo
echo "${VPNHOST} : RSA /etc/ipsec.d/private/privkey.pem
${VPNUSERNAME} : EAP "${VPNPASSWORD}"

#include /var/lib/strongswan/ipsec.secrets.inc
" > /etc/ipsec.secrets
echo
systemctl start strongswan
systemctl enable strongswan
echo
echo "--- Configuration: general server settings ---"
echo
grep -Fq 'Web-Thinker/Debian9-IKEv2-setup' /etc/sysctl.conf || echo "
# https://github.com/Web-Thinker/Debian9-IKEv2-setup
# Configuration forward for IKEv2-Serve
net.ipv4.ip_forward = 1
# Do not accept ICMP redirects (prevent MITM attacks)
net.ipv4.conf.all.accept_redirects = 0
# Do not send ICMP redirects (we are not a router)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.ip_no_pmtu_disc = 1
" > /etc/sysctl.conf
echo
SYSCTLFILE=/sbin/sysctl
if [ -f "${SYSCTLFILE}" ]; then
   echo "--- Resarting forward Debian 10 ---"
   /sbin/sysctl -p
else
   echo "--- Resarting forward Debian 9 ---"
   sysctl -p
fi
echo
# firewall
# https://www.strongswan.org/docs/LinuxKongress2009-strongswan.pdf
# https://wiki.strongswan.org/projects/strongswan/wiki/ForwardingAndSplitTunneling
# https://www.zeitgeist.se/2013/11/26/mtu-woes-in-ipsec-tunnels-how-to-fix/
IPTFILE=/sbin/iptables
if [ -f "${IPTFILE}" ]; then
   #echo "--- Resarting forward Debian 10 ---"
   IPT=/sbin/iptables
   IP6T=/sbin/ip6tables
else
   #echo "--- Resarting forward Debian 9 ---"
   IPT=iptables
   IP6T=ip6tables
fi
read -r -p "Desired SSH log-in port (default: 22): " SSHPORT
SSHPORT=${SSHPORT:-22}
TCP_PORTS="80,443,8443,4433,31337,5222,5223,5228,5060,5064,2195,2196"
UDP_PORTS="500,4500"
${IPT} -P INPUT   ACCEPT
${IPT} -P FORWARD ACCEPT
${IPT} -P OUTPUT  ACCEPT
${IPT} -F
${IPT} -t filter -F
${IPT} -t nat -F
${IPT} -t mangle -F
${IPT} -X
${IPT} -t filter -X
${IPT} -t nat -X
${IPT} -t mangle -X
${IP6T} -F
${IP6T} -t filter -F
${IP6T} -t nat -F
${IP6T} -t mangle -F
${IP6T} -X
${IP6T} -t filter -X
${IP6T} -t nat -X
${IP6T} -t mangle -X
# Drop all other inbound - default deny unless explicitly allowed policy:
# ${IPT} -A INPUT -j REJECT
# ${IPT} -A FORWARD -j REJECT
# ${IP6T} -A INPUT -j REJECT
# ${IP6T} -A FORWARD -j REJECT
# INPUT
# accept anything on the loopback interface
${IPT} -A INPUT -i lo -j ACCEPT
${IPT} -A INPUT ! -i lo -d 127.0.0.0/8 -j REJECT
${IP6T} -A INPUT -i lo -j ACCEPT
${IP6T} -A INPUT ! -i lo -d ::1/128 -j REJECT
# Accepts all established inbound connections
${IPT} -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
${IPT} -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
${IPT} -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
${IP6T} -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
${IP6T} -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
${IP6T} -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
# Allows all outbound traffic
# You could modify this to only allow certain traffic
${IPT} -A OUTPUT -j ACCEPT
${IP6T} -A OUTPUT -j ACCEPT
# Allows SSH connections
# The --dport number is the same as in /etc/ssh/sshd_config
${IPT} -A INPUT -p tcp -m state --state NEW --dport "${SSHPORT}" -j ACCEPT
${IP6T} -A INPUT -p tcp -m state --state NEW --dport "${SSHPORT}" -j ACCEPT
# Allows IM
${IPT} -A INPUT -p tcp -m multiport --dports "${TCP_PORTS}" -j ACCEPT
${IP6T} -A INPUT -p tcp -m multiport --dports "${TCP_PORTS}" -j ACCEPT
# Allows ikev2
${IPT} -A INPUT -p udp -m multiport --dports "${UDP_PORTS}" -j ACCEPT
${IP6T} -A INPUT -p udp -m multiport --dports "${UDP_PORTS}" -j ACCEPT
# Allows udp
${IPT} -A INPUT -p udp -j ACCEPT
${IP6T} -A INPUT -p udp -j ACCEPT
# Allow VPN routing
${IPT} -t nat -A POSTROUTING -s "${VPNIPPOOL}" -o "${ETH0ORSIMILAR}" -m policy --dir out --pol ipsec -j ACCEPT
${IPT} -t nat -A POSTROUTING -s "${VPNIPPOOL}" -o "${ETH0ORSIMILAR}" -j MASQUERADE
${IP6T} -t nat -A POSTROUTING -s "${VPNIPPOOL6V}" -o "${ETH0ORSIMILAR}" -m policy --dir out --pol ipsec -j ACCEPT
${IP6T} -t nat -A POSTROUTING -s "${VPNIPPOOL6V}" -o "${ETH0ORSIMILAR}" -j MASQUERADE
# log ${IPT} denied calls (access via 'dmesg' command)
${IPT} -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7
${IP6T} -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7
${IPT} -L
${IPT} -L -v -t mangle
${IPT} -L -v -t nat
echo
echo "--- Applying firewall rules... ---"
echo
/sbin/iptables-save > /etc/firewall.conf
grep -Fq 'Web-Thinker/Debian9-IKEv2-setup' /etc/network/if-up.d/iptables || echo "#!/bin/sh
# https://github.com/Web-Thinker/Debian9-IKEv2-setup
/sbin/iptables-restore < /etc/firewall.conf
" > /etc/network/if-up.d/iptables
chmod +x /etc/network/if-up.d/iptables
echo
echo "--- Resarting VPN-server... ---"
echo
IPSECFILE=/sbin/ipsec
if [ -f "${IPSECFILE}" ]; then
   echo "--- Updating strongSwan IPsec configuration Debian 10 ---"
   /sbin/ipsec update
   /sbin/ipsec reload
else
   echo "--- Updating strongSwan IPsec configuration Debian 9 ---"
   ipsec update
   ipsec reload
fi
systemctl reload ipsec
systemctl reload strongswan
systemctl restart ipsec
systemctl restart strongswan
systemctl status ipsec
echo
echo "=== Paranoid bonus. ))) ===
Removing and redirecting logging to the black hole."
echo
rm /var/log/syslog && ln -s /dev/null /var/log/syslog
rm /var/log/auth.log && ln -s /dev/null /var/log/auth.log
echo
echo "--- If the VPN server does not start, try restarting the server. To do this, use your personal account on Hosting, or run the (reboot) command. ---"
echo
exit 0
