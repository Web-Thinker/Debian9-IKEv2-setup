#!/bin/sh -e
# Sctipt for install VPN-server protocol IKEv2
# Sctipt ver. 1.0
# Created by 2021-07-27

#if [ "$EUID" -ne 0 ]
#then echo "Please run script as root"
#  exit
#fi

#echo
#echo "=== Start install VPN-server... ==="
#echo

function exit_badly {
  echo "$1"
  exit 1
}
[[ $(id -u) -eq 0 ]] || exit_badly "Please re-run as root (e.g. sudo ./path/to/this/script)"

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
[[ -n "${VPNHOSTIP}" ]] || exit_badly "Cannot resolve VPN hostname: aborting"

if [[ "${IP}" != "${VPNHOSTIP}" ]]; then
  echo "Warning: ${VPNHOST} resolves to ${VPNHOSTIP}, not ${IP}"
  echo "Something went wrong because you are behind NAT. Or (for example, the hostname points to the wrong IP address, CloudFlare proxies the shenanigans, ...)"
  read -r -p "Press [Return] to continue or Ctrl-C to abort"
fi

echo
echo "=== Creation of certificates in progress... ==="
echo
certbot certonly --rsa-key-size 4096 --standalone --agree-tos --no-eff-email --email "${EMAILADRES}" -d "${VPNHOST}"

echo
echo "=== Under your certs dir, copy paste to ipsec ==="
echo
# cp /etc/letsencrypt/live/"${VPNHOST}"/chain.pem /etc/ipsec.d/cacerts/chain.pem
# cp /etc/letsencrypt/live/"${VPNHOST}"/fullchain.pem /etc/ipsec.d/certs/fullchain.pem
# cp /etc/letsencrypt/live/"${VPNHOST}"/cert.pem /etc/ipsec.d/certs/cert.pem
# cp /etc/letsencrypt/live/"${VPNHOST}"/privkey.pem /etc/ipsec.d/private/privkey.pem
# Then I decided that it would be better to make symbolic links.
ln -f -s "/etc/letsencrypt/live/${VPNHOST}/cert.pem"    /etc/ipsec.d/certs/cert.pem
ln -f -s "/etc/letsencrypt/live/${VPNHOST}/privkey.pem" /etc/ipsec.d/private/privkey.pem
ln -f -s "/etc/letsencrypt/live/${VPNHOST}/chain.pem"   /etc/ipsec.d/cacerts/chain.pem
ln -f -s "/etc/letsencrypt/live/${VPNHOST}/fullchain.pem" /etc/ipsec.d/certs/fullchain.pem


VPNIPPOOL="10.10.10.0/24"
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

nano /etc/ipsec.conf
cat <<EOF > /etc/ipsec.conf
# ipsec.conf - strongSwan IPsec configuration file

config setup
    charondebug="ike 2, knl 3, cfg 0"
    uniqueids=never # allow multiple connection with per account

conn %default
    compress=no
    type=tunnel
    keyexchange=ikev2
    ike=aes128-sha1-modp1024,aes128-sha1-modp1536,aes128-sha1-modp2048,aes128-sha256-ecp256,aes128-sha256-modp1024,aes128-sha256-modp1536,aes128-sha256-modp2048,aes2$
    esp=aes128-aes256-sha1-sha256-modp2048-modp4096-modp1024,aes128-sha1,aes128-sha1-modp1024,aes128-sha1-modp1536,aes128-sha1-modp2048,aes128-sha256,aes128-sha256-e$
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

#conn ikev2-mschapv2
#    leftauth=eap-mschapv2
#    rightauth=eap-mschapv2
#    eap_identity=%identity
#    auto=route
EOF

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

nano /etc/ipsec.secrets
cat <<EOF > /etc/ipsec.secrets
: RSA /etc/ipsec.d/private/privkey.pem
${VPNUSERNAME} : EAP \"${VPNPASSWORD}\"
EOF

systemctl start strongswan
systemctl enable strongswan

echo
echo "--- Configuration: general server settings ---"
echo

nano /etc/sysctl.conf
cat <<EOF > /etc/sysctl.conf
# Configuration forward for IKEv2-setup
net.ipv4.ip_forward = 1
net.ipv4.ip_no_pmtu_disc = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
sysctl -p

# firewall
# https://www.strongswan.org/docs/LinuxKongress2009-strongswan.pdf
# https://wiki.strongswan.org/projects/strongswan/wiki/ForwardingAndSplitTunneling
# https://www.zeitgeist.se/2013/11/26/mtu-woes-in-ipsec-tunnels-how-to-fix/

read -r -p "Desired SSH log-in port (default: 22): " SSHPORT
SSHPORT=${SSHPORT:-22}

TCP_PORTS="80,443,8443,4433,31337,5222,5223,5228,5060,5064,2195,2196"
UDP_PORTS="500,4500"

iptables -P INPUT   ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT  ACCEPT

iptables -F
iptables -t filter -F
iptables -t nat -F
iptables -t mangle -F
iptables -X
iptables -t filter -X
iptables -t nat -X
iptables -t mangle -X

ip6tables -F
ip6tables -t filter -F
ip6tables -t nat -F
ip6tables -t mangle -F
ip6tables -X
ip6tables -t filter -X
ip6tables -t nat -X
ip6tables -t mangle -X

# INPUT
# accept anything on the loopback interface
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT ! -i lo -d 127.0.0.0/8 -j REJECT

ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A INPUT ! -i lo -d ::1/128 -j REJECT

# Accepts all established inbound connections
#iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
ip6tables -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
ip6tables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allows all outbound traffic
# You could modify this to only allow certain traffic
iptables -A OUTPUT -j ACCEPT
ip6tables -A OUTPUT -j ACCEPT

# Allows SSH connections
# The --dport number is the same as in /etc/ssh/sshd_config
iptables -A INPUT -p tcp -m state --state NEW --dport "${SSHPORT}" -j ACCEPT
ip6tables -A INPUT -p tcp -m state --state NEW --dport "${SSHPORT}" -j ACCEPT

# Allows IM
iptables -A INPUT -p tcp -m multiport --dports "${TCP_PORTS}" -j ACCEPT
ip6tables -A INPUT -p tcp -m multiport --dports "${TCP_PORTS}" -j ACCEPT

# Allows ikev2
iptables -A INPUT -p udp -m multiport --dports "${UDP_PORTS}" -j ACCEPT
ip6tables -A INPUT -p udp -m multiport --dports "${UDP_PORTS}" -j ACCEPT

# Allows udp
iptables -A INPUT -p udp -j ACCEPT
ip6tables -A INPUT -p udp -j ACCEPT

# Allow VPN routing

iptables -t nat -A POSTROUTING -s "${VPNIPPOOL}" -o "${ETH0ORSIMILAR}" -m policy --dir out --pol ipsec -j ACCEPT
iptables -t nat -A POSTROUTING -s "${VPNIPPOOL}" -o "${ETH0ORSIMILAR}" -j MASQUERADE
ip6tables -t nat -A POSTROUTING -s "${VPNIPPOOL6V}" -o "${ETH0ORSIMILAR}" -m policy --dir out --pol ipsec -j ACCEPT
ip6tables -t nat -A POSTROUTING -s "${VPNIPPOOL6V}" -o "${ETH0ORSIMILAR}" -j MASQUERADE

# log iptables denied calls (access via 'dmesg' command)
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7
ip6tables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7

# Drop all other inbound - default deny unless explicitly allowed policy:
#iptables -A INPUT -j REJECT
#iptables -A FORWARD -j REJECT
#ip6tables -A INPUT -j REJECT
#ip6tables -A FORWARD -j REJECT

iptables -L
iptables -L -v -t mangle
iptables -L -v -t nat

iptables-save > /etc/firewall.conf
nano /etc/network/if-up.d/iptables
cat <<EOF > /etc/network/if-up.d/iptables
#!/bin/sh
iptables-restore < /etc/firewall.conf
EOF
chmod +x /etc/network/if-up.d/iptables
echo
echo "--- Resarting VPN-server... ---"
echo
ipsec update
systemctl reload ipsec
systemctl reload strongswan
systemctl restart ipsec
systemctl restart strongswan
systemctl status ipsec

rm /var/log/syslog && ln -s /dev/null /var/log/syslog
rm /var/log/auth.log && ln -s /dev/null /var/log/auth.log
echo
echo "--- If the VPN server does not start, try restarting the server. To do this, use your personal account on Hosting, or run the (reboot) command. ---"
echo
