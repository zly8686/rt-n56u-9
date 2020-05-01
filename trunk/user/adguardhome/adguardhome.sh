#!/bin/sh

change_dns() {
if [ "$(nvram get adg_redirect)" = 1 ]; then
sed -i '/no-resolv/d' /etc/storage/dnsmasq/dnsmasq.conf
sed -i '/server=127.0.0.1/d' /etc/storage/dnsmasq/dnsmasq.conf
cat >> /etc/storage/dnsmasq/dnsmasq.conf << EOF
no-resolv
server=127.0.0.1#5335
EOF
/sbin/restart_dhcpd
logger -t "AdGuardHome" "添加DNS转发到5335端口"
fi
}
del_dns() {
sed -i '/no-resolv/d' /etc/storage/dnsmasq/dnsmasq.conf
sed -i '/server=127.0.0.1#5335/d' /etc/storage/dnsmasq/dnsmasq.conf
/sbin/restart_dhcpd
}

set_iptable()
{
    if [ "$(nvram get adg_redirect)" = 2 ]; then
	IPS="`ifconfig | grep "inet addr" | grep -v ":127" | grep "Bcast" | awk '{print $2}' | awk -F : '{print $2}'`"
	for IP in $IPS
	do
		iptables -t nat -A PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports 5335 >/dev/null 2>&1
		iptables -t nat -A PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports 5335>/dev/null 2>&1
	done

	IPS="`ifconfig | grep "inet6 addr" | grep -v " fe80::" | grep -v " ::1" | grep "Global" | awk '{print $3}'`"
	for IP in $IPS
	do
		ip6tables -t nat -A PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports 5335 >/dev/null 2>&1
		ip6tables -t nat -A PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports 5335 >/dev/null 2>&1
	done
    logger -t "AdGuardHome" "重定向53端口"
    fi
}

clear_iptable()
{
	OLD_PORT="5335"
	IPS="`ifconfig | grep "inet addr" | grep -v ":127" | grep "Bcast" | awk '{print $2}' | awk -F : '{print $2}'`"
	for IP in $IPS
	do
		iptables -t nat -D PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
		iptables -t nat -D PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
	done

	IPS="`ifconfig | grep "inet6 addr" | grep -v " fe80::" | grep -v " ::1" | grep "Global" | awk '{print $3}'`"
	for IP in $IPS
	do
		ip6tables -t nat -D PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
		ip6tables -t nat -D PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
	done
	
}

getconfig(){
adg_file="/etc/storage/adg.sh"
if [ ! -f "$adg_file" ] || [ ! -s "$adg_file" ] ; then
	cat > "$adg_file" <<-\EEE
bind_host: 0.0.0.0
bind_port: 3030
auth_name: admin
auth_pass: admin
language: zh-cn
rlimit_nofile: 0
dns:
  bind_host: 0.0.0.0
  port: 5335
  statistics_interval: 1
  querylog_enabled: true
  querylog_interval: 90
  querylog_size_memory: 1000
  anonymize_client_ip: false
  protection_enabled: true
  blocking_mode: nxdomain
  blocking_ipv4: ""
  blocking_ipv6: ""
  blocked_response_ttl: 60
  ratelimit: 0
  ratelimit_whitelist: []
  refuse_any: true
  bootstrap_dns:
  - 114.114.114.114
  - 119.29.29.29
  all_servers: false
  edns_client_subnet: false
  enable_dnssec: true
  aaaa_disabled: false
  fastest_addr: true
  allowed_clients: []
  disallowed_clients: []
  blocked_hosts: []
  parental_block_host: family-block.dns.adguard.com
  safebrowsing_block_host: standard-block.dns.adguard.com
  cache_size: 4194304
  cache_ttl_min: 0
  cache_ttl_max: 0
  upstream_dns:
  - tls://v.233py.com
  - https://i.233py.com/dns-query
  filtering_enabled: true
  filters_update_interval: 24
  parental_enabled: false
  safesearch_enabled: false
  safebrowsing_enabled: false
  safebrowsing_cache_size: 1048576
  safesearch_cache_size: 1048576
  parental_cache_size: 1048576
  cache_time: 30
  rewrites: []
  blocked_services: []
tls:
  enabled: false
  server_name: ""
  force_https: false
  port_https: 443
  port_dns_over_tls: 853
  allow_unencrypted_doh: false
  strict_sni_check: false
  certificate_chain: ""
  private_key: ""
  certificate_path: ""
  private_key_path: ""
filters:
- enabled: true
  url: https://gitee.com/privacy-protection-tools/anti-ad/raw/master/easylist.txt
  name: easylist
  id: 1588275967
- enabled: true
  url: https://gitee.com/xinggsf/Adblock-Rule/raw/master/rule.txt
  name: 乘风
  id: 1588275968
- enabled: true
  url: https://gitee.com/xinggsf/Adblock-Rule/raw/master/mv.txt
  name: 乘风视频
  id: 1588275969
whitelist_filters: []
user_rules: []
dhcp:
  enabled: false
  interface_name: ""
  gateway_ip: ""
  subnet_mask: ""
  range_start: ""
  range_end: ""
  lease_duration: 86400
  icmp_timeout_msec: 1000
clients: []
log_file: ""
verbose: false
schema_version: 6

EEE
	chmod 755 "$adg_file"
fi
}

dl_adg(){
logger -t "AdGuardHome" "下载AdGuardHome"
#wget --no-check-certificate -O /tmp/AdGuardHome.tar.gz https://github.com/AdguardTeam/AdGuardHome/releases/download/v0.101.0/AdGuardHome_linux_mipsle.tar.gz
curl -k -s -o /tmp/AdGuardHome/AdGuardHome --connect-timeout 10 --retry 3 https://cdn.jsdelivr.net/gh/zly8686/rt-n56u/trunk/user/adguardhome/AdGuardHome
if [ ! -f "/tmp/AdGuardHome/AdGuardHome" ]; then
logger -t "AdGuardHome" "AdGuardHome下载失败，请检查是否能正常访问github!程序将退出。"
nvram set adg_enable=0
exit 0
else
logger -t "AdGuardHome" "AdGuardHome下载成功。"
chmod 777 /tmp/AdGuardHome/AdGuardHome
fi
}

start_adg(){
    mkdir -p /tmp/AdGuardHome
	mkdir -p /etc/storage/AdGuardHome
	if [ ! -f "/tmp/AdGuardHome/AdGuardHome" ]; then
	dl_adg
	fi
	getconfig
	change_dns
	set_iptable
	logger -t "AdGuardHome" "运行AdGuardHome"
	eval "/tmp/AdGuardHome/AdGuardHome -c $adg_file -w /tmp/AdGuardHome -v" &

}
stop_adg(){
rm -rf /tmp/AdGuardHome
killall -9 AdGuardHome
del_dns
clear_iptable
}


case $1 in
start)
	start_adg
	;;
stop)
	stop_adg
	;;
*)
	echo "check"
	;;
esac
