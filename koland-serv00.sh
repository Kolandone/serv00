#!/bin/bash

re="\033[0m"
red="\033[1;91m"
green="\e[1;32m"
yellow="\e[1;33m"
purple="\e[1;35m"
red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }
reading() { read -p "$(red "$1")" "$2"; }
export LC_ALL=C
USERNAME=$(whoami)
HOSTNAME=$(hostname)
export UUID=${UUID:-'bc97f674-c578-4940-9234-0a1da46041b9'}
export NEZHA_SERVER=${NEZHA_SERVER:-''} 
export NEZHA_PORT=${NEZHA_PORT:-'5555'}     
export NEZHA_KEY=${NEZHA_KEY:-''} 
export ARGO_DOMAIN=${ARGO_DOMAIN:-''}   
export ARGO_AUTH=${ARGO_AUTH:-''}
export CFIP=${CFIP:-'www.visa.com.tw'} 
export CFPORT=${CFPORT:-'443'} 


SERVER_TYPE=$(echo $HOSTNAME | awk -F'.' '{print $2}')

if [ $SERVER_TYPE == "ct8" ];then
    DOMAIN=$USER.ct8.pl
elif [ $SERVER_TYPE == "serv00" ];then
    DOMAIN=$USER.serv00.net
else
    DOMAIN="unknown-domain"
fi
WORKDIR="/usr/home/$USER/domains/$DOMAIN/logs"

[ -d "$WORKDIR" ] || (mkdir -p "$WORKDIR" && chmod 777 "$WORKDIR")


reserve_port() {
    local needed_udp_ports=2
    local needed_tcp_ports=1

    if [ $needed_udp_ports -lt 0 ] || [ $needed_tcp_ports -lt 0 ] || [ $((needed_udp_ports + needed_tcp_ports)) -gt 3 ]; then
        echo "Error: The required port number setting is unreasonable"
        exit 1
    fi

    local port_list
    local port_count
    local current_port
    local max_attempts
    local attempts

    local add_port
    add_port() {
        local port=$1
        local type=$2
        local result=$(devil port add "$type" "$port")
        echo "Try adding reserved $type port $port: $result" 
    }

    local delete_port
    delete_port() {
        local port=$1
        local type=$2
        local result=$(devil port del "$type" "$port")
        echo "Remove $type port $port: $result"
    }

    update_port_list() {
        port_list=$(devil port list)
        port_count=$(echo "$port_list" | grep -c 'udp\|tcp')
    }

    update_port_list

    udp_count=$(echo "$port_list" | grep -c 'udp')
    tcp_count=$(echo "$port_list" | grep -c 'tcp')

    if [ $udp_count -gt $needed_udp_ports ]; then
        to_delete=$((udp_count - needed_udp_ports))
        while [ $to_delete -gt 0 ]; do
            UDP_PORT=$(echo "$port_list" | grep 'udp' | awk 'NR==1{print $1}')
            echo "Need to delete redundant UDP ports $UDP_PORT"
            delete_port $UDP_PORT "udp"
            update_port_list
            udp_count=$(echo "$port_list" | grep -c 'udp')
            to_delete=$((to_delete - 1))
        done
    fi

    if [ $tcp_count -gt $needed_tcp_ports ]; then
        to_delete=$((tcp_count - needed_tcp_ports))
        while [ $to_delete -gt 0 ]; do
            TCP_PORT=$(echo "$port_list" | grep 'tcp' | awk 'NR==1{print $1}')
            echo "Need to delete redundant TCP ports $TCP_PORT"
            delete_port $TCP_PORT "tcp"
            update_port_list
            tcp_count=$(echo "$port_list" | grep -c 'tcp')
            to_delete=$((to_delete - 1))
        done
    fi

    update_port_list
    total_ports=$(echo "$port_list" | grep -c 'udp\|tcp')

    needed_ports=$((needed_udp_ports + needed_tcp_ports))
    while [ $total_ports -lt $needed_ports ]; do
        start_port=$(( RANDOM % 63077 + 1024 )) 

        if [ $start_port -le 32512 ]; then
            current_port=$start_port
            increment=1
        else
            current_port=$start_port
            increment=-1
        fi

        max_attempts=100 
        attempts=0

        while [ $udp_count -lt $needed_udp_ports ]; do
            if add_port $current_port "udp"; then
                update_port_list
                udp_count=$(echo "$port_list" | grep -c 'udp')
                total_ports=$(echo "$port_list" | grep -c 'udp\|tcp')
            fi

            current_port=$((current_port + increment))
            attempts=$((attempts + 1))

            if [ $attempts -ge $max_attempts ]; then
                echo "Maximum number of attempts exceeded, unable to add enough reserved ports"
                exit 1
            fi
        done

        while [ $tcp_count -lt $needed_tcp_ports ]; do
            if add_port $current_port "tcp"; then
                update_port_list
                tcp_count=$(echo "$port_list" | grep -c 'tcp')
                total_ports=$(echo "$port_list" | grep -c 'udp\|tcp')
            fi

            current_port=$((current_port + increment))
            attempts=$((attempts + 1))

            if [ $attempts -ge $max_attempts ]; then
                echo "Maximum number of attempts exceeded, unable to add enough reserved ports"
                exit 1
            fi
        done
    done

    local port_list=$(devil port list)

    local TMP_UDP_PORT1=$(echo "$port_list" | grep 'udp' | awk 'NR==1{print $1}')
    local TMP_UDP_PORT2=$(echo "$port_list" | grep 'udp' | awk 'NR==2{print $1}')
    local TMP_UDP_PORT3=$(echo "$port_list" | grep 'udp' | awk 'NR==3{print $1}')
    local TMP_TCP_PORT1=$(echo "$port_list" | grep 'tcp' | awk 'NR==1{print $1}')
    local TMP_TCP_PORT2=$(echo "$port_list" | grep 'tcp' | awk 'NR==2{print $1}')
    local TMP_TCP_PORT3=$(echo "$port_list" | grep 'tcp' | awk 'NR==3{print $1}')

    if [ -n "$TMP_UDP_PORT1" ]; then
        PORT1=$TMP_UDP_PORT1
        if [ -n "$TMP_UDP_PORT2" ]; then
            PORT2=$TMP_UDP_PORT2
            if [ -n "$TMP_UDP_PORT3" ]; then
                PORT3=$TMP_UDP_PORT3
            elif [ -n "$TMP_TCP_PORT1" ]; then
                PORT3=$TMP_TCP_PORT1
            fi
        elif [ -n "$TMP_TCP_PORT1" ]; then
            PORT2=$TMP_TCP_PORT1
            if [ -n "$TMP_TCP_PORT2" ]; then
                PORT3=$TMP_TCP_PORT2
            fi
        fi
    elif [ -n "$TMP_TCP_PORT1" ]; then
        PORT1=$TMP_TCP_PORT1
        if [ -n "$TMP_TCP_PORT2" ]; then
            PORT2=$TMP_TCP_PORT2
            if [ -n "$TMP_TCP_PORT3" ]; then
                PORT3=$TMP_TCP_PORT3
            fi
        fi
    fi
    echo -e "Matches the reserved port and assigns it as follows：\n"
    hy2_port=$PORT1
    tuic_port=$PORT2    
    vmess_port=$PORT3
    
    printf "${purple}%-14s\t%-14s\t%-10s\n${re}" Port type Port number Purpose 
    printf "${yellow}%-10s\t%-10s\t%-10s\n${re}" UDP "$hy2_port" "hysteria2"
    printf "${yellow}%-10s\t%-10s\t%-10s\n${re}" UDP "$tuic_port" "tuic"
    printf "${yellow}%-10s\t%-10s\t%-10s\n${re}" TCP "$vmess_port" "vmess"    
    
}

read_nz_variables() {
  if [ -n "$NEZHA_SERVER" ] && [ -n "$NEZHA_PORT" ] && [ -n "$NEZHA_KEY" ]; then
      green "Use the custom variable Nezha to run the Nezha"
      return
  else
      reading "Do I need to install the Nezha?？【y/n】: " nz_choice
      [[ -z $nz_choice ]] && return
      [[ "$nz_choice" != "y" && "$nz_choice" != "Y" ]] && return
      reading "Please enter the Nezha domain name or IP：" NEZHA_SERVER
      green "Your Nezha domain name is: $NEZHA_SERVER"
      reading "Please enter the Nezha probe port (press Enter to skip and use 5555 by default)：" NEZHA_PORT
      [[ -z $NEZHA_PORT ]] && NEZHA_PORT="5555"
      green "Your Nezha port is: $NEZHA_PORT"
      reading "Please enter the Nezha probe key：" NEZHA_KEY
      green "Your Nezha key is: $NEZHA_KEY"
  fi
}

prepare_install(){
  yellow "Testing the installation environment for you, please wait..."
  if [ ! -f "test_permissions.sh" ];then
  cat > test_permissions.sh << EOF
#!/bin/bash 
echo "ok"
EOF
  chmod +x test_permissions.sh
  fi
  
  test=$( ./test_permissions.sh |grep -q ok && echo "yes"||echo "no")
  if [ $test == "no" ];then
    red "Your vps currently does not have the permission to run the program. We are obtaining permission for you, please wait...."
    devil binexec on
    yellow "Permissions have been obtained for you and you will exit later. Please log in to SSH again before installing and deploying.！"
    sleep 3
    killall -u $(whoami)
  else
    green "APP running permission has been turned on"
  fi

}

install_singbox() {
(ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" |awk '{print $2}' | xargs  -r kill -9)> /dev/null 2>&1
echo -e "${yellow}This script coexists with four protocols at the same time${purple}(vmess-ws,vmess-ws-tls(argo),hysteria2,tuic)${re}"
# echo -e "${yellow}Before starting the run, make sure that the panel${purple} has opened 3 ports, one tcp port and two udp ports${re}"
# echo -e "Run your own applications${yellow} in ${yellow} panel${purple}Additional services has been opened to ${purplw}Enabled${yellow} state${re}"

reading "\nAre you sure to continue the installation?？【y/n】: " choice
  case "$choice" in
    [Yy])
        
        cd $WORKDIR
        prepare_install
        read_nz_variables
        # read_vmess_port
        # read_hy2_port
        # read_tuic_port
        reserve_port
        argo_configure
        generate_config
        download_singbox
        get_links
        install_cron
        green "Once deployed, you can have fun playing with it^_^ !"
      ;;
    [Nn]) exit 0 ;;
    *) red "Invalid selection, please enter y or n" && menu ;;
  esac
}

uninstall_singbox() {
  reading "\nAre you sure you want to uninstall?？【y/n】: " choice
    case "$choice" in
        [Yy])
	      (ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" |awk '{print $2}' | xargs  -r kill -9)> /dev/null 2>&1
       	      rm -rf $WORKDIR
              del_cron
	      clear
       	      green “The 4-in-1 has been completely uninstalled”
          ;;
        [Nn]) exit 0 ;;
    	  *) red "Invalid selection, please enter y or n" && menu ;;
    esac
}

kill_all_tasks() {
reading "\nCleaning up all processes will exit the ssh connection. Are you sure you want to continue cleaning?？【y/n】: " choice
  case "$choice" in
    [Yy]) killall -9 -u $(whoami) ;;
       *) menu ;;
  esac
}

# Generating argo Config
argo_configure() {
  if [[ -z $ARGO_AUTH || -z $ARGO_DOMAIN ]]; then
      reading "Do you need to use fixed argo tunnels?？【y/n】: " argo_choice
      [[ -z $argo_choice ]] && return
      [[ "$argo_choice" != "y" && "$argo_choice" != "Y" && "$argo_choice" != "n" && "$argo_choice" != "N" ]] && { red "Invalid selection, please enter y or n"; return; }
      if [[ "$argo_choice" == "y" || "$argo_choice" == "Y" ]]; then
          reading "Please enter the argo fixed tunnel domain name: " ARGO_DOMAIN
          green "Your argo fixed tunnel domain name is: $ARGO_DOMAIN"
          reading "Please enter the argo fixed tunnel key (Json or Token）: " ARGO_AUTH
          green "Your argo fixed tunnel key is: $ARGO_AUTH"
	  echo -e "${red}Note: ${purple} uses token, you need to set the tunnel port in the cloudflare background to be consistent with the tcp port opened by the panel ${re}"
      else
          green "ARGO tunnel variable not set, temporary tunnel will be used"
          return
      fi
  fi

  if [[ $ARGO_AUTH =~ TunnelSecret ]]; then
    echo $ARGO_AUTH > tunnel.json
    cat > tunnel.yml << EOF
tunnel: $(cut -d\" -f12 <<< "$ARGO_AUTH")
credentials-file: tunnel.json
protocol: http2

ingress:
  - hostname: $ARGO_DOMAIN
    service: http://localhost:$vmess_port
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF
  else
    green "ARGO_AUTH mismatch TunnelSecret,use token connect to tunnel"
  fi
}

# Generating Configuration Files
generate_config() {

  openssl ecparam -genkey -name prime256v1 -out "private.key"
  openssl req -new -x509 -days 3650 -key "private.key" -out "cert.pem" -subj "/CN=$USERNAME.serv00.net"

  cat > config.json << EOF
{
  "log": {
    "disabled": true,
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "google",
        "address": "tls://8.8.8.8",
        "strategy": "ipv4_only",
        "detour": "direct"
      }
    ],
    "rules": [
      {
        "rule_set": [
          "geosite-openai"
        ],
        "server": "wireguard"
      },
      {
        "rule_set": [
          "geosite-netflix"
        ],
        "server": "wireguard"
      },
      {
        "rule_set": [
          "geosite-category-ads-all"
        ],
        "server": "block"
      }
    ],
    "final": "google",
    "strategy": "",
    "disable_cache": false,
    "disable_expire": false
  },
    "inbounds": [
    {
       "tag": "hysteria-in",
       "type": "hysteria2",
       "listen": "::",
       "listen_port": $hy2_port,
       "users": [
         {
             "password": "$UUID"
         }
     ],
     "masquerade": "https://bing.com",
     "tls": {
         "enabled": true,
         "alpn": [
             "h3"
         ],
         "certificate_path": "cert.pem",
         "key_path": "private.key"
        }
    },
    {
      "tag": "vmess-ws-in",
      "type": "vmess",
      "listen": "::",
      "listen_port": $vmess_port,
      "users": [
      {
        "uuid": "$UUID"
      }
    ],
    "transport": {
      "type": "ws",
      "path": "/vmess",
      "early_data_header_name": "Sec-WebSocket-Protocol"
      }
    },
    {
      "tag": "tuic-in",
      "type": "tuic",
      "listen": "::",
      "listen_port": $tuic_port,
      "users": [
        {
          "uuid": "$UUID",
          "password": "admin123"
        }
      ],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "alpn": [
          "h3"
        ],
        "certificate_path": "cert.pem",
        "key_path": "private.key"
      }
    }

 ],
    "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    },
    {
      "type": "dns",
      "tag": "dns-out"
    },
    {
      "type": "wireguard",
      "tag": "wireguard-out",
      "server": "162.159.195.100",
      "server_port": 4500,
      "local_address": [
        "172.16.0.2/32",
        "2606:4700:110:83c7:b31f:5858:b3a8:c6b1/128"
      ],
      "private_key": "mPZo+V9qlrMGCZ7+E6z2NI6NOV34PD++TpAR09PtCWI=",
      "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
      "reserved": [
        26,
        21,
        228
      ]
    }
  ],
  "route": {
    "rules": [
      {
        "protocol": "dns",
        "outbound": "dns-out"
      },
      {
        "ip_is_private": true,
        "outbound": "direct"
      },
      {
        "rule_set": [
          "geosite-openai"
        ],
        "outbound": "wireguard-out"
      },
      {
        "rule_set": [
          "geosite-netflix"
        ],
        "outbound": "wireguard-out"
      },
      {
        "rule_set": [
          "geosite-category-ads-all"
        ],
        "outbound": "block"
      }
    ],
    "rule_set": [
      {
        "tag": "geosite-netflix",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-netflix.srs",
        "download_detour": "direct"
      },
      {
        "tag": "geosite-openai",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/openai.srs",
        "download_detour": "direct"
      },      
      {
        "tag": "geosite-category-ads-all",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
        "download_detour": "direct"
      }
    ],
    "final": "direct"
   },
   "experimental": {
      "cache_file": {
      "path": "cache.db",
      "cache_id": "mycacheid",
      "store_fakeip": true
    }
  }
}
EOF
}

# Download Dependency Files
download_singbox() {
  ARCH=$(uname -m) && DOWNLOAD_DIR="." && mkdir -p "$DOWNLOAD_DIR" && FILE_INFO=()
  if [ "$ARCH" == "arm" ] || [ "$ARCH" == "arm64" ] || [ "$ARCH" == "aarch64" ]; then
      FILE_INFO=("https://github.com/eooce/test/releases/download/arm64/sb web" "https://github.com/eooce/test/releases/download/arm64/bot13 bot" "https://github.com/eooce/test/releases/download/ARM/swith npm")
  elif [ "$ARCH" == "amd64" ] || [ "$ARCH" == "x86_64" ] || [ "$ARCH" == "x86" ]; then
           FILE_INFO=("https://github.com/eooce/test/releases/download/freebsd/sb web" "https://github.com/eooce/test/releases/download/freebsd/server bot" "https://github.com/eooce/test/releases/download/freebsd/npm npm")
  else
      echo "Unsupported architecture: $ARCH"
      exit 1
  fi
declare -A FILE_MAP
generate_random_name() {
    local chars=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890
    local name=""
    for i in {1..6}; do
        name="$name${chars:RANDOM%${#chars}:1}"
    done
    echo "$name"
}

for entry in "${FILE_INFO[@]}"; do
    URL=$(echo "$entry" | cut -d ' ' -f 1)
    RANDOM_NAME=$(generate_random_name)
    NEW_FILENAME="$DOWNLOAD_DIR/$RANDOM_NAME"
    
    if [ -e "$NEW_FILENAME" ]; then
        green "$NEW_FILENAME already exists, Skipping download"
    else
        wget -q --show-progress -c "$URL" -O "$NEW_FILENAME"
        green "Downloading $NEW_FILENAME"
    fi
    chmod +x "$NEW_FILENAME"
    FILE_MAP[$(echo "$entry" | cut -d ' ' -f 2)]="$NEW_FILENAME"
done
wait

if [ -e "$(basename ${FILE_MAP[npm]})" ]; then
    tlsPorts=("443" "8443" "2096" "2087" "2083" "2053")
    if [[ "${tlsPorts[*]}" =~ "${NEZHA_PORT}" ]]; then
      NEZHA_TLS="--tls"
    else
      NEZHA_TLS=""
    fi
    if [ -n "$NEZHA_SERVER" ] && [ -n "$NEZHA_PORT" ] && [ -n "$NEZHA_KEY" ]; then
        export TMPDIR=$(pwd)
        nohup ./"$(basename ${FILE_MAP[npm]})" -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} >/dev/null 2>&1 &
        sleep 2
        pgrep -x "$(basename ${FILE_MAP[npm]})" > /dev/null && green "$(basename ${FILE_MAP[npm]}) is running" || { red "$(basename ${FILE_MAP[npm]}) is not running, restarting..."; pkill -x "$(basename ${FILE_MAP[npm]})" && nohup ./"$(basename ${FILE_MAP[npm]})" -s "${NEZHA_SERVER}:${NEZHA_PORT}" -p "${NEZHA_KEY}" ${NEZHA_TLS} >/dev/null 2>&1 & sleep 2; purple "$(basename ${FILE_MAP[npm]}) restarted"; }
    else
        purple "NEZHA variable is empty, skipping running"
    fi
fi

if [ -e "$(basename ${FILE_MAP[web]})" ]; then
    nohup ./"$(basename ${FILE_MAP[web]})" run -c config.json >/dev/null 2>&1 &
    sleep 2
    pgrep -x "$(basename ${FILE_MAP[web]})" > /dev/null && green "$(basename ${FILE_MAP[web]}) is running" || { red "$(basename ${FILE_MAP[web]}) is not running, restarting..."; pkill -x "$(basename ${FILE_MAP[web]})" && nohup ./"$(basename ${FILE_MAP[web]})" run -c config.json >/dev/null 2>&1 & sleep 2; purple "$(basename ${FILE_MAP[web]}) restarted"; }
fi

if [ -e "$(basename ${FILE_MAP[bot]})" ]; then
    if [[ $ARGO_AUTH =~ ^[A-Z0-9a-z=]{120,250}$ ]]; then
      args="tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${ARGO_AUTH}"
    elif [[ $ARGO_AUTH =~ TunnelSecret ]]; then
      args="tunnel --edge-ip-version auto --config tunnel.yml run"
    else
      args="tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile boot.log --loglevel info --url http://localhost:$vmess_port"
    fi
    nohup ./"$(basename ${FILE_MAP[bot]})" $args >/dev/null 2>&1 &
    sleep 2
    pgrep -x "$(basename ${FILE_MAP[bot]})" > /dev/null && green "$(basename ${FILE_MAP[bot]}) is running" || { red "$(basename ${FILE_MAP[bot]}) is not running, restarting..."; pkill -x "$(basename ${FILE_MAP[bot]})" && nohup ./"$(basename ${FILE_MAP[bot]})" "${args}" >/dev/null 2>&1 & sleep 2; purple "$(basename ${FILE_MAP[bot]}) restarted"; }
fi
sleep 5
#rm -f "$(basename ${FILE_MAP[npm]})" "$(basename ${FILE_MAP[web]})" "$(basename ${FILE_MAP[bot]})"
cat > app_map.json << EOF
{
  "bot":"${FILE_MAP[bot]}",
  "web":"${FILE_MAP[web]}",
  "npm":"${FILE_MAP[npm]}",
  "argo_auth":"${ARGO_AUTH}"
}
EOF
}

get_ip() {
ip=$(curl -s --max-time 2 ipv4.ip.sb)
if [ -z "$ip" ]; then
    if [[ "$HOSTNAME" =~ s[0-9]\.serv00\.com ]]; then
        ip=${HOSTNAME/s/web}
    else
        ip="$HOSTNAME"
    fi
fi
echo $ip
}

get_argodomain() {
  if [[ -n $ARGO_AUTH ]]; then
    echo "$ARGO_DOMAIN"
  else
    grep -oE 'https://[[:alnum:]+\.-]+\.trycloudflare\.com' boot.log | sed 's@https://@@'
  fi
}

get_links(){
argodomain=$(get_argodomain)
echo -e "\e[1;32mArgoDomain:\e[1;35m${argodomain}\e[0m\n"
sleep 1
IP=$(get_ip)
ISP=$(curl -s https://speed.cloudflare.com/meta | awk -F\" '{print $26"-"$18}' | sed -e 's/ /_/g') 
sleep 1
yellow "Note: The skip certificate verification of v2ray or other software needs to be set to true, otherwise the hy2 or tuic node may be blocked\n"
cat > list.txt <<EOF
vmess://$(echo "{ \"v\": \"2\", \"ps\": \"$ISP\", \"add\": \"$IP\", \"port\": \"$vmess_port\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"\", \"path\": \"/vmess?ed=2048\", \"tls\": \"\", \"sni\": \"\", \"alpn\": \"\", \"fp\": \"\"}" | base64 -w0)

vmess://$(echo "{ \"v\": \"2\", \"ps\": \"$ISP\", \"add\": \"$CFIP\", \"port\": \"$CFPORT\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/vmess?ed=2048\", \"tls\": \"tls\", \"sni\": \"$argodomain\", \"alpn\": \"\", \"fp\": \"\"}" | base64 -w0)

hysteria2://$UUID@$IP:$hy2_port/?sni=www.bing.com&alpn=h3&insecure=1#$ISP

tuic://$UUID:admin123@$IP:$tuic_port?sni=www.bing.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#$ISP
EOF
cat list.txt
purple "\n$WORKDIR/list.txt saved successfully"
purple "Running done!"
sleep 2
rm -rf boot.log sb.log 
}

CRON_CMD="/bin/bash $WORKDIR/checksb.sh" 

get_timer() {
    while true; do
        reading "Please enter the timing minutes (0~59,${yellow}Note: Enter 0 to cancel the timing ${re}${red}): " time_out
        if [[ "$time_out" =~ ^[0-9]+$ ]] && [ "$time_out" -ge -1 ] && [ "$time_out" -le 60 ]; then
            green "Your timed minutes are: $time_out"
            if [ $time_out == "0" ];then
              yellow "If you have already set a timer, the following will cancel the timer detection running status for you."
            fi
            break
        else
            yellow "Input error, please re-enter the minutes (0~59)"
        fi
    done
}


del_cron(){
  (crontab -l | grep -v -F "* * $CRON_CMD")| crontab -
  rm -f /usr/home/$USER/logs/checksb.log  
}

add_cron(){
  (crontab -l; echo "*/$time_out * * * * $CRON_CMD") | crontab -
}

create_cron(){
  local path=$(pwd)  
  cd $WORKDIR
  get_timer  
  if [ ! -f ./checksb.sh ];then  
  yellow "Downloading checksb.sh "
  wget -q --show-progress -c https://raw.githubusercontent.com/sunq945/Sing-box/main/checksb.sh -O checksb.sh 
  chmod +x checksb.sh   
  fi
  green "Downloading checksb.sh is completed and crontab is being set up...." 
  cron_record=$(crontab -l | grep -F "* * $CRON_CMD")
  if [ -z "$cron_record" ];then
    if [ $time_out != "0" ];then
      add_cron
      green "Set the scheduled detection running status successfully"
    fi
  else
    #echo $cron_record
    if [  $time_out != "0" ];then
      r_time=$(echo ${cron_record:2}| awk -F' ' '{print $1}')
      if [ $r_time != $time_out ] ;then        
        del_cron
        add_cron
        green "Modification of scheduled detection running status successful"
      else
        purple "This scheduled task already exists, no need to set it up"
      fi
    else
      del_cron
      green "Cancel scheduled detection running status successfully"
    fi

  fi
  cd $path
} 

install_cron(){
    reading "\nDo you need to set up scheduled detection of running status?？【y/n】: " choice
    case "$choice" in
        [Yy])
	        create_cron ;;
        [Nn]) exit 0 ;;
    	  *) red "Invalid selection, please enter y or n" && menu ;;
    esac
}


menu() {
   clear
   echo ""
   purple "=== (Serv00|ct8) sing-box一key installation script v1.0.2 ===\n"
   echo -e "${green}Script address：${re}${yellow}https://github.com/sun945/Sing-box${re}\n"
   echo -e "Original script address：https://github.com/eooce/Sing-box\n"
   echo -e "KOLAND (I only translated the script.)：https://t.me/KOLANDJS\n"   

   purple "Please reprint with a well-known source, please do not abuse\n"
   green "1. Install sing-box"
   echo  "========================="
   red "2. Uninstall sing-box"
   echo  "========================="
   green "3. View node information"
   echo  "========================="
   green "4. Set up scheduled detection running status？"
   echo  "========================="
   yellow "5. Clean all processes"
   echo  "========================="
   red "0. Exit script"
   echo  "========================="
   reading "Please enter your choice(0-5): " choice
   echo ""
    case "${choice}" in
        1) install_singbox ;;
        2) uninstall_singbox ;; 
        3) cat $WORKDIR/list.txt ;; 
        4) create_cron ;;
        5) kill_all_tasks ;;
        0) exit 0 ;;
        *) red "Invalid option, please enter 0 to 5" ;;
    esac
}
menu
