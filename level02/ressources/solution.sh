#! /usr/bin/env sh

CURR_FILE_PATH="$(realpath "$0")"
CURR_DIR_PATH="$(dirname "$CURR_FILE_PATH")"

#############
### UTILS ###
#############

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*";
}

##############
### DOCKER ###
##############

assert_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        log "Error: the 'docker' command is required. Considering installing the docker from https://docs.docker.com/engine/install.";
        exit 1;
    fi
}

###########
### SSH ###
###########

get_ssh_socket_path() {
    fn_name="get_ssh_socket_path";
    socket_name="$1";

    if [ -z "$socket_name" ]; then
        log "Error: ${fn_name}: missing socket name" >&2;
        return 1;
    fi

    echo "${HOME}/.ssh/${socket_name}";
}

init_ssh_socket() {
    fn_name="init_ssh_socket";
    ssh_socket_path="$1";
    host="$2";
    port="$3";
    username="$4";
    password="$5";

    if [ -z "$ssh_socket_path" ] || [ -z "$host" ] || [ -z "$port" ] || [ -z "$username" ] || [ -z "$password" ]; then
        log "Error: ${fn_name}: missing arguments. You should provide <ssh_socket_path> <host> <port> <username> <password>." >&2;
        return 1;
    fi

    if [ -S "$ssh_socket_path" ]; then
            if ssh -S "$ssh_socket_path" -O check "$host" -p "$port" >/dev/null 2>&1; then
                return 0;
            else
                rm -f "$ssh_socket_path";
            fi
    fi

    sshpass -p "$password" ssh -fNMS "$ssh_socket_path" -p "$port" "${username}@${host}"
    return $?;
}

close_ssh_socket() {
    fn_name="close_ssh_socket";
    ssh_socket_path="$1";
    host="$2";
    port="$3";
    username="$4";

    if [ -z "$ssh_socket_path" ] || [ -z "$host" ] || [ -z "$port" ] || [ -z "$username" ]; then
        log "Error: ${fn_name}: missing arguments. You should provide <ssh_socket_path> <host> <port> <username>." >&2;
        return 1;
    fi

    if ! [ -S "$ssh_socket_path" ]; then
        return 0;
    fi

    ssh -S "$ssh_socket_path" -O exit -p "$port" "${username}@${host}";
    exit_code=$?;
    rm -f "$ssh_socket_path";
    return $exit_code;
}

ssh_exec_via_socket() {
    fn_name="ssh_exec_via_socket";
    ssh_socket_path="$1";
    host="$2";
    port="$3";
    username="$4";

    if [ -z "$ssh_socket_path" ] || [ -z "$host" ] || [ -z "$port" ] || [ -z "$username" ]; then
        log "Error: ${fn_name}: missing arguments. You should provide <ssh_socket_path> <host> <port> <username>." >&2;
        return 1;
    fi

    shift 4;

    if [ $# -eq 0 ]; then
        return 0
    fi

    ssh -S "$ssh_socket_path" -p "$port" "$username@$host" "$@";
    return $?;
}

############
### MAIN ###
############

main() {
    assert_docker;

    host="localhost";
    port="4242"; # cf. port forwarding to VM 4242 => 4242.

    level02_socket_path=$(get_ssh_socket_path "snowcrash_level02_socket") || exit 1;
    level02_username="level02";
    level02_password=$(cat "$CURR_DIR_PATH/../../level01/flag");

    flag02_socket_path=$(get_ssh_socket_path "snowcrash_flag02_socket") || exit 1;
    flag02_username="flag02";
    flag02_password="";

    tshark_symlink_path="$CURR_DIR_PATH/tshark";
    tshark_pcap_path="$tshark_symlink_path/pcap/in.pcap";

    init_ssh_socket "$level02_socket_path" "$host" "$port" "$level02_username" "$level02_password" || exit 1;
    scp -o "ControlPath=$level02_socket_path" "$level02_username@$host:~/level02.pcap" "$tshark_pcap_path";
    close_ssh_socket "$level02_socket_path" "$host" "$port" "$level02_username";
    flag02_password=$("$tshark_symlink_path/tshark.sh" --hexdump-tcp "$CURR_DIR_PATH/tshark/pcap/in.pcap" | xxd -r -p | grep -a "Password: " | head -n 1 | awk '{print $NF}')

    init_ssh_socket "$flag02_socket_path" "$host" "$port" "$flag02_username" "$flag02_password" || exit 1;
    checkflag=$(ssh_exec_via_socket "$flag02_socket_path" "$host" "$port" "$flag02_username" "getflag" | head -n 1 | awk  '{print $NF}');
    close_ssh_socket "$flag02_socket_path" "$host" "$port" "$flag02_username";

    flag_outpath="$CURR_DIR_PATH/../flag";
    echo "Checkflag: $checkflag";
    echo -n "$checkflag" > "$flag_outpath";
}

main "$@";
