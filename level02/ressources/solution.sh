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

tshark_extract_tcp_payload() {
    assert_docker;
    input_pcap_file="$1";

    if [ -z "$input_pcap_file" ]; then
        log "Error: tshark_extract_tcp_payload: missing input pcap file path" >&2;
        return 1;
    elif [ ! -f "$input_pcap_file" ]; then
        log "Error: tshark_extract_tcp_payload: input pcap file not found: $input_pcap_file" >&2;
        return 1;
    fi

    hex_output=$(docker run --rm -v "$input_pcap_file:/in.pcap:ro" docker.io/parrotsec/tshark:latest -r "/in.pcap" -Y "tcp.payload && tcp.stream==0" -T fields -e tcp.payload);
    echo "$hex_output";
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

ssh_download_via_socket() {
    fn_name="ssh_download_via_socket";
    ssh_socket_path="$1";
    host="$2";
    port="$3";
    username="$4";
    path_to_remote_file="$5";
    local_path_to_save="$6";

    if [ -z "$ssh_socket_path" ] || [ -z "$host" ] || [ -z "$port" ] || [ -z "$username" ] || [ -z "$local_path_to_save" ] || [ -z "$path_to_remote_file" ]; then
        log "Error: ${fn_name}: missing arguments. You should provide <ssh_socket_path> <host> <port> <username> <path/to/remote/file> </local/path/to/save/> [options...]." >&2;
        return 1;
    fi

    shift 6;

    scp -o "ControlPath=${ssh_socket_path}" -P "$port" "$@" "$username@$host:$path_to_remote_file" "$local_path_to_save";
    return $?;
}

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

    init_ssh_socket "$level02_socket_path" "$host" "$port" "$level02_username" "$level02_password" || exit 1;
    pcap_tmp_file=$(mktemp /tmp/level02_XXXXXX.pcap);
    ssh_exec_via_socket "$level02_socket_path" "$host" "$port" "$level02_username" "cat level02.pcap" > "$pcap_tmp_file" || exit 1;
    hex_tcp_traffic=$(tshark_extract_tcp_payload "$pcap_tmp_file");
    rm -f "$pcap_tmp_file";
    close_ssh_socket "$level02_socket_path" "$host" "$port" "$level02_username";

    ascii_tcp_traffic=$(echo "$hex_tcp_traffic" | xxd -r -p | tr -d '\000');
    flag02_password=$(printf '%s' "$ascii_tcp_traffic" | grep "Password: " | head -n 1 | awk  '{print $NF}');

    init_ssh_socket "$flag02_socket_path" "$host" "$port" "$flag02_username" "$flag02_password" || exit 1;
    checkflag_str=$(ssh_exec_via_socket "$flag02_socket_path" "$host" "$port" "$flag02_username" "getflag");
    checkflag=$(echo -n "$checkflag_str" | head -n 1 | awk  '{print $NF}');
    close_ssh_socket "$flag02_socket_path" "$host" "$port" "$flag02_username";

    flag_outpath="$CURR_DIR_PATH/../flag";
    echo "Checkflag: $checkflag";
    echo -n "$checkflag" > "$flag_outpath";
}

main "$@";
