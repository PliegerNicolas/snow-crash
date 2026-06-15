#! /usr/bin/env sh

CURR_FILE_PATH="$(realpath "$0")"
CURR_DIR_PATH="$(dirname "$CURR_FILE_PATH")"

#############
### UTILS ###
#############

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*";
}

char_to_decimal() {
    char="$1";

    case "$char" in
        ?)
            printf "%d" "'$char";
            ;;
        *)
            log "Error: char_to_decimal: invalid char value: $char" >&2;
            return 1;
            ;;
    esac
}

decimal_to_char() {
    decimal="$1";

    case "$decimal" in
        '' | *[!0-9]*)
            log "Error: decimal_to_char: invalid decimal value: $decimal" >&2;
            return 1;
            ;;
        *)
            printf "%b" "\\$(printf '%03o' "$decimal")";
            ;;
    esac
}


decode() {
    encoded_str="$1";
    decoded_str="";

    if [ -z "$encoded_str" ]; then
        log "Error: decode: missing encoded string" >&2;
        return 1;
    fi

    char_shift=0;
    while [ ! -z "$encoded_str" ]; do
        char="${encoded_str%${encoded_str#?}}"; # Get first char.
        encoded_str="${encoded_str#?}"; # Strip first char.

        decimal_char=$(char_to_decimal "$char");
        normalized_decimal_char=$(((decimal_char - char_shift % 128 + 128) % 128));
        shifted_char=$(decimal_to_char $normalized_decimal_char);

        decoded_str="${decoded_str}${shifted_char}";

        char_shift=$((char_shift + 1));
    done

    echo "$decoded_str";
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

    level09_socket_path=$(get_ssh_socket_path "snowcrash_level09_socket") || exit 1;
    level09_username="level09";
    level09_password=$(cat "$CURR_DIR_PATH/../../level08/flag");

    flag09_socket_path=$(get_ssh_socket_path "snowcrash_flag09_socket") || exit 1;
    flag09_username="flag09";
    flag09_password="";

    init_ssh_socket "$level09_socket_path" "$host" "$port" "$level09_username" "$level09_password";
    encoded_token=$(ssh_exec_via_socket "$level09_socket_path" "$host" "$port" "$level09_username" "cat /home/user/level09/token");
    close_ssh_socket "$level09_socket_path" "$host" "$port" "$level09_username";

    decoded_token=$(decode $encoded_token);
    flag09_password="$decoded_token";

    init_ssh_socket "$flag09_socket_path" "$host" "$port" "$flag09_username" "$flag09_password";
    checkflag_str=$(ssh_exec_via_socket "$flag09_socket_path" "$host" "$port" "$flag09_username" "getflag");
    checkflag=$(echo -n "$checkflag_str" | head -n 1 | awk  '{print $NF}');
    close_ssh_socket "$flag09_socket_path" "$host" "$port" "$flag09_username";

    flag_outpath="$CURR_DIR_PATH/../flag";
    echo "Checkflag: $checkflag";
    echo -n "$checkflag" > "$flag_outpath";
}

main "$@";
