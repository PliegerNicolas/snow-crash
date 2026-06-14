#! /usr/bin/env sh

CURR_FILE_PATH="$(realpath "$0")"
CURR_DIR_PATH="$(dirname "$CURR_FILE_PATH")"

#############
### UTILS ###
#############

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*";
}

is_upper_char() {
    case "$1" in
        [A-Z]) return 0 ;;
        *) return 1 ;;
    esac
}

is_lower_char() {
    case "$1" in
        [a-z]) return 0 ;;
        *) return 1 ;;
    esac
}

rotn() {
    fn_name="rotn";
    str="${1:-}";
    n="${2:-0}";
    dir="${3:-+}";

    if ! [ "$n" -eq "$n" ] 2>/dev/null; then
        log "Error: ${fn_name}: second argument should be a number" >&2;
        return 1;
    fi

    if [ "$dir" != "+" ] && [ "$dir" != "-" ]; then
        log "Error: ${fn_name}: third argument should be one of ['+', '-']" >&2;
        return 1;
    fi

    n=$((n % 26)); # Wrap around the alphabet.

    if [ -z "$str" ] || [ "$n" -eq 0 ]; then
        echo $str
        return 0;
    fi

    shifted_str="";

    for char in $(echo -n "$str" | fold -w1); do
        shifted_char="$char"
        char_ascii=$(printf "%d" "'$char");
        if is_upper_char "$char"; then
            if [ "dir" = "+" ]; then
                shifted_char_ascii=$(( (char_ascii - 65 + n) % 26 + 65 ))
            else
                shifted_char_ascii=$(( (char_ascii - 65 - n + 26) % 26 + 65 ))
            fi
            shifted_char=$(printf "\\$(printf "%o" "$shifted_char_ascii")")
        elif is_lower_char "$char"; then
            if [ "dir" = "+" ]; then
                shifted_char_ascii=$(( (char_ascii - 97 + n) % 26 + 97 ))
            else
                shifted_char_ascii=$(( (char_ascii - 97 - n + 26) % 26 + 97 ))
            fi
            shifted_char=$(printf "\\$(printf "%o" "$shifted_char_ascii")")
        fi
        shifted_str="${shifted_str}${shifted_char}"
    done

    echo $shifted_str;
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
    host="localhost";
    port="4242"; # cf. port forwarding to VM 4242 => 4242.

    level00_socket_path=$(get_ssh_socket_path "snowcrash_level00_socket") || exit 1;
    level00_username="level00";
    level00_password="level00";

    flag00_socket_path=$(get_ssh_socket_path "snowcrash_flag00_socket") || exit 1;
    flag00_username="flag00";
    flag00_password="";

    init_ssh_socket "$level00_socket_path" "$host" "$port" "$level00_username" "$level00_password" || exit 1;
    flag00_password=$(
        flag00_owned_readable_files=$(ssh_exec_via_socket "$level00_socket_path" "$host" "$port" "$level00_username" "find / -user flag00 -perm -o=r 2>/dev/null");
        flag00_cyphered_password_filename=$(echo "$flag00_owned_readable_files" | grep "/usr/sbin/" |head -n 1);
        flag00_cyphered_password=$(ssh_exec_via_socket "$level00_socket_path" "$host" "$port" "$level00_username" "cat ${flag00_cyphered_password_filename}");
        # Le MDP est stocké dans un fichier lisible mais encrypté (pas hashé).
        # En usant du site: "https://www.dcode.fr/chiffre-cesar" on découvre qu'il s'agit d'un chiffrement césar, aussi dit rot-n.
        flag00_password=$(rotn "$flag00_cyphered_password" 15 "+");
        echo "$flag00_password";
    );
    close_ssh_socket "$level00_socket_path" "$host" "$port" "$level00_username";

    init_ssh_socket "$flag00_socket_path" "$host" "$port" "$flag00_username" "$flag00_password" || exit 1;
    checkflag=$(
        checkflag_str=$(ssh_exec_via_socket "$flag00_socket_path" "$host" "$port" "$flag00_username" "getflag");
        checkflag=$(echo -n "$checkflag_str" | head -n 1 | awk  '{print $NF}');
        echo "$checkflag";
    );
    close_ssh_socket "$flag00_socket_path" "$host" "$port" "$flag00_username";

    flag_outpath="$CURR_DIR_PATH/../flag";
    echo "Checkflag: $checkflag";
    echo -n "$checkflag" > "$flag_outpath";
}

main "$@";
