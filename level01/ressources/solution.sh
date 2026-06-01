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

hashcat_identify_hash_algorythm() {
    hash="$1";

    assert_docker;
    docker run --rm dizcza/docker-hashcat:pocl --interactive -- hashcat --identify "$hash";
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

    # As the initial setup is similar to what we hd 

    trap 'close_ssh_socket "$level01_socket_path" "$host" "$port" "$level01_username"' EXIT;
    init_ssh_socket "$level01_socket_path" "$host" "$port" "$level01_username" "$level01_password" || exit 1;
    flag01_password=$(

    );

    # flag00_socket_path=$(get_ssh_socket_path "snowcrash_flag00_socket") || exit 1;
    # flag00_username="flag00";
    # flag00_password="";

    # trap 'close_ssh_socket "$level00_socket_path" "$host" "$port" "$level00_username"' EXIT;
    # init_ssh_socket "$level00_socket_path" "$host" "$port" "$level00_username" "$level00_password" || exit 1;
    # flag00_password=$(
    #     flag00_owned_readable_files=$(ssh_exec_via_socket "$ssh_socket_path" "$host" "$port" "$level00_username" "find / -user flag00 -perm -o=r 2>/dev/null");
    #     flag00_cyphered_password_filename=$(echo "$flag00_owned_readable_files" | grep "/usr/sbin/" |head -n 1);
    #     flag00_cyphered_password=$(ssh_exec_via_socket "$ssh_socket_path" "$host" "$port" "$level00_username" "cat ${flag00_cyphered_password_filename}");
    #     # Le MDP est stocké dans un fichier lisible mais encrypté (pas hashé).
    #     # En usant du site: "https://www.dcode.fr/chiffre-cesar" on découvre qu'il s'agit d'un chiffrement césar, aussi dit rot-n.
    #     flag00_password=$(rotn "$flag00_cyphered_password" 15 "+");
    #     echo "$flag00_password";

    #     ssh_exec_via_socket "$ssh_socket_path" "$host" "$port" "$level00_username" "su - flag00";
    # )
    # close_ssh_socket "$level00_socket_path" "$host" "$port" "$level00_username";

    # trap 'close_ssh_socket "$flag00_socket_path" "$host" "$port" "$flag00_username"' EXIT;
    # init_ssh_socket "$flag00_socket_path" "$host" "$port" "$flag00_username" "$flag00_password" || exit 1;
    # checkflag_str=$(ssh_exec_via_socket "$ssh_socket_path" "$host" "$port" "$flag00_username" "getflag");
    # checkflag=$(echo -n "$checkflag_str" | head -n 1 | awk  '{print $NF}');
    # close_ssh_socket "$flag00_socket_path" "$host" "$port" "$flag00_username"

    # flag_outpath="$CURR_DIR_PATH/../flag";
    # echo "$checkflag" > $flag_outpath;
}

main "$@";
