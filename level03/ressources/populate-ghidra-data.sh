#!/usr/bin/env sh

CURR_FILE_PATH="$(realpath "$0")"
CURR_DIR_PATH="$(dirname "$CURR_FILE_PATH")"

#############
### UTILS ###
#############

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*";
}

###########
### SSH ###
###########

ssh_download() {
    fn_name="ssh_download"
    host="$1";
    port="$2";
    username="$3";
    password="$4";
    path_to_remote_file="$5";
    local_path_to_save="$6";

    shift 6;

    if [ -z "$host" ] || [ -z "$port" ] || [ -z "$username" ] || [ -z "$password" ] || [ -z "$path_to_remote_file" ] || [ -z "$local_path_to_save" ]; then
        log "Error: ${fn_name}: missing arguments. You should provide <host> <port> <username> <password> <path/to/remote/file> </local/path/to/save/> [options...]." >&2;
        return 1;
    fi

    sshpass -p "$password" scp -P "$port" "$username@$host:$path_to_remote_file" "$local_path_to_save" || return 1;
    return 0;
}

############
### MAIN ###
############

main() {
    host="localhost";
    port="4242";
    level03_username="level03";
    level03_password=$(cat "$CURR_DIR_PATH/../../level02/flag");

    ssh_download "$host" "$port" "$level03_username" "$level03_password" "~/level03" "$CURR_DIR_PATH/ghidra/data/level03" || return 1;
}

main "$@";
