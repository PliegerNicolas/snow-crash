#! /usr/bin/env sh

REMOTE_HOST="${REMOTE_HOST:-localhost}"
REMOTE_PORT="${REMOTE_PORT:-4242}"
REMOTE_USER="${REMOTE_USER:-level00}"
REMOTE_PASSWORD="${REMOTE_PASSWORD:-level00}"

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
    str="${1:-}";
    n="${2:-0}";
    dir="${3:-+}";

    if ! [ "$n" -eq "$n" ] 2>/dev/null; then
        log "Error: second argument should be a number" >&2;
        return 1;
    fi

    if [ "$dir" != "+" ] && [ "$dir" != "-" ]; then
        log "Error: third argument should be one of ['+', '-']" >&2;
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

ssh_exec() {
    username="$1"
    password="$2"
    shift 2;

    if [ -z "$username" ]; then
        log "Error: missing username" >&2;
        return 1;
    fi
    if [ -z "$password" ]; then
        log "Error: missing password" >&2;
        return 1;
    fi

    sshpass -p "$password" ssh -p "${REMOTE_PORT}" "${username}@${REMOTE_HOST}" "$@"
}

main() {
    # On scan les fichiers détenus par la cible (user flag00) et quels fichiers à lui sont lisibles.
    flag00_owned_readable_files=$(ssh_exec "level00" "level00" "find / -user flag00 -perm -o=r 2>/dev/null");
    flag00_cyphered_password_filename=$(echo "$flag00_owned_readable_files" | head -n 1);
    flag00_cyphered_password=$(ssh_exec "level00" "level00" "cat ${flag00_cyphered_password_filename}");
    # Le MDP est stocké dans un fichier lisible mais encrypté (pas hashé).
    # En usant du site: "" on découvre qu'il s'agit d'un chiffrement caesar (rot-n).
    flag00_password=$(rotn "$flag00_cyphered_password" 15 "+");
    
    # On login et execute getflag pour obtenir le MDP de level01 et on le sauvegarde localement.
    check_flag_str=$(ssh_exec "flag00" "$flag00_password" "getflag");
    check_flag=$(echo -n "$check_flag_str" | head -n 1 | awk  '{print $NF}');
    
    checkflag_file_path="$CURR_DIR_PATH/../flag";
    echo -n "$check_flag" > "$checkflag_file_path";
    chmod 640 "$checkflag_file_path"
}

main "$@";
