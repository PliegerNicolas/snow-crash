#!/usr/bin/env sh

CURR_FILE_PATH="$(realpath "$0")"
CURR_DIR_PATH="$(dirname "$CURR_FILE_PATH")"
HASHCAT_DOCKER_IMAGE="docker.io/dizcza/docker-hashcat:pocl"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*";
}

###############
### ASSERTS ###
###############

assert_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        log "Error: the 'docker' command is required. Considering installing Docker from https://www.docker.com/products/docker-desktop.";
        exit 1;
    fi
}

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

#############
### UTILS ###
#############

is_url() {
    case "$1" in
        http://*|https://*) return 0 ;;
        *) return 1 ;;
    esac
}

download_and_extract_wordlists() {
    wordlists_dir="$1"; shift 1;

    if [ ! -d "$wordlists_dir" ]; then
        log "Error: download_and_extract_wordlists: wordlists directory not found: $wordlists_dir" >&2;
        return 1;
    fi

    for wordlist_url in "$@"; do
        if ! is_url "$wordlist_url"; then
            log "Error: download_and_extract_wordlists: invalid wordlist url: $wordlist_url" >&2;
            continue;
        fi
        log "Downloading wordlist(s) from $wordlist_url to $wordlists_dir";

        filename="$(basename "$wordlist_url")";
        filepath="$wordlists_dir/$filename";

        if ! curl -L "$wordlist_url" -o "$filepath" --silent --show-error --fail; then
            log "Error: download_and_extract_wordlists: failed to download wordlist from $wordlist_url" >&2;
            continue;
        fi

        case "$filepath" in
            *.gz)
                assert_gzip;
                if ! gzip -d -f "$filepath"; then
                    log "Error: download_and_extract_wordlists: failed to extract wordlist from $filepath" >&2;
                    rm -f "$filepath";
                    continue;
                fi
                rm -f "$filepath";
                ;;
            *.zip)
                assert_unzip;
                if ! unzip -o "$filepath" -d "$wordlists_dir"; then
                    log "Error: download_and_extract_wordlists: failed to extract wordlist from $filepath" >&2;
                    rm -f "$filepath";
                    continue;
                fi
                rm -f "$filepath";
                ;;
            *)
                ;;
        esac
    done
}

resolve_wordlists() {
    wordlists_dir="$1";

    if [ ! -d "$wordlists_dir" ]; then
        log "Error: resolve_wordlists: wordlists directory not found: $wordlists_dir" >&2;
        return 1;
    fi

    wordlist_files=""
    for wordlist_file in "$wordlists_dir"/*; do
        [ -f "$wordlist_file" ] || continue;
        case "$wordlist_file" in
            *[!a-zA-Z0-9._/-]*)
                log "Error: invalid wordlist file name: $wordlist_file" >&2
                continue;
                ;;
        esac;
        wordlist_files="${wordlist_files} ${wordlist_file}";
    done

    echo $wordlist_files;
}

get_last_cracked_hash() {
    cracked_hashes_file="$1";

    if [ ! -f "$cracked_hashes_file" ]; then
        log "Error: get_last_cracked_hash: missing cracked hashes file path" >&2;
        return 1;
    fi

    cat "$cracked_hashes_file" | tail -n 1 | cut -d: -f2;
}

##############
### DOCKER ###
##############

identify_hash() {
    assert_docker;

    hash="$1"; shift;

    if [ -z "$hash" ]; then
        log "Error: identify_hash: missing hash to identify" >&2;
        return 1;
    fi

    docker run --rm -it $HASHCAT_DOCKER_IMAGE hashcat --identify "$hash";
    return $?;
}

crack_hash() {
    assert_docker;

    hash="$1"; shift;
    cache="$1"; shift;
    cracked_hashes_dir="$CURR_DIR_PATH/cracked_hashes";

    if [ -z "$hash" ]; then
        log "Error: crack_hash: missing hash to crack" >&2;
        return 1;
    fi

    if [ -z "$cache" ]; then
        log "Error: crack_hash: missing cache argument" >&2;
        return 1;
    fi

    if [ ! -d "$cracked_hashes_dir" ]; then
        log "Error: crack_hash: cracked hashes directory not found: $cracked_hashes_dir" >&2;
        return 1;
    fi

    wordlists=$(resolve_wordlists "$CURR_DIR_PATH/wordlists");
    docker_mapped_wordlists=$(for wordlist in $wordlists; do echo -n "/wordlists/$(basename "$wordlist") "; done);
    docker_mapped_wordlist_volumes=$(for wordlist in $wordlists; do echo -n "--volume $wordlist:/wordlists/$(basename "$wordlist")"; done);

    if [ "$cache" != true ] || [ ! -f "$cracked_hashes_dir/cracked.txt" ]; then
        log "Attempting to crack the following hash: $hash. This might take a while..." >&2;
        log "WARNING: We enforce --attack-mode 3 as we are in the context of an exercice. The container might not work on some machines without it." >&2
        docker run --rm -it \
            $docker_mapped_wordlist_volumes \
            --volume "$cracked_hashes_dir:/out:rw" \
            $HASHCAT_DOCKER_IMAGE hashcat -o /out/cracked.txt --attack-mode 3 "$hash" $docker_mapped_wordlists \
        >&2;
    fi

    last_cracked_hash=$(get_last_cracked_hash "$cracked_hashes_dir/cracked.txt");
    if [ "$cache" != true ]; then
        rm -f "$cracked_hashes_dir/cracked.txt";
    fi
    echo "$last_cracked_hash";
}

start_hashcat_docker_container() {
    assert_docker;
    docker run --rm -it $HASHCAT_DOCKER_IMAGE sh;
}

############
### MAIN ###
############

main() {
    assert_docker;
    assert_gzip;
    assert_unzip;

    if [ "$#" -eq 0 ]; then
        echo "Usage: $0 [OPTIONS]";
        echo "Options:";
        echo "  -i, --identify  [HASH]  Identify the used encryption algorithm, also said the hash type.";
        echo "  -c, --crack     [HASH]  Crack the hash";
        echo "  -s, --start             Start the docker container";
        return 0;
    fi

    while [ -n "$1" ]; do
        option="$1"; shift;

        case "$option" in
            -i|--identify)
                if [ -z "$1" ] || [ "${1#-}" != "$1" ]; then
                    log "Error: with the -i|--identify option, you must provide the hash to identify as argument." >&2;
                    return 1;
                fi
                hash="$1"; shift;
                identify_hash "$hash";
                break;
                ;;
            -c|--crack)
                if [ -z "$1" ] || [ "${1#-}" != "$1" ]; then
                    log "Error: with the -c|--crack option, you must provide the hash to crack as argument." >&2;
                    return 1;
                fi
                hash="$1"; shift;
                cache_enabled=true;
                crack_hash "$hash" "$cache_enabled";
                break;
                ;;
            -w|--download-wordlists)
                if [ -z "$1" ] || [ "${1#-}" != "$1" ]; then
                    log "Error: with the -w|--download-wordlists option, you must provide at least one wordlist url as argument." >&2;
                    return 1;
                fi
                while [ "$#" -gt 0 ] && [ "${1#-}" = "$1" ]; do
                    wordlist_url="$1"; shift;
                    download_and_extract_wordlists "$CURR_DIR_PATH/wordlists" "$wordlist_url";
                done
                break;
                ;;
            -s|--start)
                start_hashcat_docker_container;
                break;
                ;;
            *)
                log "Error: unknown option: $option" >&2;
                return 1;
                ;;
        esac;
    done
}

main "$@";