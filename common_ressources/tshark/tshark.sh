#!/usr/bin/env sh

CURR_FILE_PATH="$(realpath "$0")"
CURR_DIR_PATH="$(dirname "$CURR_FILE_PATH")"
TSHARK_DOCKER_IMAGE="docker.io/parrotsec/tshark:7.1"

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

assert_xxd() {
    if ! command -v xxd >/dev/null 2>&1; then
        log "Error: the 'xxd' command is required. Considering installing the xxd package." >&2;
        exit 1;
    fi
}

assert_tr() {
    if ! command -v tr >/dev/null 2>&1; then
        log "Error: the 'tr' command is required. Considering installing the tr package." >&2;
        exit 1;
    fi
}

#############
### UTILS ###
#############



##############
### DOCKER ###
##############

tshark_hexdump_tcp_payload() {
    assert_docker;
    assert_xxd;

    input_pcap_file="$1"; shift;

    if [ ! -f "$input_pcap_file" ]; then
        log "Error: tshark_hexdump_tcp_payload: input pcap file not found: $input_pcap_file" >&2;
        return 1;
    fi

    docker run --rm \
        --user "$(id -u):$(id -g)" \
        --volume "$input_pcap_file:/in.pcap:ro" \
        $TSHARK_DOCKER_IMAGE -r /in.pcap -Y "tcp.payload && tcp.stream==0" -T fields -e tcp.payload \
    2>/dev/null;
}

############
### MAIN ###
############

main() {
    assert_docker;
    assert_xxd;

    if [ "$#" -eq 0 ]; then
        echo "Usage: $0 [OPTIONS]";
        echo "Options:";
        echo "  -p, --hexdump-tcp [PCAP_FILE] Parse and Hex dump TCP payload from the specified pcap file";
        return 0;
    fi

    while [ -n "$1" ]; do
        option="$1"; shift;

        case "$option" in
            -p|--hexdump-tcp)
                if [ -z "$1" ] || [ "${1#-}" != "$1" ]; then
                    log "Error: with the -p|--hexdump-tcp option, you must provide the pcap file as argument." >&2;
                    return 1;
                fi
                pcap_filepath="$1"; shift;
                tshark_hexdump_tcp_payload "$pcap_filepath";
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
