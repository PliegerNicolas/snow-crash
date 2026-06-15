#!/usr/bin/env sh

CURR_FILE_PATH="$(realpath "$0")"
CURR_DIR_PATH="$(dirname "$CURR_FILE_PATH")"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*";
}

###############
### ASSERTS ###
###############

assert_vagrant() {
    if ! command -v vagrant >/dev/null 2>&1; then
        log "Error: the 'vagrant' command is required. Considering installing the vagrant from https://www.vagrantup.com/downloads.";
        exit 1;
    fi
}

#############
### UTILS ###
#############

###############
### VAGRANT ###
###############

provision_vagrant_ghidra_box() {
    assert_vagrant;
    GUI=false vagrant up --provision --destroy-on-error || return 1;
    vagrant halt || return 1;
    return $?;
}

build_vagrant_ghidra_box_golden_image() {
    assert_vagrant;

    box_outdir="${1}";

    if [ -z "$box_outdir" ]; then
        log "Error: build_vagrant_ghidra_box_golden_image: missing box output path" >&2;
        return 1;
    fi

    vagrant destroy -f || return 1;
    GUI=false provision_vagrant_ghidra_box || return 1;
    vagrant package --output "${box_outdir}" || return 1;
    return $?;
}

start_vagrant_ghidra_box() {
    assert_vagrant;

    GUI=false provision_vagrant_ghidra_box || return 1;
    GUI=true vagrant up || return 1;
    return $?;
}

############
### MAIN ###
############

main() {
    assert_vagrant;

    if [ "$#" -eq 0 ]; then
        echo "Usage: $0 [OPTIONS]";
        echo "Options:";
        echo "  -p, --provision     Provision the vagrant ghidra box";
        echo "  -b, --build         Build a golden image of the vagrant ghidra box (output path can be specified as argument, default: ./ghidra.box)";
        echo "  -s, --start         Start the vagrant ghidra box";
        return 0;
    fi

    while [ -n "$1" ]; do
        option="$1";
        shift;

        case "$option" in
            -p|--provision)
                log "Provisioning the vagrant ghidra box... This can take a while.";
                provision_vagrant_ghidra_box || return 1;
                ;;
            -b|--build)
                box_outdir="${1:-$CURR_DIR_PATH/ghidra.box}";
                log "Building a golden image of the vagrant ghidra box... This can take a while and take up a lot of disk space.";
                build_vagrant_ghidra_box_golden_image "${box_outdir}" || return 1;
                ;;
            -s|--start)
                start_vagrant_ghidra_box || return 1;
                ;;
            -d|--destroy)
                log "Destroying the vagrant ghidra box...";
                vagrant destroy -f || return 1;
                ;;
            *)
                log "Error: unknown option: $option" >&2;
                return 1;
                ;;
        esac;
    done
}

main "$@";