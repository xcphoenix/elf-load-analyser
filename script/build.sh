#!/usr/bin/env bash
set -u
source ./util.sh
source ./merge.sh

readonly TARGET="ela"
readonly WORK_DIR=$(pwd)
readonly GO_WORK="${WORK_DIR}/../"
readonly SRC_DIR="${WORK_DIR}/../pkg/module/src"
readonly FRONTED_DIR="${WORK_DIR}/../pkg/web/template"

# for banner.txt
readonly BANNER_LEN_EXPR='github.com/xcphoenix/elf-load-analyser/pkg/env.BannerLen='
readonly BANNER_PATH="${WORK_DIR}/../pkg/env/banner.txt"

readonly ARG_ERR=100
readonly VAL_ERR=101

rm_extra_symbol=0
compress_level=0

ld_flags=
gc_flags=
target_bin="${TARGET}"

function help() {
    echo "Usage of build.sh"
    echo "  -r bool"
    echo "     remove debug and symbol data"
    echo "  -l int"
    echo "     compressed level, 1-9; if define, compressed target file used by upx"
    echo "  -d bool"
    echo "     enable debug"
}

function get_arg_val() {
    if [ $# -lt 2 ] || [ -z "$2" ]; then
        echo "miss arg[$1] value"
        help
        exit "${ARG_ERR}"
    fi
    echo "$2"
}

while (($# > 0)); do
    case $1 in
    -r)
        rm_extra_symbol=1
        shift 1
        ;;
    -d)
        gc_flags="all=-N -l"
        shift 1
        ;;
    -l)
        level=$(get_arg_val "$@")
        shift 2
        if [ "${level}" -gt 9 ] || [ "${level}" -lt 1 ]; then
            echo "argue value invalid"
            help
            exit "${VAL_ERR}"
        fi
        compress_level="${level}"
        ;;
    *)
        echo "Invalid arg: $1"
        help
        exit "${ARG_ERR}"
    esac
done

if [ "${gc_flags}" ]; then
    echo "Debug mode, disable other feature"
    rm_extra_symbol=0
    compress_level=0
fi

echo "Bcc source dir: ${SRC_DIR}"
cd "${SRC_DIR}" || exit
echo "Merge files"
merge_src
echo "Build fronted"
cd "${FRONTED_DIR}" || exit
build_fronted || exit

cd "${GO_WORK}" || exit
echo "Build binary..."
mkdir -p "target"
# remove symbol data
if [ "${rm_extra_symbol}" -ne 0 ]; then
    ld_flags="-s -w"
fi
# inject val use go build -X
banner_max_len=$(awk '{if (length(max)<length()) max=$0}END{print length(max)+10;}' "${BANNER_PATH}")
ld_flags="${ld_flags} -X ${BANNER_LEN_EXPR}${banner_max_len}"
go build -gcflags="${gc_flags}" -ldflags "${ld_flags}" -o target/"${TARGET}" \
    github.com/xcphoenix/elf-load-analyser/cmd || exit

# compressed
if [ "${compress_level}" -ne 0 ]; then
    cd target || exit
    target_bin="${TARGET}-compressed"
    echo "Clean old binary"
    rm_file "${target_bin}"

    echo "Compressed..."
    upx "-${compress_level}" -o "${target_bin}" "${TARGET}" || exit

    rm_file "${TARGET}"
    cd "${GO_WORK}" || exit
fi

echo "Build ok, now you can use '$(pwd)/target/${target_bin}' run program"

cd "${SRC_DIR}" || exit
echo "Clean tmp files"
rm_file "*.${OUT_SUFFIX}"
