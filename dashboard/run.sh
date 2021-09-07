# dev : suwonchon(suwonchon@gmail.com)

while [[ $# -gt 0 ]]; do
    key="$1"
    case "$key" in
        -r|--run)
        smashing start -p 80 -e production
        ;;
        -s|--ssl)
        smashing start -p 443 -e production -d
        ;;
        -s|--stop)
        kill -9 `ps aux | grep python3 | grep -v grep | awk '{print $2}'`
        ;;
        -h|--help)
        echo 'Usage: ./run.sh [OPTIONS...] '
        echo ''
        echo '  -r, --run           Executing web for debug(default 80)'
        echo '  -s, --ssl           Executing web production(default 443)'
        echo '  -b, --backgorund    Executing web production(default 80)'
        echo '  -u, --unittest      Unittest'
        echo ''
        echo 'Report bugs to suwonchon@gmail.com.'
        ;;
        *)
        echo "Unknown option '$key'"
        ;;
    esac
    shift
done