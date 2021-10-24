#!/usr/bin/bash
# dev : suwonchon(suwonchon@gmail.com)

while [[ $# -gt 0 ]]; do
    key="$1"
    case "$key" in
        -r|--run)
        python3 ./Pb_01.py
        ;;
        -i|--init)
        python3 ./Console.py -i
        ;;
        -u|--unittest)
        python3 ./Unittest.py
        ;;
        -b|--background)
        nohup python3 Pb_01.py &
        ;;
        -h|--help)
        echo 'Usage: ./bigb.sh [OPTIONS...] '
        echo ''
        echo '  -r, --run           Executing shell commands'
        echo '  -b, --background    Executing in the background'
        echo '  -s, --stop          Stop running process'
        echo '  -i, --init          Reset data and dashboard'
        echo '  -u, --unittest      Unittest'
        echo ''
        echo 'Report bugs to suwonchon@gmail.com.'
        ;;
        -s|--stop)
        kill -9 `ps aux | grep python3 | grep -v grep | awk '{print $2}'`
        ;;
#        -o=*|--output-file=*)
#        OUTPUTFILE="${key#*=}"
#        ;;
        *)
        echo "Unknown option '$key'"
        ;;
    esac
    shift
done