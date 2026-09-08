# Owner-reviewed fragment for the existing sentinel-ro forced-command gateway.
# The shell never evaluates SSH_ORIGINAL_COMMAND; the Python helper validates
# the complete string against a closed grammar before reading fixed log files.
case "${SSH_ORIGINAL_COMMAND-}" in
  sentinel-origin-evidence-window\ *)
    exec /usr/bin/python3 /usr/local/libexec/sentinel-origin-evidence-window.py
    ;;
esac
