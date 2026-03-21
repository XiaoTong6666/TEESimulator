DEBUG=false

MODDIR=${0%/*}

cd $MODDIR

# Continuous logcat capture for debug builds.
if [ "$DEBUG" = "true" ]; then
  BUGHUNTER_DIR="/data/adb/tricky_store/bughunter"
  mkdir -p "$BUGHUNTER_DIR"
  LOGFILE="$BUGHUNTER_DIR/bughunter_$(date +%Y%m%d_%H%M%S).log"
  # Restart loop: if logcat is killed (lmkd, oom, etc.), it respawns.
  # Append mode (>>) preserves data across restarts.
  # head -c caps total output at 8MB then the pipeline terminates logcat.
  (while true; do
    logcat -v threadtime -T 1 -s "TEESimulator:*" 2>/dev/null | head -c 8388608 >> "$LOGFILE"
    # head exits after 8MB causing logcat to receive SIGPIPE and die.
    # If we reached the cap, the file is full — stop permanently.
    [ "$(stat -c%s "$LOGFILE" 2>/dev/null || echo 0)" -ge 8388608 ] && break
    sleep 1
  done) &
fi

while true; do
  ./daemon "$MODDIR" || exit 1
  # ensure keystore initialized
  sleep 2
done &
