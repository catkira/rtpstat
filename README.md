# rtpstat

## Test
run gst-launch-1.0 -v filesrc location=test.hevc ! h265parse ! rtph265pay ! udpsink host=<local ip> port=5600
and run rtptest