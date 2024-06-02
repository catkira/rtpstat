# rtpstat

## Test
run gst-launch-1.0 -v filesrc location=test_data/test.hevc ! h265parse ! rtph265pay ! udpsink host=127.0.0.0 port=5600

and run rtptest
