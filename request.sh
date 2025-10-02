curl -x POST \
  -H "Content-Type: application/json" \
  -H '{"sql_injection": "+OR+1=1"}'\
  https://localhost/dummy-post