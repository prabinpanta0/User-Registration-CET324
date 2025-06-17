import jester, times

# Test if newCookie is available
when compiles(newCookie("test", "value")):
  echo "newCookie is available"
else:
  echo "newCookie is NOT available"

# Test what's available
echo "Testing cookie functionality"
