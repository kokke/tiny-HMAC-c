import binascii
import hashlib
from hashlib import sha1
import hmac
import os
import random
import string
import subprocess
import sys
import time
import threading
try:
    import Queue
except:
    import queue as Queue

BIN_PATH = "./build/test_hmac_sha1"

NTHREADS = 2
NTESTS = 10
NBYTES = 20


global still_making_input
still_making_input = True
tests = Queue.Queue()
failures = list()


#
# Helper functions
#


def random_string(len):
  """ Returns a random string of length 'len' consisting of upper + lowercase letters and digits """
  ret = list()
  rand = random.Random()

  for i in range(len):
    ret.append("%.02x" % rand.randint(0, 255))

  return "".join(ret)

  #selector = string.ascii_uppercase + string.ascii_lowercase + string.digits
  #return ''.join(random.choice(selector) for _ in range(len))


def run_test(key, msg, expected_output):
  """ Run the C test program, comparing the Python HMAC-SHA1 implementation to the one in C """
  return subprocess.call([BIN_PATH, key, msg, expected_output])


def run_in_thread(target_function):
  t = threading.Thread(target=target_function)
  t.start()
  t.join()


def run_tests():
  while (tests.empty() == False) or (still_making_input == True):
    try:
      key, msg, out = tests.get(True, 0)
      retcode = run_test(key, msg, out)
      if retcode != 0:
        failures.append([key, msg, out])
        sys.stdout.write("X")
      else:
        sys.stdout.write(".")
      sys.stdout.flush()
    except Queue.Empty:
      time.sleep(0.1) #pass # Ignore exceptions here




def hmac_sha(key, msg):
  return hmac.new(key, msg, sha1).hexdigest()


def make_test_input():
  # Create input and expected output
  for i in range(NTESTS):
    test_key = random_string(NBYTES)
    test_msg = random_string(NBYTES)
    test_output = hmac_sha(binascii.a2b_hex(test_key), binascii.a2b_hex(test_msg))
    tests.put([test_key, test_msg, test_output])



#
# Test driver
#
if __name__ == "__main__":

  # Read NTESTS from stdin 
  if len(sys.argv) > 1:
    if sys.argv[1].isdigit():
      NTESTS = int(sys.argv[1])

  # Read NTHREADS from stdin
  if len(sys.argv) > 2:
    if sys.argv[2].isdigit():
      NTHREADS = int(sys.argv[2])

  # Read NBYTES from stdin
  if len(sys.argv) > 3:
    if sys.argv[3].isdigit():
      NBYTES = int(sys.argv[3])


  # Tell user what is going to happen
  print("")
  str_threads = "thread"
  if NTHREADS > 1:
    str_threads += "s"
  print("Running %d %s calculating HMAC-SHA1 on %d pairs of random %d-byte strings," % (NTHREADS, str_threads, NTESTS, NBYTES))
  print("comparing the results to the HMAC calculation using Python's hmac module.")
  print("")

  t_mk_input = threading.Thread(target=make_test_input)
  t_mk_input.start()

  # Create new threads
  threadlist = list()
  for i in range(NTHREADS):
    threadlist.append(threading.Thread(target=run_tests))

  # Run all threads
  for i, thread in enumerate(threadlist):
    thread.start()

  t_mk_input.join()
  still_making_input = False

  # Wait for threads to complete
  for i, thread in enumerate(threadlist):
    thread.join()


  print(" ")
  print(" ")
  print("%d/%d tests succeeded." % (NTESTS - len(failures), NTESTS))
  print(" ")

  if len(failures) > 0:
    error_log = open("error_log.txt", "a")
    for fail_key, fail_msg, fail_output in failures:
      error_log.write("%s %s %s %s %s" % (BIN_PATH, fail_key, fail_msg, fail_output, os.linesep))
    error_log.close()
    


