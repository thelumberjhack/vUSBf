from TestcaseLoader import testcase_loader
import sys
import json
import test_case
import os

def main():
  old_file = sys.argv[1]
  testcases = testcase_loader(old_file)

  payloads = []
  for p in testcases.payloads:
    payloads.append(p.serialize_obj())

  save_file_name = old_file.replace(".obj", ".json")
  print "Writing file to : " + save_file_name
  with open(save_file_name, 'w') as the_file:
    the_file.write(json.dumps(payloads))

  print "removing : " + old_file
  os.remove(old_file)

if __name__ == "__main__":
  main()
