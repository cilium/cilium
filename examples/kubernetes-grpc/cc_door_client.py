# Copyright 2015 gRPC authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""The Python implementation of the GRPC cloudcity.DoorManager client."""

from __future__ import print_function

import grpc

import cloudcity_pb2
import cloudcity_pb2_grpc
import sys

arg1 = 'GetName'
arg2 = '1'
arg3 = '99' 

def run():
  channel = grpc.insecure_channel('cc-door-server:50051')
  stub = cloudcity_pb2_grpc.DoorManagerStub(channel)
  if arg1 == 'GetName':
    response = stub.GetName(cloudcity_pb2.DoorRequest(door_id=int(arg2)))
    print("Door name is: " + response.name)
  elif arg1 == 'GetLocation':
    response = stub.GetLocation(cloudcity_pb2.DoorRequest(door_id=int(arg2)))
    print("Door location is lat = %s long = %s" % (response.lat, response.long))
  elif arg1 == 'GetStatus':
    response = stub.GetStatus(cloudcity_pb2.DoorRequest(door_id=int(arg2)))
    if response.state == cloudcity_pb2.OPEN: 
        print("Door is open")
    else: 
        print("Door is closed")
  elif arg1 == 'RequestMaintenance':
    response = stub.RequestMaintenance(cloudcity_pb2.DoorMaintRequest(
            door_id=int(arg2), maint_description=arg3))
    if response.success: 
        print("Successfully submitted maintenance request")
    else: 
        print("Failed to submit maintenance request") 
  elif arg1 == 'SetAccessCode':
    response = stub.SetAccessCode(cloudcity_pb2.DoorAccessCodeRequest(
            door_id=int(arg2), access_code=int(arg3)))
    if response.success: 
        print("Successfully set AccessCode to " + arg3)
    else: 
        print("Failed to set AccessCode") 

  else:
    print("Invalid call " + arg1)
    return

if __name__ == '__main__':
  if len(sys.argv) > 1:
    arg1 = sys.argv[1]
  if len(sys.argv) > 2:
    arg2 = sys.argv[2]
  if len(sys.argv) > 3:
    arg3 = sys.argv[3]

  run()
