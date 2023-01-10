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

"""The Python implementation of the GRPC cloudcity.DoorManager server."""

from concurrent import futures
import time

import grpc

import cloudcity_pb2
import cloudcity_pb2_grpc

_ONE_DAY_IN_SECONDS = 60 * 60 * 24


class DoorManager(cloudcity_pb2_grpc.DoorManagerServicer):

  def GetName(self, request, context):
    return cloudcity_pb2.DoorNameReply(name='Spaceport Door #%s' % request.door_id)

  def GetLocation(self, request, context): 
    return cloudcity_pb2.DoorLocationReply(lat=10.2222, long=68.8788)

  def GetStatus(self, request, context): 
    return cloudcity_pb2.DoorStatusReply(state=cloudcity_pb2.CLOSED)

  def RequestMaintenance(self, request, context): 
    return cloudcity_pb2.DoorActionReply(success=True) 

  def SetAccessCode(self, request, context): 
    return cloudcity_pb2.DoorActionReply(success=True) 


def serve():
  server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
  cloudcity_pb2_grpc.add_DoorManagerServicer_to_server(DoorManager(), server)
  server.add_insecure_port('[::]:50051')
  server.start()
  try:
    while True:
      time.sleep(_ONE_DAY_IN_SECONDS)
  except KeyboardInterrupt:
    server.stop(0)

if __name__ == '__main__':
  serve()
