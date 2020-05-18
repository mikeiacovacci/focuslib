#!/bin/bash

# Copyright 2020 Mike Iacovacci
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

if [ $EUID -ne 0 ]; then
  echo "Error: Root privileges required" >&2
  exit 1
fi

if [ $# -ne 1 ]; then
  echo "Error: One argument expected" >&2
  exit 2
fi

if [ "$1" -eq "$1" 2> /dev/null ]; then
  if [ $1 -gt 0 ]; then
    valid_PID=$1
  else
    echo "Error: PID must be greater than zero" >&2
    exit 4
  fi
else
  echo "Error: Integer expected" >&2
  exit 3
fi

sudo_PID=$(pgrep -P $valid_PID 2> /dev/null)

target_PID=$(pgrep -P $sudo_PID 2> /dev/null)

vmnet_sniffer_PIDs=$(pgrep vmnet-sniffer 2> /dev/null)

for pid in $vmnet_sniffer_PIDs
do
  if [ $pid == $target_PID ]; then
    echo "Terminating vmnet-sniffer process (PID $target_PID)"
    kill $target_PID
    echo "Success"
    exit 0
  fi
done
echo "No matching vmnet-sniffer processes found"
exit 5
