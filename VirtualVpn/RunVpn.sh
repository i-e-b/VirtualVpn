#!/bin/bash

cd /root/VirtualVpn/VirtualVpn || exit 2
echo "Compiling VirtualVPN..."
dotnet run . load=mpesa.json always=197.250.65.132

exit 1