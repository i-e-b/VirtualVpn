# VirtualVpn

An IKEv2 VPN gateway that presents an application as if it was on a private network

This is currently in progress.

## Projects and parts

- **VirtualVpn** - This is the VPN utility. See `VirtualVpn.Settings` for configurable options. You will need to run this as root/admin.
- **JustListen** - A small test utility that echos UDP activity
- **SmallWebTest** - A minimal ASP.Net application to test routing from VirtualVpn

## Notes

If your ports are in use on Windows, use `netstat -ano` to get the
process id. It's probably the IKE service, which you'll need to turn off.

Parts based on, or derived from:

https://github.com/dschoeffm/go-ikev2
https://github.com/alejandro-perez/pyikev2
https://github.com/qwj/python-vpn

https://datatracker.ietf.org/doc/html/rfc7296
https://www.omnisecu.com/tcpip/ikev2-phase-1-and-phase-2-message-exchanges.php
https://security.stackexchange.com/questions/56434/understanding-the-details-of-spi-in-ike-and-ipsec

http://unixwiz.net/techtips/iguide-ipsec.html

https://www.secfu.net/2017/12/23/the-ikev2-header-and-the-security-association-payload/
https://www.rfc-editor.org/rfc/rfc9293

## Current issues & work-face

### Run web-app on non-socket interface?

https://gist.github.com/abgoswam/025bbf7b845259e6cbfb0671c12b51ac
https://github.com/atlascode/Kestrel.Transport.Streams
https://github.com/jacqueskang/IpcServiceFramework


### Now

- https://en.wikipedia.org/wiki/Internet_checksum
- https://en.wikipedia.org/wiki/IPv4#Header
- https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
- https://en.wikipedia.org/wiki/Ping_(networking_utility)#Message_format

`tcpdump -i vti_h -v`

- [x] Read IP packets
- [x] Encrypt ESP packets
- [x] Respond to ping (then dance around the room a bit)
- [x] TCP connection / handshake etc
- [x] Read wget and give some kind of dummy response
- [ ] Close connection
- [ ] Read and write across fragments

### Next

- [ ] Migrate Payloads to Bitwise serialiser? (this would need counts & looping)
- [ ] Need to be able to start a SA from this side

### Future

- [ ] Either host an app, or pass network requests to one
- [ ] Go through the collection types and make them thread safe
- [ ] Check all "to-do" items