# VirtualVpn

An IKEv2/IPSEC VPN gateway that presents an application as if it was on a private network

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

### Now

- [ ] Add POST endpoint to the test web app, and post something big to it from Curl
      This has a bug!

- [ ] Need to be able to start a SA from this side

### Next

- [ ] Migrate Payloads to Bitwise serialiser? (this would need counts & looping)

### Future

- [ ] Go through the collection types and make them thread safe
- [ ] Check all "to-do" items

## Helpful Bash Commands

### Posting a binary file with curl
https://curl.se/docs/manpage.html#-d
```
curl -X 'POST' 'http://55.55.55.55:5223/WeatherForecast/checksum' -H 'accept: */*' -H 'Content-Type: application/octet-stream' -d @CHANGES -v
```