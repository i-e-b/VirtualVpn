# VirtualVpn

An IKEv2/IPSEC VPN gateway that presents an application as if it was on a private network

This is currently in progress.

It will respond to StrongSwan opening a session from outside, and will
correctly start a secured session. It allows communication to and from
a configured web app.

It is slow compared to a hardware VPN device. It is slow compared to a
pair of tin-cans with a tight string in between. It might be just fast
enough for a basic API that is called a few times a second at most.

## Current issues & work-face

### Now

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

## Setup for test and development

### Example ipsec.conf

This config goes in `/etc/ipsec.conf` for StrongSwan to use.
"alice" is a server running both VirtualVPN and the web app.
"bob" is a server running StrongSwan as a test 'remote' VPN
gateway

```
conn alice
    # life cycle #
    auto=add
    dpdaction=clear
    dpddelay=300s
    rekey=no
    ## phase 1 ##
    keyexchange=ikev2
    ## phase 2 ##
    authby=secret
    mark=24
    type=tunnel
    # us (bob) #
    leftauth=psk
    left=192.168.0.3
    leftid=192.168.0.3
    leftsubnet=192.168.0.40/32
    lefthostaccess=yes
    leftallowany=yes
    leftupdown=/etc/ipsec-notify-bob.sh
    # them (alice) #
    rightauth=psk
    right=192.168.0.2
    rightid=192.168.0.2
    rightsubnet=55.55.0.0/16
```

### Notify script

This goes with the ipsec.conf, in `/etc/ipsec-notify-bob.sh`.
It needs to have execute permissions. This script adds a vti 
which routes traffic for 55.55.?.? to a VirtualVPN device on
Bob. Because the sub-net is a `/16` range, many IP addresses
will route to the one VirtualVPN - but it does not care. All
requests will get routed to the web app VirtualVPN is set up
to use. Ports are also ignored, and the web app will get any
requests -- except ICMP pings, which VirtualVPN will respond
to itself.

```
#!/bin/bash
echo "###### BOB UP/DOWN SCRIPT #######"
echo "wake..." > /var/log/vti_state
set -o errexit
! echo "VERB = ${PLUTO_VERB-}" || true

case "${PLUTO_VERB-}" in
    "up-client")
        echo "cleaning old vti devices" > /var/log/vti_state
        ! ip tunnel del vti_h || true
        echo "creating vti device ${PLUTO_ME} -> ${PLUTO_PEER} mark=${PLUTO_MARK_OUT%%/*}->${PLUTO_MARK_IN%%/*}" > /var/log/vti_state
        #ip tunnel add vti_h mode vti local "${PLUTO_ME}" remote "${PLUTO_PEER}" key "${PLUTO_MARK_IN%%/*}"
        ip tunnel add vti_h mode vti local "${PLUTO_ME}" remote 0.0.0.0 key "${PLUTO_MARK_IN%%/*}"
        echo "linking" > /var/log/vti_state
        ip link set vti_h up mtu 1419
        echo "adding routes" > /var/log/vti_state

        ip addr add 192.168.0.40/32 remote 55.55.0.0/16 dev vti_h

        echo "setting sysctl" > /var/log/vti_state
        sysctl -w "net.ipv4.conf.vti_h.disable_policy=1"
        echo "up" > /var/log/vti_state
        ;;
    "up-host")
        echo "cleaning old vti devices" > /var/log/vti_state
        ! ip tunnel del vti_h || true
        echo "creating vti device ${PLUTO_ME} -> ${PLUTO_PEER} mark=${PLUTO_MARK_OUT%%/*}->${PLUTO_MARK_IN%%/*}" > /var/log/vti_state
        ip tunnel add vti_h mode vti local "${PLUTO_ME}" remote "${PLUTO_PEER}" okey "${PLUTO_MARK_OUT%%/*}" ikey "${PLUTO_MARK_IN%%/*}"
        echo "linking" > /var/log/vti_state
        ip link set vti_h up mtu 1419
        echo "adding routes" > /var/log/vti_state

        ip addr add 192.168.0.40/32 remote 55.55.0.0/16 dev vti_h

        echo "setting sysctl" > /var/log/vti_state
        sysctl -w "net.ipv4.conf.vti_h.disable_policy=1"
        echo "up" > /var/log/vti_state
        ;;
    "down-client")
        echo "removing vti_h" > /var/log/vti_state
        ! ip tunnel del vti_h || true
        echo "down" > /var/log/vti_state
        ;;
esac
```

## Notes

If ports are blocked on Windows,  call `netstat -ano` to get
the process ids. It's probably the IKE service, which you'll
need to turn off.

To get this fully working, you will either need a good modem
that allow you to pass all traffic to your device, or not be
behind any kind of NAT, and have a firewall that permits all
traffic on ports 500 and 4500 regardless of protocol type.

Parts based on, or derived from:

- https://github.com/strongswan/strongswan
- https://github.com/dschoeffm/go-ikev2
- https://github.com/alejandro-perez/pyikev2
- https://github.com/qwj/python-vpn
- https://github.com/frebib/netstack.git

References

https://datatracker.ietf.org/doc/html/rfc7296
https://www.rfc-editor.org/rfc/rfc9293
https://security.stackexchange.com/questions/56434/understanding-the-details-of-spi-in-ike-and-ipsec
http://unixwiz.net/techtips/iguide-ipsec.html
https://www.secfu.net/2017/12/23/the-ikev2-header-and-the-security-association-payload/