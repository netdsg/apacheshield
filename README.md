# apacheshield
Dynamically blocks client source IP addresses that generate given error codes.

I noticed my web server getting hit with over a thousand bogus requests in rapid succession from IP addresses that had no business making a connection to the server.  The requests were for pages that do not exist and generated 404 errors.  I can only imagine the source of the bad requests were hoping to happen across a page they could exploit for nefarious purposes.  In my opinion this is not much different than someone attempting to take your wallet on the street just to see if they can.  

This situation inspired me to come up with apacheshield; a script that monitors the apache access log for given error codes.  If a client triggers the error code for a configured number of times iptables writes a rule on the fly to block all traffic from the client.  
![alt tag](https://github.com/netdsg/apacheshield/master/apacheshield_line_drawing.png)
