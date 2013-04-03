Linux-Wall-of-Fire
==================

My linux adaptive firewall kernel module. Makes use of netfilter hooks and yes, this version does read in a text file from kernel space ;).

Features
==================

- Ability to have black and white lists. black lists for incoming and outgoing - whitelist for incoming

Format of textfiles to be read in
==================

The format of the files should handle all of the cases shown below (note that TCP and SSH are examples and other protocols/ports should be supported, see parse_data() method to get an idea of what's supported):
- 192.168.0.4/24 TCP SSH
- 192.168.0.4/24 tcp ssh
- 192.168.0.4/24 TCP 22
- 192.168.0.4/24 tcp 22
- 192.168.0.4/24 6 22
- 192.168.0.4/24 TCP
- 192.168.0.4/24 tcp
- 192.168.0.4/24 6
- 192.168.0.4/24


Things to do
==================

- Get spinlocks to work and make a version that doesn't read in a textfile from kernel space.

