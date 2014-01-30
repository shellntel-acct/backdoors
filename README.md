dragon
======

dragon.c: a sniffing, non binding, reverse down/exec, portknocking service  * Based on cd00r.c by fx@phenoelit.de and helldoor.c by drizzt@drizzt.it.

Compiles as a windows service.  Once installed & started, it'll listen (using winpcap) to all interfaces on the machine.  If a packet comes across with the "magic source port", it'll reach out using wget to download and execute a binary based off of the src ip of the senders packet.

As it stands the the "magic source port" is 12317.  To change this, you can modify the option listed in the accepted source port in the function "packet_handler".

To compile use MinGW's version of gcc.

You will need to have installed or reference the path to the libpcap and WpdPack Libraries.

i.e.

gcc.exe -v -I c:\Path\To\WpdPack\Include -L c:\Path\To\WpdPack\lib dragon.c -L/usr/local/lib -lwpcap -lws2_32 -static -o dragon.exe

Note this has been tested and works under both 32 and 64 bit versions of windows ranging from XP - Win8 and Server 2k3 to Server2k12.

If you have any questions reach me at @jarsnah12 on twitter.
