#THIS IS JUST TO SHOW THE COMMANDS THAT WERE PLUGGED INTO GDB

#To run our C environment:
#Inside our restricted launch docker container:

gdb ./tmp/server

#Set logging files
set logging file [FILENAME].txt
set logging enabled on
break process_packet_sat2
stepi
stepi
stepi
commands
    silent  #Silences GDB output other than our direct commands to it
    finish  #Steps to the end of process execution so we can examine the state of SAT2 post-packet processing
    info locals #Shows local variables after the point of processing
    info args   #Shows what arguments are being passed into the function 
    info registers  #Shows processor register states after packet processing
    x/32xb &pinfo->packet   #Shows the memory address buffer after processing a packet
    continue    #Continues execution
    end #Just shows the end of our custom commands

run /tmp/PACKET_DIR #Runs the program with our command setup and with our packet data as input
