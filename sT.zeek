
# Raise a Notice when a threshold is reached
# Startover counting
# In the msg of the Notice, include the number of previous Notices for the same scan.

# Use connection_reset event, for every event check Port and Source IP, if IP == recIP and Port != recPort, or a list of ports then count this.

# Hold a table of IP's and Ports to each IP, everytime an IP disconnects a with RST packet on a new port, add one to table
# When Threshold mod Count == 0


type ipRec: record {
    noticeCounter: int;
    ipPorts: set[port];
};
global a: table[addr] of ipRec;
global threshold: int = 4;

redef enum Notice::Type += {
	sT_Port_Scanning,
};

function raiseNotice(address: addr)
	{
	local i: int = |a[address]$ipPorts|;
	if (modulo(i, threshold) == 0)
	{
		NOTICE([$note=sT_Port_Scanning,
        $msg=fmt("%s appears to port scanning using nmap -sT. Notice nr. %d",
                 address, a[address]$noticeCounter)]);
		a[address]$noticeCounter += 1;
	}
	}

event connection_reset(c : connection)
	{
	
	local originator_host: addr = c$id$orig_h;
    local responder_port: port = c$id$resp_p;
    
    if ( originator_host !in a )
    {
		a[originator_host] = [$noticeCounter=0, $ipPorts=set(responder_port)];
	}
	
	if ( responder_port !in a[originator_host]$ipPorts )
	{
		a[originator_host]$ipPorts += set(responder_port);
		raiseNotice(originator_host);
	}
	
	}
	

event zeek_done()
	{
	print a;
	}
