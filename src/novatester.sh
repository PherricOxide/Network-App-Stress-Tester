fuzzers=()
scanners=()


# Nmap commands go here
scanners+=("nmap -T4 -sS --top-ports 4000 $1 >> test\$srcip")
scanners+=("nmap -T4 -sS -p0-65535 $1 >> test\$srcip")
scanners+=("nmap -T4 -sS -p0-10000 $1 >> test\$srcip")
scanners+=("nmap -T4 -sU -p0-65535 $1 >> test\$srcip")
scanners+=("nmap -T4 -sU -p0-10000 $1 >> test\$srcip")
scanners+=("nmap -T1 -sS --top-ports 100 $1 >> test\$srcip")



# Fuzzer commands go here

# This will just kill the fuzzers so we get nmap by itself
fuzzers+=("-exit")

# Fuzz the packet interval deviation
fuzzers+=("-packetcount 2 -fuzzPacketInterval -intervalmin 10 -intervalmax 100000")
fuzzers+=("-packetcount 200 -fuzzPacketInterval -intervalmin 5000")
fuzzers+=("-packetcount 2000 -fuzzPacketInterval -intervalmin 10 -intervalmax 100000")
fuzzers+=("-packetcount 2000 -fuzzPacketInterval -intervalmin 5000")

# Fuzz the payload size
fuzzers+=("-packetcount 200 -fuzzPayloadSize -payloadmin 1 -payloadmax 1200")
fuzzers+=("-packetcount 200 -fuzzPayloadSize -payloadmin 1002 -payloadmax 1000")
fuzzers+=("-packetcount 2000 -fuzzPayloadSize -payloadmin 1 -payloadmax 1200")
fuzzers+=("-packetcount 2000 -fuzzPayloadSize -payloadmin 1002 -payloadmax 1000")

# Fuzz the port traffic distro by just talking to one port (happens above too)
fuzzers+=("-packetcount 100 -payload 1")
fuzzers+=("-packetcount 1000 -payload 1")
fuzzers+=("-packetcount 5000 -payload 1")
fuzzers+=("-packetcount 10000 -payload 1")





ipSwitch='ifconfig eth0 $srcip netmask 255.255.255.0'
#ipSwitch='echo "Switching to IP $srcip" >> test$srcip'

# Fuzzing command wrapper
fastFuzzing="./fast -dstip $1 -dstmac $2 -dstport 42 -srcport 42 -srcip \$srcip \$fuzzCommands >> test\$srcip"


# Just some color for the output
txtbld=$(tput bold)             # Bold
bldred=${txtbld}$(tput setaf 1) #  red
bldblu=${txtbld}$(tput setaf 2) #  green
txtrst=$(tput sgr0)             # Reset


testNumber=1
function RunTest()
{
	for i in "${fuzzers[@]}"; do
		for scanner in "${scanners[@]}"; do
			echo -n $bldblu
			echo "Running test $testNumber"
			echo -n $txtrst
		
			srcip="192.168.10.$testNumber"
			let testNumber++

			fuzzCommands=$i

			echo "Switching IP address to $srcip"
			eval ${ipSwitch}
		
			
			echo -n $bldred
			echo -n "Fuzzer: "
			echo -n $txtrst
			echo $fuzzCommands
			eval ${fastFuzzing}

			echo -n $bldred
			echo -n "Scanner: "
			echo -n $txtrst
			echo $scanner
			eval ${scanner}

			echo -e "\n"
		done
	done
}

RunTest
