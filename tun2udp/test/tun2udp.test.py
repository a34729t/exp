# Program to test the basic udp tunnel
# NOTE: To use sudo with paramiko with resorting serious contortions we echo password in with sudo -S
#   (stdin, stdout, stderr) = sshConn.exec_command("echo \""+ pw + "\" | sudo -S ...")
# NOTE: Remember to properly edit /etc/sudoers file on all VMs:
#
#   # Allow members of group sudo to execute any command
#   %sudo   ALL=(ALL:ALL) ALL
#   nflacco ALL=(ALL) NOPASSWD: ALL <---- NEW
#
# NOTE: We use pscp so we can pass password in; on ubuntu this requires the following package:
#   sudo apt-get install putty-tools

# packages
import paramiko

# vars
user = 'nflacco'
pw = 'greek'
vm0 = '10.0.1.24'
vm1 = '10.0.1.25'
vm0_virtualAddr = '10.9.8.1'
vm1_virtualAddr = '10.9.8.2'
port = '55511'
dir = '/home/nflacco/projects/exp/tun2udp'
size_testfile = '15' # mb, with approx 5mb/sec transfer speed between local vms
testfile_name = 'file.txt'
testfile_scp_name = 'file_rx.txt'
process_name = '/tun2udp/tun2udp'

# Set up ssh multiple clients
ssh0 = paramiko.SSHClient()
ssh1 = paramiko.SSHClient()
ssh0.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh1.set_missing_host_key_policy(paramiko.AutoAddPolicy())
# ... initialize the connections that we will later use
ssh0.connect(vm0, username=user, password=pw)
ssh1.connect(vm1, username=user, password=pw)

def main ():
    # Initialize VMs and create the tunnel endpoints
    startProgram (ssh0, vm0, vm1, vm0_virtualAddr)
    startProgram (ssh1, vm1, vm0, vm1_virtualAddr)
    
    # Create the test files and get checksums
    chksum0 = createTestFile (ssh0)
    chksum1 = createTestFile (ssh1)
    
    # Send files (first from one side of tunnel, then from other side)
    sendFileOverTunnel(ssh0, vm1_virtualAddr)
    sendFileOverTunnel(ssh1, vm0_virtualAddr)
    
    # Kill programs
    killProgram (ssh0, process_name)
    killProgram (ssh1, process_name)
    
    # Get checksums of received files
    chksum1_rx = verifyChecksum (ssh1) # checksum of file received by vm1
    chksum0_rx = verifyChecksum (ssh0) # checksum of file received by vm0
    
    # Print out output
    print "-------------------------------------------------------------------------------"
    if chksum0 == chksum1_rx:
      print "vm0 -> vm1 transfer successful with checksum = " + chksum0
    else:
      print "vm0 -> vm1 transfer failure; checksum mismatch"
      print "\t" + "vm0 tx: " + chksum0
      print "\t" + "vm1 rx: " + chksum1_rx
      
    if chksum0 == chksum1_rx:
      print "vm1 -> vm0 transfer successful with checksum = " + chksum1
    else:
      print "vm1 -> vm0 transfer failure; checksum mismatch"
      print "\t" + "vm1 tx: " + chksum1
      print "\t" + "vm0 rx: " + chksum0_rx

def verifyChecksum (sshConn):
    cmd = "sha1sum " + dir + "/" + testfile_scp_name + " | cut -b-40" # get only checksum part of output
    (stdin, stdout, stderr) = sshConn.exec_command(cmd)
    checksum = stdout.readline().rstrip('\n');
    return checksum;

def tun2udpCommand (localAddr, remoteAddr, tunName):
    # Helper function to create long-ass command to run tun2udp and log stuff correctly
    # NOTE: Run as background process and use nohup (each paramiko exec_command is own ssh session)
    cmd = " sudo -S nohup " + dir + "/tun2udp "
    cmd += " -local-address \'" + localAddr + ":" + port + "\' "
    cmd += " -remote-address  \'" + remoteAddr + ":" + port + "\' "
    cmd += " -tun -no-pi -tun-dev " + tunName + " -debug " 
    cmd += " > " + dir + "/test.log 2> " + dir + "/test.err < /dev/null "
    cmd += " &"
    return cmd

def killProgram (sshConn, processName):
    # Fancy grep/kill
    cmd = "sudo -S ps aux | grep -e '" + processName + "' | grep -v grep | awk '{print $2}' | xargs -i kill {} "
    (stdin, stdout, stderr) = sshConn.exec_command("echo \""+ pw + "\" | " + cmd)
    stdout.readlines(); stderr.readlines() # need to do this to make ssh sessions run!

def startProgram (sshConn, localAddr, remoteAddr, virtualAddr, tunName="tunX"):
    print "Configuring " + localAddr + " with virtual address " + virtualAddr 
    # Git pull, make, start program with correct options and logging and do ip link

    # git pull, Make, clean logs, etc.
    cmd = "cd " + dir + ";"
    cmd += "rm test.err test.log;"
    cmd += "git pull;"
    cmd += "make clean; make;"
    (stdin, stdout, stderr) = sshConn.exec_command(cmd)
    print "\tGit pull, make, clean logs"
    
    # TODO: Kill program if already running
    killProgram (sshConn, process_name)
    print "\tKill program if running"
    
    # Start the program
    cmd = tun2udpCommand (localAddr, remoteAddr, tunName)
    (stdin, stdout, stderr) = sshConn.exec_command("echo \""+ pw + "\" | " + cmd)
    print "\tStart program in background (nohup)"
    stdout.readlines(); stderr.readlines() # need to do this to make ssh sessions run!
    
    # Link the ip and tun
    cmd += "sudo -S ip link set " + tunName + " up; sudo ip addr add " + virtualAddr + "/24 dev " + tunName
    (stdin, stdout, stderr) = sshConn.exec_command("echo \""+ pw + "\" | " + cmd)
    stdout.readlines(); stderr.readlines() # need to do this to make ssh sessions run!
    print "\tSet up TUN device and link to virtual IP"

def createTestFile(sshConn):
    # Regenerate test file and get checksum (sha1 40 bytes)
    # see http://www.skorks.com/2010/03/how-to-quickly-generate-a-large-file-on-the-command-line-with-linux/
    cmd = "dd if=/dev/urandom of=" + dir + "/" + testfile_name + " bs=1048576 count=" + size_testfile + ";"
    cmd += "sha1sum " + dir + "/" + testfile_name + " | cut -b-40" # get only checksum part of output
    (stdin, stdout, stderr) = sshConn.exec_command(cmd)
    checksum = stdout.readline().rstrip('\n');
    return checksum;

def sendFileOverTunnel(sshConn, virtualAddr):
    # Helper function to send a file from a server to a virtual IP address that
    # is on the other end of some tunnel.
    # NOTE: use pscp (putty) so we can use password via command line unlike normal scp
    print "Sending " + testfile_name + " over tunnel to " + virtualAddr + "..."
    cmd = "pscp -pw " + pw + " " + dir + "/" + testfile_name + " " + user + "@" + virtualAddr + ":" + dir + "/" + testfile_scp_name
    #print "cmd = " + cmd
    (stdin, stdout, stderr) = sshConn.exec_command("echo \"Y\" | " + cmd)
    stdout.readlines(); stderr.readlines() # need to do this to make ssh sessions run!
    #print stdout.readlines();
    #print stderr.readlines();
    

if __name__=="__main__":
    main()