# WireShark Project
### Analyzing packet captures using WireShark to identify three cases of suspicious activity inside the network. 
#### By Glen Abalayan

* You can recreate the lab environment on your own device by using `curl` to download the file with this URL: http://tinyurl.com/yaajh8o8
    - Example: `curl -L -o pcap.pcap http://tinyurl.com/yaajh808`

### Scenario 1: Discovering malware downloaded to the network
Two users are suspected of creating their own web server on the corporate network. They have successfully set up an Active Directory network and are allegedly downloading malware. We are tasked to investigate the created server and determine what type of malware is being downloaded. The users' IP addresses are somehwere in the range of `10.6.12.0/24`.
  * Finding the Domain Controller of the Active Directory network
     - To locate the IP address of the custom server, filter for traffic within the IP address range that uses the LDAP protocol in WireShark.
        - **LDAP** (Lightweight Directory Access Protocol) is the protocol used by Active Directory for directory services authentication. 
     - Filtering for `ip.addr==10.6.12.0/24 && ldap` in WireShark gives us these results.
     - ![](Images/TT%20IP%20address%20of%20Domain%20Controller%20of%20AD%20network.JPG)
      - The IP address of the Domain Controller is `10.6.12.12`.
   * Finding the custom site
      - To find the domain name of the custom site, filter for traffic within the IP address range that uses DNS protocol.
        - **DNS** (Domain Name System) is the protocol used to translate domain names to IP addreses. This will be useful for finding the site. 
      - Filtering for `ip.addr==10.6.12.0/24 && dns` in WireShark gives us theses results.
      - ![](Images/TT%20DNS%20and%20Ip%20address%20of%20custom%20site.JPG)
      - The custom site's domain name is `frank-n-ted.com`
   * Identifying the malware
      - To identify the malware downloaded onto the network, filter for traffic within the IP address range that is requesting files from the internet.
        - The **HTTP GET** request method is used to request a resource from an online server. This will be useful to find dowloaded files. 
      - Filtering the packet capture for `ip.addr==10.6.12.0/24 && http.request.method==GET` gives us these results.
      - ![](Images/TT%20wireshark%20query%20to%20show%20malware%20dowloaded%20to%20machine.JPG)
      - A machine with the IP address of `10.6.12.203` downloaded a file called `june11.dll`. 
      - Uploading `june11.dll` to [VirusTotal.com](https://www.virustotal.com/gui/) for analysis reveals that the malicious file is a Trojan Horse. 
      - ![](Images/TT%20VirusTotal%20classifies%20file%20as%20trojan.JPG)

### Scenario 2: Spotting an infected Windows host on the network
The Security team received reports of an infected Windows host on the network. The machines in the network live in the range `172.16.4.0/24`. The domain `mind-hammer.net` is associated with the infected computer. The Domain Controller for the network is located at `172.16.4.4` and is named Mind-Hammer-DC. We are tasked to inspect the traffic to determine more details about the infected Windows machine and determine where the infection originated. 
   * Investigating the infected Windows machine
      - To find the infected Windows machine, we need to first filter for DNS traffic within the IP address range to see which devices are communicating with the domain controller. 
      - Filtering for `ip.addr==172.16.4.0/24 && dns` gives us these results. 
      - ![](Images/VWM%20Rotterdam%20PC%20Hostname.JPG)
      - A machine with the IP address of `172.16.4.205` is seen communicating with the domain `mind-hammer.net`.
      - Now that we have determined that this is the infected machine, we can now filter for traffic from this address to determine its hostname and MAC address.
      - Filtering for `ip.addr==172.16.4.205` gives us this result.
      - ![](Images/VWM%20host%20name%20and%20IP%20address%20of%20infected%20computer.JPG)
      - The hostname is `ROTTERDAM-PC` and its MAC address is `00:59:07:b0:63:a4`. 
      - To find the Windows username associated with this we need to filter for traffic coming from `172.16.4.205` that uses the Kerberos protocol.
          - Kerberos is the protocol used to authenticate service requests between two or more hosts. This will be useful in finding our host. 
      - Filtering for `ip.addr==172.16.4.205 && kerberos.CNameString` gives us this result.
      - ![](Images/VWM%20Windows%20username%20of%20infected%20computer.JPG)
          - The username of the Windows user whose computer is infected is `mattijs.dervies`.
   * Determining where the infection originated
      - To find the IP traffic used to infect the Windows computer, we need to search for conversations between `172.16.4.205` and another computer.
      - Going into `Statistics > Conversations` in Wireshark shows all the conversations in the packet capture.
      - Filtering for only conversations that include `172.16.4.205` shows us these results.
      - ![](Images/VWM%20IP%20address%20used%20in%20the%20actual%20infection%20traffic.JPG) 
          - The IP address used to infect the computer is `185.243.115.84`. This is because the amount of data transmitted from this address is significantly higher than other forms of data sent to `172.16.4.205`.
### Scneario 3: Identifying Illegal Downloads
The IT team has been informed that some users have been torrenting on the corporate network. While the security team does not explicity forbid the use of torrents, they have a strict policy against copyright infringement. The machines using torrents are located in the range `10.0.0.0/24` and the domain controller is located at `10.0.0.2`.  We are tasked to investigate the machine responsible for torrenting and find out which torrent file was downloaded. 
   * Identifying the machine used for torrents
      - To find the machine torrenting files, we need to find which devices are communicating with the domain controller. We can filter for packets that use the `LDAP` protocol to find this. 
      - Filtering for `ip.addr==10.0.0.0/24 && ldap` gives us these results
      - ![](Images/ID%20MAC%20Address.JPG)
          - The machine communicating with the domain controller has an IP address of `10.0.0.201` and a MAC address of `00:16:17:18:66:c8`.
      - To find the username of the Windows computer responsible for torrenting files we need to filter for traffic cooming from `10.0.0.201` that uses the Kerberos protocol. 
      - Filtering for `ip.addr==10.0.0.201 && kerberos.CNameString` gives us these results.
      - ![](Images/ID%20Username.JPG)
           - The username associated with the computer used for torrenting is `elmer.blanco`.
      - To find the OS version of the Windows computer, we need to filter for traffic coming from `10.0.0.201` that uses the HTTP protocol.
           - Headers for HTTP include the User-Agent, as well as the OS version. This will be useful to determine the operating system of Elmer's computer.
       - Applying the filter for `ip.addr==10.0.0.201 && http` gives us these results
       - ![](Images/ID%20OS%20Version.JPG)
           - The OS version of Elmer's computer is `Windows NT 10.0 x64`.
   * Examining the torrent file downloaded
       - To find the torrent file downloaded, we need to filter for traffic from `10.0.0.201` using `HTTP GET` requests and use the find feature (Cntrl + F) for "torrent".
       - Applying this filter to the packet capture gives us this result
       - ![](Images/ID%20Torrent%20Download.JPG)
           - The torrent file downlaoded was a movie titled `Betty Boop Rhythm on the Reservation`. 
           - The torrented file violated copyright and requires immediate removal. 
