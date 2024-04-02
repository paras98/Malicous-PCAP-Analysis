# Malicious PCAP Dissection with Wireshark

![AIA Project](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/AIAProject-37002416.jpg)

## Lab Overview 📚

In this lab, we delve into the intriguing world of network forensics using Wireshark, a powerful tool for network protocol analysis. Our journey will guide you through dissecting packet capture (PCAP) files to unveil the mysteries of an infected network. You'll learn the intricacies of network packets, how to filter and analyze them, and ultimately, how to identify and dissect malicious traffic with precision.

### Learning Objectives 🎯

- **Network Packet Analysis:** Master the art of using Wireshark to dissect network packets and unearth the hidden activities within a network.
- **Malicious Traffic Identification:** Learn the techniques to spot and extract suspicious files from network traffic for deeper analysis.
- **Malware Identification:** Sharpen your skills in determining the maliciousness of a file using its signature and online tools.

## Introduction to Wireshark 🐋

Wireshark is not just a tool but a window to understanding what flows through the veins of a network. It’s a powerful ally for anyone looking to understand network protocols, troubleshoot problems, or inspect security issues within a network. Whether you're a network administrator, security engineer, or an enthusiast eager to learn about network internals, Wireshark offers the insights you need.

### Quick Wireshark Guide for Network Analysis 🛠

- **Discovering Hosts:** Learn how to identify the active hosts on a network using DHCP filters, NBNS, and more.
- **Analyzing Packets:** Get hands-on experience in dissecting packets to reveal the operating system, browser information, and user names involved in network communication.
- **Identifying Non-Malicious Traffic:** Understand the baseline of normal network traffic to better identify anomalies.

## Lab Exercises 🧪

### Lab 1: Dissecting Malicious Traffic

**Scenario:** Assume the role of a Security Operations Center Engineer tasked with investigating suspicious network activities. Analyze two PCAP files using Wireshark to identify malicious behavior.

**Steps:**
1. **General Analysis:** Begin by examining the file properties and endpoints to understand the traffic flow.
2. **HTTP Traffic Investigation:** Delve into HTTP requests to pinpoint potentially malicious communications.
3. **Payload Analysis:** Identify and extract malware payloads for further examination.
4. **Payload Deep Dive:** Utilize malware analysis tools to uncover the nature and behavior of the extracted payloads.

### Lab 2: Advanced Malicious Traffic Dissection

**Setting Up:** Prepare for the lab by accessing the provided PCAP file and familiarizing yourself with the network diagram.

**Objective:** Further your analysis skills by identifying indicators of compromise, both host-based and network-based, to conclude the nature of the malware affecting the network.

## Conclusion 🏁

This lab provides a foundational understanding of network traffic analysis for identifying malicious activities. By engaging in practical exercises, you’ll gain the skills necessary to navigate the complex landscape of network security, setting the stage for more advanced exploration in the field of information assurance.

---

_**Authors:** Paras Saxena and Johncliff Mutungwa | Guided by **Mr. Robot**_

# Lab Guide 📓: 
## LAB OVERVIEW 💻

In this lab for "Malicious PCAP Dissection", we will be using the Wireshark network protocol analyzer to examine captured packet capture (PCAP) files containing network traffic from an infected Network. Wireshark is a network packet analyzer, it is used for examining what goes inside a network through captured traffic on the network interfaces. It offers many criteria to filter packets in great detail of protocols and create various statistics for quick understanding.
### Learning Objectives 📝

By the end of this lab, you will be able to:

- Understand the network packet analysis: How to use wireshark to analyze network packets from the PCAP file to understand what hosts took part in the attack and gain information about the hosts and determine the possible attack method.
- Identify a malicious traffic: How to identify and save malicious suspicious files on the network traffic for further analysis, based on specific patterns and characteristics within the network packets.
- Identify the malware used: How to identify whether a suspicious file on the network traffic was malicious using available tools online and determine its type based on its signature.
- Apply the best practices when it comes to analyzing, documenting, and sharing insights regarding malicious files.
## Introduction to Wireshark 🐋 
Wireshark is a network packet analyzer that presents captured packet data in as much detail as possible. You could think of a network packet analyzer as a measuring device for examining what's happening inside a network cable, just like an electrician uses a voltmeter for examining what’s happening inside an electric cable (but at a higher level, of course). In the past, such tools were either very expensive, proprietary, or both. However, with the advent of Wireshark,that has changed. Wireshark is available for free, is open source, and is one of the best packet analyzers available today.
Here are some reasons people use Wireshark:
- Network administrators use it to troubleshoot network problems 🔀
- Network security engineers use it to examine security problems 👮
- Quality Assurance engineers use it to verify network applications 👷
- Developers use it to debug protocol implementations 🌐
- People use it to learn about the internals of network protocols 👿
Wireshark can also be helpful in many other situations.
### Quick Introduction to Wireshark for Network Analysis

**For malicious packet analysis, It's important to discover information about the host on the network. Common ways of doing this are:**

#### 1. DHCP Filter:

  Just put DHCP as filter criteria to get all DHCP packets

![image10-1117370768.png](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/image10-1117370768.png)

The issue with DHCP traffic is that it is not likely to be captured and will make it difficult to analyze the DHCP traffic during the incident.  

#### 2. NBNS i.e net bios name server:

  It can only be used to discover Microsoft windows hosts and macOS hosts, the filter is NBNS.

![image12-1576615343.png](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/image12-1576615343.png)

#### 3. Packet Analysis ( Discovery of OS and web browser )

  
Note:( Attackers often spoofs the User-Agents line)  
For this, use the feature `"follow tcp stream"` using `http.request` as the filter. To do this, `select the target packet > right click and select "Follow" > TCP Stream.`

![image7-405135646.png](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/image7-405135646.png)

![image14-1790360527.png](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/image14-1790360527.png)

Windows Version mapped from the wireshark information  

- Windows NT 5.1 | Windows XP
- Windows NT 6.0 | Windows Vista
- Windows NT 6.1 | Windows 7
- Windows NT 6.2 | Windows 8
- Windows NT 6.3 | Windows 8.1
- Windows NT 10.0 | Windows 10

#### 4. User's Name :

  
Filter : `**kerberos.CNameString**`  
Note: If a name is followed by a "$" sign it means that it is a machine account.

![image6-1764231247.png](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/image6-1764231247.png)

Here more ways to find windows User Name if Kerbaros traffic is missing in the packets  
**SMB traffic:**  
SMB host announcement packets consist of the windows host name `“DESKTOP-...”`

![image11-1459048887.png](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/image11-1459048887.png)

If even SMB traffic is missing from packet capture other way to find windows host name is with this:  
Filter: **udp and ip contains DESKTOP-...**  
Note: This method only work from windows10 version.

![image4-1162074335.png](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/image4-1162074335.png)

#### 5. Non-Malicious Traffic

In order to understand malicious traffic you must first understand what non-malicious and normal traffic looks like.  
So go through the following text:  

##### 5.1 _Windows Bootup Traffic_

This is the PCAP image from a windows startup. In 3 minutes, please check this image and familiarize yourself with non-malicious windows traffic. Looking at the traffic of the startup of windows system will help you determine what is normal and what is malicious traffic.

![image3-1096301791.png](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/image3-1096301791.png)

##### 5.2 _Windows Update Download Traffic_

Now, Windows constantly downloads files for applications. For example, for Windows Store. As you will discover in a later lab, most of the malware is distributed via embedding into an image file. It's important to recognize what sources are genuine and non-malicious.

![image5-983783951.png](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/image5-983783951.png)

Follow tcp Stream

![image9-325075222.png](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/image9-325075222.png)

Note: Observe HTTP header. There is no user agent string, which is normal for these downloads. But a malicious image will have a user agent string.

#### 6. _Operating System traffic:_

  
So, whenever there is a USB device plugged into a Windows system, Windows sends two requests to go.microsoft.com and also dmd.metaservices.microsoft.com.

![image19-949373488.png](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/image19-949373488.png)

Windows downloads updates using SWARN protocol, so it's easy to filter out this traffic.

![image1-1910069763.png](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/image1-1910069763.png)

#### 7. _Traffic Caused by Web browsers_

  
Updates for Google and Chromium-based browsers will contain the traffic generated by domains ending in .gvt1.com.

![image16-1219054959.png](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/image16-1219054959.png)

**These are not inclusive of all traffic, but they are the most common ones required for the lab.**

### Common Distribution Methods of Malware

- Email Attachments: Malware is sent via email in the form of an attachment. When the user opens the attachment, the malware is executed on their device.
- Malvertising: Attackers create ads that contain malicious code and place them on legitimate websites. When users click on the ads, they unwittingly download and install malware on their devices.
- Malicious Websites: Malicious websites contain links to or are embedded with malicious code. Users are directed to these sites through phishing emails, social engineering tactics, or other means. Once on the site, users may be prompted to download malware or enter sensitive information.
- Social Engineering: Attackers use psychological manipulation to trick users into performing actions that they would not otherwise perform. Tactics include phishing emails, phone calls, or impersonation to trick users into downloading and installing malware or disclosing sensitive information.
- Drive-by-Download: Malicious code is injected into legitimate websites. When users visit the site, the code is executed and malware is downloaded onto their device.
- File-Sharing Network: Attackers upload malware disguised as legitimate files to popular file-sharing networks. When users download and open the files, the malware is executed on their device.

**Out of these the most popular mass distribution channels are**

**Email Attachments:** The flow is described in following diagram.

![2023-03-22_22_20_11-Clipboard-927136851.png](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/2023-03-22_22_20_11-Clipboard-927136851.png)

![2023-03-22_22_22_17-Clipboard-206403618.png](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/2023-03-22_22_22_17-Clipboard-206403618.png)

**Malvertising:** The distribution flow is described in the following diagram.

![2023-03-22_22_50_01-Clipboard-1569527439.png](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/2023-03-22_22_50_01-Clipboard-1569527439.png)

![2023-03-22_22_50_57-Clipboard-1288780706.png](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/2023-03-22_22_50_57-Clipboard-1288780706.png)

## **Lab 1**

#### Network Diagram

![NetworkDiagram-29001545.jpg](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/NetworkDiagram-29001545.jpg)

### BACKGROUND SCENARIO

Suppose you are a Security Operations Center Engineer and suspect that your network is compromised by malware. To investigate the issue, you capture network traffic using Wireshark, which allows you to analyze the traffic and identify any signs of malicious activity.

First, you select a computer or device on the network that you suspect to be infected with malware. You use this computer to capture the network traffic. To do this, you download and install Wireshark on the computer.

Once Wireshark is installed, you configure it to capture network traffic. To do this, you select the appropriate network interface and set Wireshark to capture all traffic. You may also want to configure Wireshark to filter out any unwanted traffic, such as broadcasts or multicast packets.

Once you configure Wireshark, you start the capture. This begins recording all network traffic on the selected interface. You let the capture run for a period of time, preferably several hours or more, to ensure that you capture enough traffic to analyze.

After the capture is complete, you save the capture file in the PCAP format. This allows you to analyze the traffic using Wireshark or other network analysis tools.

Now as a SOC Engineer, you have two PCAP files captured by Wireshark for a network that has been affected by malicious activities. Your task is to dissect the PCAP files and identify any signs of malicious behavior.

#### Step 0: Getting started

1. Start the lab and let the **System** bootup.

The PCAP files to be analyzed can be found on the repository download it and open it in Wireshark. To open a Terminal window, click on the icon located at the bottom of the menu on the left-hand side called "Show Applications" then type "terminal" in the search field, Enter or click on the black icon as follows:.

![2023-04-06_23_28_57-Clipboard-401086668.png](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/2023-04-06_23_28_57-Clipboard-401086668.png)

2. Type the following commands to copy the zipped file to the Desktop [OS Ubuntu in this demo]
3. Download the Zip of Pcap from the repository 
**student@ubuntu:~$`cd Download`**  
**student@ubuntu:~/Desktop$`unzip MalwareAnalysis1.zip`**  
It will prompt you to enter a password. Type `"infected"` and click "enter"  
**student@ubuntu:~/Desktop$`ls`**  
Now you have a PCAP file on the Desktop called MalwareAnalysis1.pcap29. To open the PCAP file in a wireshark, type:
**student@ubuntu:~/Desktop$`wireshark MalwareAnalysis1.pcap`**  
The following window will pop up:

![WiresharkOpen-1492015328.jpg](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/WiresharkOpen-1492015328.jpg)

#### Step 1: General analysis of the PCAP file

Let us begin the analysis of the network traffic by first determining the duration of the traffic being analyzed and the size of the file.  
Go to menu bar of the wireshark window, click on "Statistics" then choose the first option which is "capture file properties".

![statistics-302050896.jpg](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/statistics-302050896.jpg)

At this time, open a new tab for terminal window and run the following command  
**Grading Script Can be also found in the repository Under Script Folder Download them as well.** 

**student@ubuntu:~/Desktop$`python3 ~/Desktop/script/grading_script1.py`** and you will be able to answer question 1 and question 2.

Next let's find out what are the devices that are communicating on the network via IPv4 whether internal or external by going on again the wireshark menu bar, click on "statistics" and then select "Endpoints". From the Endpoints window, click the "IPv4-16" button to display IPs of all devices under communication on the network captured file.

![Endpoints-335845325.jpg](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/Endpoints-335845325.jpg)

Now you should be able to answer question 3, which asks for the IP address that is used the most for communication in the network.

#### Step 2: Analysis of the infectious malware on HTTP Traffic

Type this command in the wireshark filter windows: `http.request`.  
Once we have filtered the http request to remove irrelevant traffic, we can focus on detecting any suspicious or abnormal activity. Let's now investigate the IPs in the traffic. Upon analysis, we find that certain IPs are making multiple POST requests, which may indicate that they are sharing some information.

It's important to note that Malware traffic is often marked by large volumes of traffic to and from unknown or suspicious IP addresses, or to uncommon or known malicious ports.

Do the right click on the packet, click on "Follow", then "TCP Stream". Find out which packet that will give you the information you need. The following screenshot is similar but not exactly to the one you will be getting.

![infectedIPaddress-759657264.jpg](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/infectedIPaddress-759657264.jpg)

Take note that the information displayed in red signifies the data sent from your host, while the data presented in blue indicates what is received from the established connection.  
You can execute the second script from this point by entering the following command:  
**student@ubuntu:~/Desktop$`python3 script/grading_script2.py`**  
And you are able to answer Question 1 to Question 4 of the second script.

Continue exploring all the packets to identify the ones that have captured the email password of the user account mentioned in question 3.  
Now you are able to answer question 5.  

#### Step 3: Finding out the payloads with the malware traffic

Next, let's Look for any payloads associated with the malware traffic, such as executables, scripts, or data files. You can identify these by looking for unusual file transfers or unusual patterns in the traffic.  
It is important to note that typically, when an executable file is included, the message that appears is "This program cannot be executed in DOS Mode."  
So let's filter the packets with this command: **`ip contains "This program"`** Then follow TCP stream for each packet got to analyze if they contains file signature of "MZ" that stands for **Mark Zbikowski** which is one of the principal architects of MS-DOS and the Windows/DOS executable file format. ![ExecutableFiles-984051089.jpg](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/ExecutableFiles-984051089.jpg)

Once you find that there are packets containing those executable files, locate them and download them by clicking **"File" -> "Exports Objects" -> "HTTP"**. Here is where you will get all the files and select ones you've found from the above filtered packets and save them at ~/Desktop/Lab1/FilesfromPcap.  
Now run the grading script 3 using the following command:  

**student@ubuntu:~/Desktop$`python3 script/grading_script3.py`**  
Here you are able to answer question 1 and question 2.  
  
Then calculate the SHA256 hash of the first and second files by executing the following command  
student@ubuntu:~/Desktop/Lab1$`cd FilesfromPcap`  
student@ubuntu:~/Desktop/Lab1/FilesfromPcap$`sha256sum file1name.png`  
student@ubuntu:~/Desktop/Lab1/FilesfromPcap$`sha256sum file2name.png`  
You are now able to answer question 3 and question 4 of the grading_script3

#### Step 4: Analyze the payloads with the malware analysis tools

Finally, Let's analyze the malware payload using a malware analysis tool such as virustotal.com to determine what the malware does and how it behaves.  
As of Now, you have the hashes you can simply check those on the Online Databases for Malware such as virustotal.com  
For now we have prepared an image file with each hash as their name in the folder called "virustotalResults" which is in "FilesfromPcap" folder  
Now you can answer the question Q1 to Q4 of the grading_script4. By running the script  
**student@ubuntu:~/Desktop$`python3 script/grading_script4.py`**  

Here is where you can report your findings to the appropriate parties, such as your IT security team or law enforcement if necessary.
## **Lab 2**
Note : Close all instance of wireshark  
  
![new-436048620.png](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/new-436048620.png)

As a Security Operations Center agent, it is necessary to report your findings in a comment format after analyzing a PCAP file, as follows:  
“On [date] at [time in UTC], a Windows computer used by [victim's name] was infected with [name of malware, if known].”  
#### Step 0 Setting Up
Open up the PCAP file Lab2.pcap from the folder location '~/Desktop/Lab2' with wireshark  
Also execute the grading_script_5.py in a new terminal window  
**student@ubuntu: $`python3 ~/Desktop/script/grading_script5.py`**  
#### Step 1 Analysis of PCAP.
Let's start by analyzing the PCAP file, best approach is to go into the Statistics tab > Conversation > IPv4 conversion and sort the conversion with size. There is a major conversion with one internal IP address. To confirm this suspicious behavior,let's put a filter on this IP and observe the traffic:  
**`ip.addr == XXX.XXX.XXX.XXX`**  
Now you should be able to answer Q1.  
To find the mac address of the victims there are many ways, you may look into the Ethernet Frame ( Note select the source IP in the packet to get the correct mac).  
Now you should be able to answer Q2.    
Next need to identify the Host and User of the infected device on the network.  
Now you should be able to answer Q3, Q4.  
Hint Q3: Refer Section (1. DHCP Filter)  
Hint Q4: Refer Section (4. User's Name)  
#### Step 2 IOC
Now determining indicator of compromise [IOC]  
The place to start to look for is files associated in the pcap,since to spread a malware some delivery mechanism is needed as discussed in the introduction section and to find out these files in wireshark.  
**Go to: File Tab > Export Object > HTTP Object**  
Now answer the Q5. 
  
Save the files in FilesfromPcap folder within Lab2 folder on Desktop you can use save all button and then execute following cmd in new terminal.  
  
**student@ubuntu:~/Desktop$`cd ~/Desktop/Lab2/FilesfromPcap`**  
**student@ubuntu:~/Lab2/FilesfromPcap$`sha256sum * > hash.txt`**  
**student@ubuntu:~/Lab2/FilesfromPcap$`cat hash.txt`**  
  
Now you have the hashes you can simply check those on the Online Databases for Malware such as virustotal.com  
For now we have prepared a image file located at `/home/student/Desktop/Lab2/virus_Total_Screen_Shot` with each hash as there name  
Now you can answer the question Q6 to Q12.    
Now note, all of the files listed are legitimate DLL's and not inherently malicious. But why are they masked as .jpg so there is something fishy? They are indicators of compromise. The presence of these files should be combined with the network-based IOC's as listed below to form a holistic assessment.  
  
So let's find the network based indicators now.  
For this open up the PCAP in wireshark put the filter as following 
**`ip.addr == XXX.XXX.XXX.XXX && http.request.method == POST`**  
Note: XXX.XXX.XXX.XXX is the infected system IP you found previously  
Analyze the traffic and find out the post request in which a .zip file is sent to the attacker through a post request at port 80  
Now you can answer the question Q13.  
If you would download the .zip file and extract it and go thought it you will encounter data from the victim's system, containing multiple autofill text files, cookies, and credentials were exfiltrated.   
Now combining the information from Host-Base Indicator and Network-Based indicator and researching these factors we came across this site "Meet Oski Stealer: An In-depth Analysis of the Popular Credential Stealer (cyberark.com)" [attached as pdf as well of site screenshot] indicate this is a **Oski Stealer Malware**.  
Thus completing the final analysis.  
Now you can answer the question Q14.  

![2023-03-23_19_53_19-Clipboard-1675344019.png](https://topomojo.ini.cmu.edu/docs/281c115265f447f09c993d784ef99093/2023-03-23_19_53_19-Clipboard-1675344019.png)

## **Conclusion:**

We explored the complexities of evaluating a PCAP carrying malicious network traffic in this lab. Investigating the spread of the malicious activities and finding the underlying infection were our main goals. The analysis's methodology only partially addressed malware and attacks that are frequently launched against enterprise networks.  
The lab gave an overview of the key procedures involved in network traffic analysis to find malicious activities. We learnt how to examine network data with Wireshark and spot anomalies that can point to nefarious behavior. Additionally, we investigated various approaches of analyzing the malware itself in order to comprehend its behavior and properties.  
It is important to remember that the methodology and tools for analysis we reviewed in this lab just scratch the surface of what is necessary for a thorough investigation into network security. A successful security analysis requires a thorough understanding of various malware and attacks, knowledge of the network infrastructure, and proficiency in using different network security tools.  
As a wrap-up, this lab introduced us to the core ideas and methods involved in network traffic analysis for security purposes. It provided as a foundation for deeper investigation into the many approaches and technologies that security professionals might use to detect and prevent hostile behavior on networks.

### Reference:

- [https://www.virustotal.com/](https://www.virustotal.com/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://www.cyberark.com/resources/threat-research-blog/meet-oski-stealer-an-in-depth-analysis-of-the-popular-credential-stealer](https://www.cyberark.com/resources/threat-research-blog/meet-oski-stealer-an-in-depth-analysis-of-the-popular-credential-stealer)
- [https://tryhackme.com/room/wiresharkthebasics](https://tryhackme.com/room/wiresharkthebasics)
- [https://www.malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/)
