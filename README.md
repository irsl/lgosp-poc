LG On Screen Phone authentication bypass PoC
============================================

What is LG On Screen Phone?
---------------------------
The LG On-Screen Phone application (OSP) makes it easy to access and control LG’s Android smartphones through a PC. The connection can be established either by using an USB cable or wirelessly through Wi-Fi or Bluetooth. When attempting to connect to the phone via OSP, a popup dialog is displayed on the phone and it is to be confirmed and accepted by the owner. Once the channel is established, the screen contents of the device are being transmitted to the PC as a motion stream, mouse clicks on the PC are turned into touch events on the phone. By using OSP one can control an LG Smart Phone just like it was in their hands.

Authentication bypass vulnerability
-----------------------------------
SEARCH-LAB Ltd. discovered a serious security vulnerability in the On Screen Phone protocol used by LG Smart Phones. A malicious attacker is able to bypass the authentication phase of the network communication, and thus establish a connection to the On Screen Phone application without the owner’s knowledge or consent. Once connected, the attacker could have full control over the phone – even without physical access to it. The attacker needs only access to the same local network as the phone is connected to, for example via Wi-Fi.

CVE
---
The ID CVE-2014-8757 was assigned to this vulnerability.

Affected Versions
-----------------
LG On Screen Phone v4.3.009 (inclusive) and older versions of the application are vulnerable.
This vulnerability was fixed in LG OSP v4.3.010

Most smart phone models of LG are affected and the OSP application is even preinstalled, and there is no
option to uninstall or stop it. On newer models, like G3 the OSP application is not preinstalled anymore.

Proof of Concept
----------------
The Proof of Concept code was tested against G1 and G2 models.

This osp-discovery helper script listens for discovery broadcast messages of the official LG On Screen Phone 
application and answers them, so the application would believe a Phone running OSP is available locally.

The osp-proxy script excepts the official LG On Screen Phone application would connect to it,
which is possible by running osp-discovery.pl. 


Recommendations
---------------
*End Users*: Update the OSP appliaction to revision 4.3.010 or newer through LG Update Center.

