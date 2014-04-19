#### Heartbleed Script for Vulnerable Tor Exit Nodes
====================
This script takes in a list of Tor exit nodes. It assumes that they run on port 443. Iterates through the list every 5 minutes and if the script succeeds for an exit node, it runs the exploit four more times on the same node, and moves on to the next one on the list.

##### Improvements to be made:
  - Currently the script only tries port 443, and gives up if it fails. Tor's exit node list can be parsed keeping the port in mind, and the list can have entries in the form of <ip>:<port>.
  - The script fetches the maximum amount of memory that can be fetched. Fetching smaller amounts might result in acquiring different memory locations, leading to more sensitive information being revealed.

Feel free to make changes to the code and put a pull request.
Contact me if you have any questions or improvements to the code.
