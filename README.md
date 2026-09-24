#I) reaver-er 
Automates reaver+pixie-dust attacks on surrounding WPS-capable routers. Requires: 
	
	** input interface to be already in MONITOR MODE (use airmon-ng for that)
	** needs to be run as sudo
	** airodump-ng (with WPS feature; version 1.2 & up), reaver & pixie-dust to be already installed on your system

DISCLAIMER: the way the stdouts, stderrs and pipes are handled could posibly be improved and done in fewer lines of code. Not too worried about that for the moment, as long as the script works.



#II) connGs 
generates both the adjacency and distance matrices of a graph representation input by user, and tells user whether the graph entered is connected or not. User input for graph must follow this format:
	
	** argv[2] = # of vertices
        ** argv[3:last-1] = every 2 elements defines an edge; size of sub-stream must be even 
        ** argv[last] == -1

Input example: ./connGs 5 0 1 1 4 2 3 1 3 3 4 -1, refers to a graph of 5 vertices with edges (0 1), (1 4), (2 3), (1 3), (3 4)

#III) iptabler_ 
script for adding iptables rules.  Requires a formatted .txt file called "iptabler_rules.txt", with valid iptable rules and comments beginning with character "#".  See example for details.


#IV) movie-grabber
Python app that watches a list of movie titles, searches torrent sites on a schedule (X times every Y hours/days) for 1080p BluRay/WEB (VOD) rips from preferred groups (YTS, YIFY, ...), downloads them with qBittorrent, files them into the Plex library as "Title (Year)/Title (Year).ext" and emails you when done. See movie-grabber/README.md for setup (Ubuntu + systemd).
