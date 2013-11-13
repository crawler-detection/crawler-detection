A simple python script to identify and classify possible crawlers through analysis of web server log files. The script categorizes identified web crawlers in to three as "known", "suspicious" and "other".

This works with log files in Apache common log format describe below. 


format = r'%V %h  %l %u %t \"%r\" %>s %b \"%i\" \"%{User-Agent}i\" %T'
%V          - the server name according to the UseCanonicalName setting
%h          - remote host (ie the client IP)
%l          - identity of the user 
%u          - user name determined by HTTP authentication
%t          - time the server finished processing the request.
%r          - request line from the client. ("GET / HTTP/1.0")
%>s         - status code sent from the server to the client (200, 404 etc.)
%b          - size of the response to the client (in bytes)
\"%i\"      - Referer is the page that linked to this URL.
User-agent  - the browser identification string
%T          - Apache request time 

If your log files are not in this format first you have to convert them before-hand. This script suppose hidden links are implemented in the web site using terms “link1.html” ,”link2.html” and “link3.html” although it is not compulsory.

Note that you need Internet connection in order to completely run this program
Usage

    Put the log file in the same folder where the crawler-detection.py script is placed.
    In the terminal run following command.

    python crawler-detection.py <name of your log file>

    At the end of running the script following text files will be generated. Bolded ones in the following list contain details of "known","suspicious" and "other" crawler sessions.
        hiddenlinks Accessed
        Known Crawlers
        honeypot
        whois
        robots.txt Accessed
        Suspicious Crawlers
        PossibleCrawlers?
        Not Known Crawlers
        blacklistIps
        Other Crawlers 

Notes

Current script is not implemented as a python package and it is meant for prototyping. 
