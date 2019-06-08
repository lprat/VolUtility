# VolUtility
Web Interface for Volatility Memory Analysis framework from https://github.com/kevthehermit/VolUtility with modified by https://github.com/kisec/VolUtility & https://github.com/matandobr/VolUtility
Juste clone of https://github.com/kisec/VolUtility and added feature:
- docker-compose
- add plugin psinfo && autorun
- yarascan with yara community base
- view of plugin yara optimized + stat
- stat on timeliner
- add floss & capstone pdbparse on dependency
- add script python for automtic add image in volutility

## Run
 - cd docker && docker-compose up
 - run your navigatore on http://your_ip:8080

## Nginx
 - You can use nginx reverse for add ssl & auth htpasswd (change docker-compose for listen on internal ip docker)

## Overview
Runs plugins and stores the output in a mongo database. 
Extracts files from plugins (that support dump-dir) and stores them in the database
Search across all plugins and file content with string search and yara rules.
Allows you to work on multiple images in one database

Video Demo showing some of the features.
https://www.youtube.com/watch?v=ruEj94Zhn6I

## Wiki

See the wiki pages for detailed installation and usage details.

https://github.com/kevthehermit/VolUtility/wiki
  
  
## Help

## Thanks
 - Volatility Foundation for writing Volatility - http://www.volatilityfoundation.org/
 - Alissa Torres for teaching me memory via SANS FOR526 - https://twitter.com/sibertor
 - Using volatility as a library - http://dsocon.blogspot.co.uk/2012/08/using-volatility-framework-as-library.html
 - James Habben's origional eVolve concept - https://github.com/JamesHabben/evolve
