# Securly Classroom 4 Windows : Vulnerability Write-Up
### Authored by Katt on March 6th, 2025.
---
## Background
Hi there, this is a collection of my security research into the Windows application for Securly Classroom. My intention with this week-long project was to examine Classroom under a microscope and try and find potential vulnerabilities.
I have tested some vulnerabilities, others I have not tested and I don't know whether or not they are an actual issue.

These shouldn't be used to "bypass Securly" in any educational setting. I had permission to do this from my school's IT department and that is the only reason I am able to put together this report of what I found and whether or not it works.
If there is no test data for any given file that it was not tested.

I wrote a majority of these in Python because that is something that most schools will allow their students access to for courses based around computer science. I've designed all of the Python code I've written in this repository to work with most newer versions of Python.
Python files should generally require above Python 3.6 at the minimum for these vulnerabilities to be tested. (pip was used in proof-of-concept files and actual testing files were standalone)

This is only covering the Securly Classroom app for Windows because that is what I had an interest in looking into and pentesting. The browser extension is breifly mentioned with some potential vulnerabilities that I have not verified.

Questions? Contact me via email or via something like [HackerOne](https://hackerone.com/cosmosrolling)
---
## Methodology
The approach I took to this week-long hobby is that I went through and recorded things that interested me in a Google Doc for later review. Some files were decompiled using JetBrains DotPeek, which is a tool that allows for .NET applications
to be decompiled and this app can be installed and run on a Windows machine without requiring administrator permissions so it can theoretically be used in an educational setting.

#### In general part of my approach was to look across the codebase for a given vulnerability instead of focusing on finding specific vulnerabilities in a specific file. The only exception to this would be what I'm nicknaming the "clay vulnerability" which uses the cassiusclay argument when spawning a Classroom instance to theoretically get another user's activity.
---
## Notes & Interesting bits
Through this and just generally looking around I was able to connect several domains back to Securly such as the following:
- [techpilotlabs.com](https://techpilotlabs.com) (This is what Securly uses to create the block pages.) (Also the name of the pug is Pepita)
- [oauth.dyknow.me](https://dyknow.me) (For the landing website see [dyknow.com](https://dyknow.com))
- Each installation/domain seemingly has a similar hard-coded UID that seemingly is used for API requests. I didn't look into this one much so I have not clue why.
- Generally most requests are sent via POST to `https://org<id>.deviceconsole.securly.com` except for what seems to be a background updater which sends requests to https://classroom-updates.securly.com/v1/update. (This also includes URL params like the machine name, username, domain, etc.)
- The browser extension seems to be most commonly bypassed using `javascript://*` or via the (Stop) and (Unregister) buttons inside of `chrome://serviceworker-internals` based on [https://www.reddit.com/r/SecurlyBypasses/](https://www.reddit.com/r/SecurlyBypasses/). (I am not endorsing bypassing Securly, just providing a source.)
- There is some seemingly arbitrary requests to `https://org<id>.deviceconsole.securly.com`/win/fire and /win/handle which are not documented within Securly in any capacity and without a tool like Wireshark it's basically impossible to tell exactly what the request is from the client side.
---
## Why are these issue important?
Even though a majority of devices in schools are ChromeOS, Windows is still frequently used in places like technology labs where students will likely be and will trust the computers with their student data/information.
It's important that these tools be secure so that a threat actor cannot exploit them to determine what a given student is doing or what they were doing earlier. (Securly's logs show who was logged in and when, generally with a large number of errors around these events.)
This is a shared responsibility in my opinion, the application should be secure and dependable but staff should also be aware of what a student is doing, even if they've either completely or tried to bypass any form of screen sharing and such.

#### That being said allowing the application to allow regular users permissions like some of the ones given by Securly to do things like use the clay vulnerability to gather a list of what other students are doing or allowing them to theoretically access the IPCs of Securly.
#### Securly's logs are encrypted in what seems to be an attempt to rectify the fact that their logs show a large amount of information but the fact that the encryption keys are hard-coded makes it incredibly easy to reverse the encryption and then convert the log out of binary and discover who used a given computer and what they did.
---
## What proof of these exploits do you have
The evidence I have for these exploits can be seen in my log file, `hellothere.vpk` which is from a test I performed earlier today with oversight. 

#### For what should be obvious reasons I will not be sharing the Securly Classroom code in any portion or in full to anybody, regardless of how you ask. My goal with this was to find potential security vulnerabilities, not to share Securly's source code.
---
## Closing
The exploits and vulnerabilities that I have shared in this repository are intended for security use or cannot be used directly to achive any potential goal.

The activitymonitor oversight is included as I believe that it is critical that Securly is aware of the potential issues that can arise from that being in the production application as part of the clay vulnerability.
Every other piece of code within this repository is designed for testing only and cannot be used to directly achive any security oversight like running administrator commands without additional tools.

I'm doing this not only because it seemed interesting to me, but also so that Securly can patch or resolve some of the vulnerabilities I've mention or that are included in this repo.

##### I am having to assume the best way to go about this due to the fact that Securly does not have an obvious bug-bounty program or set of instructions/scopes. (It would be appreachated to see a specific resource regarding what and how to pentest similar to [GitHub's bug bounty program](https://bounty.github.com/).)
---
