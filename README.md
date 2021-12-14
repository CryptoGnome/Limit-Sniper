# Limit Sniper
A mempool sniping bot for Ethereum, Binance Smart Chain, Matic, &amp; Fantom that is able to scan for new liquidity adds on token launches, so as to be able to buy a token as soon as liquidity is added --> in the same block

*This bot was built as a learning project for me to learn how to use Web.py, Erc20, & improve my coding skills please use at your own risk!*

#### Grab the Latest Release:
https://github.com/CryptoGnome/Limit-Sniper/releases

## HOW TO INSTALL Sniper Bot
There are 3 ways to install Sniper Bot : 

&nbsp;


### 1. Run The Python Code Locally [*this is most ideal and can work on any OS*]
Here is a tutorial step-by-step: 
- [x] Download last Sniper Bot code on the "Code" page https://github.com/CryptoGnome/Limit-Sniper by clicking on Code > Download Zip: 
<img src="https://user-images.githubusercontent.com/70858574/145568534-e22c2887-d761-4fba-8dd0-f765b4300a6c.png" width="300">

- [x] Unzip file
- [x] Install Python on your computer : https://www.python.org/downloads/ 

**PLEASE ADD IT TO PATH BY CHECKING THIS OPTION:**

<img src="https://user-images.githubusercontent.com/70858574/145692350-b2cb248a-8888-4471-8a63-2b6654e9b671.png" width="500">

- [x] Install Visual Studio : https://visualstudio.microsoft.com/fr/thank-you-downloading-visual-studio/?sku=Community&rel=17

Please install the default package and all those options :
![image](https://user-images.githubusercontent.com/70858574/145580447-bd648d6d-c3ce-4dd9-8527-84ecfb5f30cc.png)

- [x] Open **Windows Powershell** (or Mac Terminal on MacOs)

- [X] Run this command to locate Sniper folder : 

`Get-ChildItem -Filter sniper.py -Recurse -ErrorAction SilentlyContinue -Force`

- [x] It should look like this:

<img src="https://user-images.githubusercontent.com/70858574/145731245-21a90bd0-7d4d-43b0-b05d-8275bedd83b3.png" width="700">

- [X] Copy the Directory 

(example : `C:\Users\Administrator\Desktop\Limit-Sniper-main`)

- [X] Paste the Directory after the "cd" command to navigate through the bot folder 

(example : `cd C:\Users\Administrator\Desktop\Limit-Sniper-main`)

<img src="https://user-images.githubusercontent.com/70858574/145731342-1d707da4-084b-41cc-b714-2e987125e07e.png" width="700">

- [x] Run command: `pip install -r requirements.txt`  --> this will install all the packages needed to run LimitSwap

&nbsp;

✅ ✅ ✅ And it's done! ✅ ✅ ✅

&nbsp;

- [x] Simply **double-click on "sniper.py"** and it will run, since you've installed Python 👍👍

&nbsp;

#### Pros and cons
🟢 : you are sure of the code that is running on your computer

🔴 : little bit complicated

&nbsp;
&nbsp;

### 2. Download the pre-compiled package [*This can lag behind current version*]
That we provide on the Release page : it's a .exe file that you can run on your computer.
https://github.com/CryptoGnome/Limit-Sniper/releases

#### Pros and cons
🟢 : very easy to setup

🔴 : it's pre-compiled, so you cannot check the Source Code

&nbsp;
&nbsp;

### 3. With Docker

#### Requirements
MacOS and Windows users require Docker for Desktop https://www.docker.com/products/docker-desktop
Ubuntu Linux require Docker installed `sudo apt-get install docker.io`

#### Usage
Navigate into the bot directory and build the Docker image by executing the following command:

`docker build -t limit_sniper .`

(For MacOS and Linux) Still within the main directory you can run Docker via:

`docker run --rm --name limit-sniper -it -v $(pwd)/settings.json:/app/settings.json -v $(pwd)/tokens.json:/app/tokens.json limit_sniper`

(For Windows with Powershell)

`docker run --rm --name limit-sniper -it -v $PWD/settings.json:/app/settings.json -v $PWD/tokens.json:/app/tokens.json limit_sniper`

If you wish to run the container in the background please include -d for detached.

The streaming container logs can be visualised with `docker logs -f limit_sniper`

To stop the bot `docker stop limit_sniper`

#### Pros and cons
🟢 : easy to setup if you know Docker

🔴 : needs Docker

&nbsp;

&nbsp;

![alt text](https://gblobscdn.gitbook.com/assets%2F-MZTPzgUqGxiIf6m_uoa%2F-MdT8RECUAK42MnmqRTa%2F-MdT9crcWoeNiTkmhokB%2Fsniper-works.png)


## Developers 🔧
Want to help contribute to LimitSwap, reach out on telegram all you need to do is make changes or fix bugs and we will pay developer bounties in $LIMIT for helping make the bot batter!

## Links & Socials:

#### WiKi
https://limitswapv3.gitbook.io/limitswap/

#### Website:
https://www.limitswap.com/

#### Twitter:
https://twitter.com/LimitSwap

#### Telegram:
https://t.me/LimitSwap
