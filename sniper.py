from web3 import Web3
from time import sleep, time
import json
from decimal import Decimal
import os
from web3.exceptions import ABIFunctionNotFound, TransactionNotFound, BadFunctionCallOutput
import logging
from datetime import datetime
import requests
import sys
import cryptocode, re, pwinput

# global used to track if any settings need to be written to file
settings_changed = False

def timestamp():
    timestamp = time()
    dt_object = datetime.fromtimestamp(timestamp)
    return dt_object


"""""""""""""""""""""""""""
//ERROR LOGGING
"""""""""""""""""""""""""""
log_format = '%(levelname)s: %(asctime)s %(message)s'
logging.basicConfig(filename='./logs/errors.log',
                    level=logging.INFO,
                    format=log_format)


logging.info("*************************************************************************************")
logging.info("For Help & To Learn More About how the bot works please visit our wiki here:")
logging.info("https://cryptognome.gitbook.io/limitswap/")
logging.info("*************************************************************************************")



"""""""""""""""""""""""""""
//PRELOAD
"""""""""""""""""""""""""""
print(timestamp(), "Preloading Data")
f = open('./settings.json', )
settings = json.load(f)[0]
f.close()

directory = './abi/'
filename = "standard.json"
file_path = os.path.join(directory, filename)
with open(file_path) as json_file:
    standardAbi = json.load(json_file)

directory = './abi/'
filename = "lp.json"
file_path = os.path.join(directory, filename)
with open(file_path) as json_file:
    lpAbi = json.load(json_file)

directory = './abi/'
filename = "router.json"
file_path = os.path.join(directory, filename)
with open(file_path) as json_file:
    routerAbi = json.load(json_file)

directory = './abi/'
filename = "factory2.json"
file_path = os.path.join(directory, filename)
with open(file_path) as json_file:
    factoryAbi = json.load(json_file)

directory = './abi/'
filename = "koffee.json"
file_path = os.path.join(directory, filename)
with open(file_path) as json_file:
    koffeeAbi = json.load(json_file)

directory = './abi/'
filename = "pangolin.json"
file_path = os.path.join(directory, filename)
with open(file_path) as json_file:
    pangolinAbi = json.load(json_file)

directory = './abi/'
filename = "joeRouter.json"
file_path = os.path.join(directory, filename)
with open(file_path) as json_file:
    joeRouter = json.load(json_file)

"""""""""""""""""""""""""""
//NETWORKS SELECT
"""""""""""""""""""""""""""

if settings['EXCHANGE'].lower() == 'pancakeswap':
    if settings['USECUSTOMNODE'].lower() == 'true':
        my_provider = settings['CUSTOMNODE']
        print(timestamp(), 'Using custom mode.')
    else:
        my_provider = "https://bsc-dataseed4.defibit.io"

    if not my_provider:
        print(timestamp(), 'Custom node empty. Exiting')
        exit(1)

    if my_provider[0].lower() == 'h':
        print(timestamp(), 'Using HTTPProvider')
        client = Web3(Web3.HTTPProvider(my_provider))
    elif my_provider[0].lower() == 'w':
        print(timestamp(), 'Using WebsocketProvider')
        client = Web3(Web3.WebsocketProvider(my_provider))
    else:
        print(timestamp(), 'Using IPCProvider')
        client = Web3(Web3.IPCProvider(my_provider))
    
    print(timestamp(), "Binance Smart Chain Connected =", client.isConnected())
    print(timestamp(), "Loading Smart Contracts...")

    routerAddress = Web3.toChecksumAddress("0x10ED43C718714eb63d5aA57B78B54704E256024E")
    factoryAddress = Web3.toChecksumAddress("0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73")

    routerContract = client.eth.contract(address=routerAddress, abi=routerAbi)
    factoryContract = client.eth.contract(address=factoryAddress, abi=factoryAbi)
    weth = Web3.toChecksumAddress("0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c")
    base_symbol = "BNB"
    modified = False

if settings['EXCHANGE'].lower() == 'traderjoe':

    if settings['USECUSTOMNODE'].lower() == 'true':
        my_provider = settings['CUSTOMNODE']
        print(timestamp(), 'Using custom mode.')
    else:
        my_provider = "https://api.avax.network/ext/bc/C/rpc"

    client = Web3(Web3.HTTPProvider(my_provider))
    print(timestamp(), "AVAX Smart Chain Connected =", client.isConnected())
    print(timestamp(), "Loading Smart Contracts...")


    routerAddress = Web3.toChecksumAddress("0x60aE616a2155Ee3d9A68541Ba4544862310933d4")
    factoryAddress = Web3.toChecksumAddress("0x9Ad6C38BE94206cA50bb0d90783181662f0Cfa10")


    routerContract = client.eth.contract(address=routerAddress, abi=joeRouter)
    factoryContract = client.eth.contract(address=factoryAddress, abi=factoryAbi)
    weth = Web3.toChecksumAddress("0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7")
    base_symbol = "AVAX"
    modified = True

elif settings['EXCHANGE'].lower() == 'apeswap':
    if settings['USECUSTOMNODE'].lower() == 'true':
        my_provider = settings['CUSTOMNODE']
        print(timestamp(), 'Using custom mode.')
    else:
        my_provider = "https://bsc-dataseed4.defibit.io"
    
    if not my_provider:
        print(timestamp(), 'Custom node empty. Exiting')
        exit(1)

    if my_provider[0].lower() == 'h':
        print(timestamp(), 'Using HTTPProvider')
        client = Web3(Web3.HTTPProvider(my_provider))
    elif my_provider[0].lower() == 'w':
        print(timestamp(), 'Using WebsocketProvider')
        client = Web3(Web3.WebsocketProvider(my_provider))
    else:
        print(timestamp(), 'Using IPCProvider')
        client = Web3(Web3.IPCProvider(my_provider))

    print(timestamp(), "Binance Smart Chain Connected =", client.isConnected())
    print(timestamp(), "Loading ApeSwap Smart Contracts...")

    routerAddress = Web3.toChecksumAddress("0xcF0feBd3f17CEf5b47b0cD257aCf6025c5BFf3b7")
    factoryAddress = Web3.toChecksumAddress("0x0841BD0B734E4F5853f0dD8d7Ea041c241fb0Da6")

    routerContract = client.eth.contract(address=routerAddress, abi=routerAbi)
    factoryContract = client.eth.contract(address=factoryAddress, abi=factoryAbi)

    weth = Web3.toChecksumAddress("0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c")
    busd = Web3.toChecksumAddress("0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56")
    base_symbol = "BNB"
    modified = False

elif settings["EXCHANGE"].lower() == 'uniswap':
    if settings['USECUSTOMNODE'].lower() == 'true':
        my_provider = settings['CUSTOMNODE']
        print(timestamp(), 'Using custom mode.')
    else:
        my_provider = "https://pedantic-montalcini:lair-essay-ranger-rigid-hardy-petted@nd-857-678-344.p2pify.com"

    if not my_provider:
        print(timestamp(), 'Custom node empty. Exiting')
        exit(1)

    if my_provider[0].lower() == 'h':
        print(timestamp(), 'Using HTTPProvider')
        client = Web3(Web3.HTTPProvider(my_provider))
    elif my_provider[0].lower() == 'w':
        print(timestamp(), 'Using WebsocketProvider')
        client = Web3(Web3.WebsocketProvider(my_provider))
    else:
        print(timestamp(), 'Using IPCProvider')
        client = Web3(Web3.IPCProvider(my_provider))
    
    print(timestamp(), "Uniswap Chain Connected =", client.isConnected())
    print(timestamp(), "Loading Smart Contracts...")
    routerAddress = Web3.toChecksumAddress("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D")
    factoryAddress = Web3.toChecksumAddress("0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f")
    routerContract = client.eth.contract(address=routerAddress, abi=routerAbi)
    factoryContract = client.eth.contract(address=factoryAddress, abi=factoryAbi)
    weth = Web3.toChecksumAddress("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
    base_symbol = "ETH"
    modified = False

elif settings["EXCHANGE"].lower() == 'kuswap':
    if settings['USECUSTOMNODE'].lower() == 'true':
        my_provider = settings['CUSTOMNODE']
        print(timestamp(), 'Using custom mode.')
    else:
        my_provider = "https://rpc-mainnet.kcc.network"

    client = Web3(Web3.HTTPProvider(my_provider))
    print(timestamp(), "Kucoin Chain Connected =", client.isConnected())
    print(timestamp(), "Loading KuSwap Smart Contracts...")
    routerAddress = Web3.toChecksumAddress("0xa58350d6dee8441aa42754346860e3545cc83cda")
    factoryAddress = Web3.toChecksumAddress("0xAE46cBBCDFBa3bE0F02F463Ec5486eBB4e2e65Ae")
    routerContract = client.eth.contract(address=routerAddress, abi=routerAbi)
    factoryContract = client.eth.contract(address=factoryAddress, abi=factoryAbi)
    weth = Web3.toChecksumAddress("0x4446Fc4eb47f2f6586f9fAAb68B3498F86C07521")
    base_symbol = "KCS"
    modified = False

elif settings["EXCHANGE"].lower() == 'koffeeswap':
    if settings['USECUSTOMNODE'].lower() == 'true':
        my_provider = settings['CUSTOMNODE']
    else:
        my_provider = "https://rpc-mainnet.kcc.network"

    client = Web3(Web3.HTTPProvider(my_provider))
    print(timestamp(), "Kucoin Chain Connected =", client.isConnected())
    print(timestamp(), "Loading KoffeeSwap Smart Contracts...")
    routerAddress = Web3.toChecksumAddress("0xc0fFee0000C824D24E0F280f1e4D21152625742b")
    factoryAddress = Web3.toChecksumAddress("0xC0fFeE00000e1439651C6aD025ea2A71ED7F3Eab")
    routerContract = client.eth.contract(address=routerAddress, abi=koffeeAbi)
    factoryContract = client.eth.contract(address=factoryAddress, abi=factoryAbi)
    weth = Web3.toChecksumAddress("0x4446Fc4eb47f2f6586f9fAAb68B3498F86C07521")
    base_symbol = "KCS"
    modified = True

elif settings["EXCHANGE"].lower() == 'spookyswap':
    if settings['USECUSTOMNODE'].lower() == 'true':
        my_provider = settings['CUSTOMNODE']
        print(timestamp(), 'Using custom mode.')
    else:
        my_provider = "https://rpcapi.fantom.network"

    client = Web3(Web3.HTTPProvider(my_provider))
    print(timestamp(), "FANTOM Chain Connected =", client.isConnected())
    print(timestamp(), "Loading Smart Contracts...")
    routerAddress = Web3.toChecksumAddress("0xF491e7B69E4244ad4002BC14e878a34207E38c29")
    factoryAddress = Web3.toChecksumAddress("0x152eE697f2E276fA89E96742e9bB9aB1F2E61bE3")
    routerContract = client.eth.contract(address=routerAddress, abi=routerAbi)
    factoryContract = client.eth.contract(address=factoryAddress, abi=factoryAbi)
    weth = Web3.toChecksumAddress("0x21be370d5312f44cb42ce377bc9b8a0cef1a4c83")
    base_symbol = "FTM"
    modified = False

elif settings["EXCHANGE"].lower() == 'spiritswap':
    if settings['USECUSTOMNODE'].lower() == 'true':
        my_provider = settings['CUSTOMNODE']
        print(timestamp(), 'Using custom mode.')
    else:
        my_provider = "https://rpcapi.fantom.network"

    client = Web3(Web3.HTTPProvider(my_provider))
    print(timestamp(), "FANTOM Chain Connected =", client.isConnected())
    print(timestamp(), "Loading Smart Contracts...")
    routerAddress = Web3.toChecksumAddress("0x16327E3FbDaCA3bcF7E38F5Af2599D2DDc33aE52")
    factoryAddress = Web3.toChecksumAddress("0xEF45d134b73241eDa7703fa787148D9C9F4950b0")
    routerContract = client.eth.contract(address=routerAddress, abi=routerAbi)
    factoryContract = client.eth.contract(address=factoryAddress, abi=factoryAbi)
    weth = Web3.toChecksumAddress("0x21be370d5312f44cb42ce377bc9b8a0cef1a4c83")
    base_symbol = "FTM"
    modified = False

elif settings["EXCHANGE"].lower() == 'quickswap':
    if settings['USECUSTOMNODE'].lower() == 'true':
        my_provider = settings['CUSTOMNODE']
        print(timestamp(), 'Using custom mode.')
    else:
        my_provider = "https://rpc-mainnet.matic.network"

    client = Web3(Web3.HTTPProvider(my_provider))
    print(timestamp(), "Matic Chain Connected =", client.isConnected())
    print(timestamp(), "Loading Smart Contracts...")
    routerAddress = Web3.toChecksumAddress("0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff")
    factoryAddress = Web3.toChecksumAddress("0x5757371414417b8c6caad45baef941abc7d3ab32")
    routerContract = client.eth.contract(address=routerAddress, abi=routerAbi)
    factoryContract = client.eth.contract(address=factoryAddress, abi=factoryAbi)
    weth = Web3.toChecksumAddress("0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270")
    base_symbol = "MATIC"
    modified = False

elif settings["EXCHANGE"].lower() == 'waultswap':
    if settings['USECUSTOMNODE'].lower() == 'true':
        my_provider = settings['CUSTOMNODE']
        print(timestamp(), 'Using custom mode.')
    else:
        my_provider = "https://rpc-waultfinance-mainnet.maticvigil.com/v1/0bc1bb1691429f1eeee66b2a4b919c279d83d6b0"

    client = Web3(Web3.HTTPProvider(my_provider))
    print(timestamp(), "Matic Chain Connected =", client.isConnected())
    print(timestamp(), "Loading Smart Contracts...")
    routerAddress = Web3.toChecksumAddress("0x3a1D87f206D12415f5b0A33E786967680AAb4f6d")
    factoryAddress = Web3.toChecksumAddress("0xa98ea6356A316b44Bf710D5f9b6b4eA0081409Ef")
    routerContract = client.eth.contract(address=routerAddress, abi=routerAbi)
    factoryContract = client.eth.contract(address=factoryAddress, abi=factoryAbi)
    weth = Web3.toChecksumAddress("0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270")
    base_symbol = "MATIC"
    modified = False

elif settings["EXCHANGE"].lower() == 'pangolin':
    if settings['USECUSTOMNODE'].lower() == 'true':
        my_provider = settings['CUSTOMNODE']
        print(timestamp(), 'Using custom mode.')
    else:
        my_provider = "https://api.avax.network/ext/bc/C/rpc"

    client = Web3(Web3.HTTPProvider(my_provider))
    print(timestamp(), "AVAX Chain Connected =", client.isConnected())
    print(timestamp(), "Loading Smart Contracts...")
    routerAddress = Web3.toChecksumAddress("0xE54Ca86531e17Ef3616d22Ca28b0D458b6C89106")
    factoryAddress = Web3.toChecksumAddress("0xefa94DE7a4656D787667C749f7E1223D71E9FD88")
    routerContract = client.eth.contract(address=routerAddress, abi=pangolinAbi)
    factoryContract = client.eth.contract(address=factoryAddress, abi=factoryAbi)
    weth = Web3.toChecksumAddress("0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7")
    base_symbol = "AVAX"
    modified = True


def get_password():
    
    global settings_changed
    setnewpassword = False

    # Check to see if the user has a version of the settings file before private key encryption existed
    if 'ENCRYPTPRIVATEKEYS' not in settings:
        response = ""
        settings_changed = True
        while response != "y" and response != "n":
            print ("\nWould you like to use a password to encrypt your private keys?")
            response = input ("You will need to input this password each time LimitSniper is executed (y/n): ")
    
        if response == "y":
            settings['ENCRYPTPRIVATEKEYS'] = "true"
            setnewpassword = True
        else:
            settings['ENCRYPTPRIVATEKEYS'] = "false"  

    # If the user wants to encrypt their private keys, but we don't have an encrypted private key recorded, we need to ask for a password
    elif settings['ENCRYPTPRIVATEKEYS'] == "true" and not settings['PRIVATEKEY'].startswith('aes:'):
        print ("\nPlease create a password to encrypt your private keys.")
        setnewpassword = True

    # Set a new password when necessary
    if setnewpassword == True:
        settings_changed = True
        passwords_differ = True
        while passwords_differ:
            pwd = pwinput.pwinput(prompt="\nType your new password: ")
            pwd2 = pwinput.pwinput(prompt="\nType your new password again: ")
            
            if pwd != pwd2:
                print ("Error, password mismatch. Try again.")
            else:
                passwords_differ = False
    
    # The user already has encrypted private keys. Accept a password so we can unencrypt them
    elif settings['ENCRYPTPRIVATEKEYS'] == "true":

        pwd = pwinput.pwinput(prompt="\nPlease specify the password to decrypt your keys: ")

    else:
        pwd = ""

    if not pwd.strip():
        print ()
        print ("X WARNING =-= WARNING =-= WARNING =-= WARNING =-= WARNING =-= WARNING=-= WARNING X")
        print ("X      You are running LimitSniper without encrypting your private keys.         X")
        print ("X     Private keys are stored on disk unencrypted and can be accessed by         X")
        print ("X anyone with access to the file system, including the Systems/VPS administrator X")
        print ("X       and anyone with physical access to the machine or hard drives.           X")
        print ("X WARNING =-= WARNING =-= WARNING =-= WARNING =-= WARNING =-= WARNING=-= WARNING X")
        print ()

    return pwd

def save_settings(pwd):
    
    global settings_changed

    if len(pwd) > 0:
        encrypted_settings = settings.copy()
        encrypted_settings['LIMITWALLETPRIVATEKEY'] = 'aes:' + cryptocode.encrypt(settings['LIMITWALLETPRIVATEKEY'], pwd)
        encrypted_settings['PRIVATEKEY'] = 'aes:' + cryptocode.encrypt(settings['PRIVATEKEY'], pwd)
    
    # MASSAGE OUTPUT - LimitSniper currently loads settings.json as a [0] element, so we need to massage our
    #                  settings.json output so that it's reasable. This should probably be fixed by us importing
    #                  the entire json file, instead of just the [0] element.
    if settings_changed == True:
        print (timestamp(), "Writing settings to file.")

        if settings['ENCRYPTPRIVATEKEYS'] == "true":
            output_settings = encrypted_settings
        else:
            output_settings = settings

        with open('settings.json', 'w') as f:
            f.write("[\n")                 
            f.write(json.dumps(output_settings, indent=4))
            f.write("\n]\n")

def load_wallet_settings(pwd):

    global settings
    global settings_changed

    # Check for limit wallet information
    if " " in settings['LIMITWALLETADDRESS'] or settings['LIMITWALLETADDRESS'] == "":
        settings_changed = True
        settings['LIMITWALLETADDRESS'] = input("Please provide the wallet address where you have your LIMIT: ")
    
    # Check for limit wallet private key
    if " " in settings['LIMITWALLETPRIVATEKEY'] or settings['LIMITWALLETPRIVATEKEY'] == "":
        settings_changed = True
        settings['LIMITWALLETPRIVATEKEY'] = input("Please provide the private key for the wallet where you have your LIMIT: ")
    
    # If the limit wallet private key is already set and encrypted, decrypt it
    elif settings['LIMITWALLETPRIVATEKEY'].startswith('aes:'):
        print (timestamp(), "Decrypting limit wallet private key.")
        settings['LIMITWALLETPRIVATEKEY'] = settings['LIMITWALLETPRIVATEKEY'].replace('aes:', "", 1)
        settings['LIMITWALLETPRIVATEKEY'] = cryptocode.decrypt(settings['LIMITWALLETPRIVATEKEY'], pwd)

        if settings['LIMITWALLETPRIVATEKEY'] == False:
            print("ERROR: Your private key decryption password is incorrect")
            exit(1)


    # Check for trading wallet information
    if " " in settings['WALLETADDRESS'] or settings['WALLETADDRESS'] == "":
        settings_changed = True
        settings['WALLETADDRESS'] = input("Please provide the wallet address for your trading wallet: ")
    
    # Check for trading wallet private key
    if " " in settings['PRIVATEKEY'] or settings['PRIVATEKEY'] == "":
        settings_changed = True
        settings['PRIVATEKEY'] = input("Please provide the private key for the wallet you want to trade with: ")
    
    # If the trading wallet private key is already set and encrypted, decrypt it
    elif settings['PRIVATEKEY'].startswith('aes:'):
        print (timestamp(), "Decrypting limit wallet private key.")
        settings['PRIVATEKEY'] = settings['PRIVATEKEY'].replace('aes:', "", 1)
        settings['PRIVATEKEY'] = cryptocode.decrypt(settings['PRIVATEKEY'], pwd)




# LOAD MIDDLEWEAR HERE TO DECODE CONTRACTS
from web3.middleware import geth_poa_middleware

client.middleware_onion.inject(geth_poa_middleware, layer=0)


def decode_key():
    private_key = settings['LIMITWALLETPRIVATEKEY']
    acct = client.eth.account.privateKeyToAccount(private_key)
    addr = acct.address
    return addr

def auth():
    my_provider2 = "https://pedantic-montalcini:lair-essay-ranger-rigid-hardy-petted@nd-857-678-344.p2pify.com"
    client2 = Web3(Web3.HTTPProvider(my_provider2))
    #print(timestamp(), "Connected to Ethereum BlockChain =", client2.isConnected())
    # Insert LIMITSWAP Token Contract Here To Calculate Staked Verification
    address = Web3.toChecksumAddress("0x1712aad2c773ee04bdc9114b32163c058321cd85")
    abi = standardAbi
    balanceContract = client2.eth.contract(address=address, abi=abi)
    decimals = balanceContract.functions.decimals().call()
    DECIMALS = 10 ** decimals

    # Exception for incorrect Key Input
    try:
        decode = decode_key()
    except Exception:
        print("There is a problem with your private key : please check if it's correct. Don't enter seed phrase !")
        logging.info("There is a problem with your private key : please check if it's correct. Don't enter seed phrase !")

    wallet_address = Web3.toChecksumAddress(decode)
    balance = balanceContract.functions.balanceOf(wallet_address).call()
    true_balance = balance / DECIMALS
    print(timestamp(), "Current $LIMIT Tokens Staked =", true_balance)
    logging.info("Current $LIMIT Tokens Staked = " + str(true_balance))
    return true_balance

def check_bnb_balance():
    balance = client.eth.getBalance(settings['WALLETADDRESS'])
    print(timestamp(), "Current Wallet Balance is :", Web3.fromWei(balance, 'ether'))
    return balance

def wait_for_tx(tx_hash):
    print(timestamp(), "Waiting for TX to Confirm....")
    timeout = time() + 45
    while True:
        print(timestamp(), ".........waiting............")
        sleep(1)
        try:
            txn_receipt = client.eth.getTransactionReceipt(tx_hash)
            return txn_receipt['status']
        except Exception as e:
            txn_receipt = None

        if txn_receipt is not None and txn_receipt['blockHash'] is not None:
            return txn_receipt['status']

        elif time() > timeout:
            print(timestamp(), "Transaction Timed Out, Breaking Check Cycle....")
            logging.info("Transaction Timed Out, Breaking Check Cycle....")
            break

def decimals(address):
    try:
        balanceContract = client.eth.contract(address=Web3.toChecksumAddress(address), abi=standardAbi)
        decimals = balanceContract.functions.decimals().call()
        DECIMALS = 10 ** decimals
    except ABIFunctionNotFound:
        DECIMALS = 10 ** 18
    except ValueError as ve:
        logging.exception(ve)
    return DECIMALS

def check_pool(inToken, outToken, symbol):
    pair_address = factoryContract.functions.getPair(inToken, outToken).call()
    DECIMALS = decimals(outToken)
    pair_contract = client.eth.contract(address=pair_address, abi=lpAbi)
    reserves = pair_contract.functions.getReserves().call()
    pooled = reserves[1] / DECIMALS
    print(timestamp(), "Current Liquidity Reserves:", pooled, symbol)
    return pooled

def rug_check(address):
    print("Rug Check in Progress")
    s = requests.get(
        'https://api.bscscan.com/api?module=contract&action=getsourcecode&address=' + address + '&apikey=P8DMYB4BDEYRB1PFRXS5NGP9U8673PZ7TW').json()
    _contract = s['result']
    for verified in _contract:
        # print("Checking if Contract is Verifed..")

        if verified['ABI'] != 'Contract source code not verified':

            for contract in _contract:
                source = contract['SourceCode']

                if 'TransferHelper' in verified['ABI'] or 'TransferHelper' in source:
                    print("Our Rug code Checker has found that this contract contains has Honeypot Function Found in Code")
                    mint = True
                elif 'IPayable' in verified['ABI'] or 'IPayable' in source:
                    print("Our Rug code Checker has found that this contract was made by token generator")
                    mint = True
                elif 'HelloBEP20' in verified['ABI'] or 'HelloBEP20' in source:
                    print("Our Rug code Checker has found that this contract contains has vittominacori.github.io Generator")
                    mint = True
                elif 'BEP20TOKEN' in verified['ABI'] or 'BEP20TOKEN' in source:
                    print("Our Rug code Checker has found that this contract contains has Common Scam Contract using BEP20TOKEN Code")
                    mint = True
                elif 'clearCNDAO' in verified['ABI'] or 'clearCNDAO' in source:
                    print("Our Rug code Checker has found that this contract contains has clearCNDAO function Found in Contract")
                    mint = True
                elif 'addAllow' in verified['ABI']:
                    print("Add Allow Contract Found")
                    mint = True
                elif 'removeLiquidityETHWithPermit' in verified['ABI'] or 'removeLiquidityETHWithPermit' in source:
                    print("Our Rug code Checker has found that this contract contains has Remove Liquidty Function")
                    mint = True
                elif 'transferFromMiddleware' in verified['ABI'] or 'transferFromMiddleware' in source:
                    print("Our Rug code Checker has found that this contract contains has Transfer Middleware Fucntion")
                    mint = True
                elif 'ratchetClank' in verified['ABI'] or 'ratchetClank' in source:
                    print("Our Rug code Checker has found that this contract contains has Ratchet & Clank Scam Function")
                    mint = True
                elif 'require(from == _owner' in source:
                    print("Our Rug code Checker has found that this contract contains has Tranfer Function Scam ")
                    mint = True
                elif 'contract BEP20Token' in source:
                    print("Contract Similar to other BEP20 unedited contracts")
                elif 'function issue' in source or 'event Issue' in source or 'event Redeem' in source:
                    print("Our Rug code Checker has found that this contract contains has Issue Redeem Mint Function Scam ...")
                    mint = True

                else:
                    mint = False
        else:
            mint = False

    return mint


def scan(tokens):
    if settings['DXSALE'].lower() != 'true':
        filter = client.eth.filter({'address': routerAddress})
        pending_block = client.eth.getBlock('pending', full_transactions=True)
        print(timestamp(), "Scanning Mempool & Waiting for New Liquidity Add Event..... Current Block: ", pending_block['number'])
        #pending_block = client.eth.getBlock(8831531, full_transactions=True)
        pending_transactions = pending_block['transactions']
        to_address = routerAddress

        for pending in pending_transactions:

            if pending['to'] == to_address:
                tx_hash = pending['hash']
                # result = tx_hash.hex()
                input_bytes = pending['input']
                contract = client.eth.contract(address=routerAddress, abi=routerAbi)

                try:
                    decoded = contract.decode_function_input(input_bytes)
                    #print(decoded)
                except ValueError as ve:
                    logging.exception(ve)
                    break

                if str(decoded[
                           0]) == '<Function addLiquidityETH(address,uint256,uint256,uint256,address,uint256)>' or str(
                        decoded[
                            0]) == '<Function addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)>' or str(
                        decoded[0]) == '<Function addLiquidityKCS(address,uint256,uint256,uint256,address,uint256)>' or str(
                        decoded[0]) == '<Function addLiquidityAVAX(address,uint256,uint256,uint256,address,uint256)>':
                    filter_contract = decoded[1]

                    for token in tokens:

                        try:
                            if filter_contract['token'] == Web3.toChecksumAddress(token['ADDRESS']):
                                token_check = True
                            else:
                                token_check = False

                        except Exception as e:
                            if filter_contract['tokenA'] == Web3.toChecksumAddress(token['ADDRESS']) or filter_contract['tokenB'] == Web3.toChecksumAddress(token['ADDRESS']):
                                token_check = True
                            else:
                                token_check = False

                        #Means the toke in in found proceed to makign buy
                        if token_check:
                            if token['RUGCHECK'].lower() == 'true':
                                rug = rug_check(token['ADDRESS'])
                            else:
                                rug = False

                            if not rug:
                                if token['MULTIPLEBUYS'].lower() == 'true':
                                    count = 0
                                    timeout = int(token['BUYCOUNT'])
                                    nonce = client.eth.getTransactionCount(settings['WALLETADDRESS'])

                                    while True:
                                        if count < timeout:
                                            buy_many(pending, token, nonce)
                                            count += 1
                                            nonce += 1
                                        else:
                                            logging.info("Buy's Sent Stopping Bot")
                                            sys.exit("Buy's Sent Stopping Bot")


                                else:
                                    nonce = client.eth.getTransactionCount(settings['WALLETADDRESS'])
                                    buy(pending, token, nonce, token['BUYAFTER_XXX_SECONDS'])
                                    logging.info("Buy Sent Stopping Bot")
                                    sys.exit("Buy Sent Stopping Bot")

                            else:
                                pass
                        else:
                            pass
                else:
                    pass

    else:
        filter = client.eth.filter({'address': Web3.toChecksumAddress(settings['DXPRESALECONTRACT'])})
        pending_block = client.eth.getBlock('pending', full_transactions=True)
        #pending_block = client.eth.getBlock(9067713, full_transactions=True)
        print("DXSALE MODE ENABLED: ", timestamp(), "Scanning Mempool & Waiting for New Liquidity Add Event..... Current Block: ", pending_block['number'])
        pending_transactions = pending_block['transactions']
        to_address = Web3.toChecksumAddress(settings['DXPRESALECONTRACT'])



        for pending in pending_transactions:

            if pending['input'] == '0x267dd102':
                tx_hash = pending['hash']
                #result = tx_hash.hex()
                input_bytes = pending['input']

                #Check DX SALE Contract event input for 0x267dd102 which is the same when launching sale to pancakeswap
                if pending['input'] == '0x267dd102':

                    for token in tokens:

                        if token['RUGCHECK'].lower() == 'true':
                            rug = rug_check(token['ADDRESS'])
                        else:
                            rug = False

                        if not rug:
                            if token['MULTIPLEBUYS'].lower() == 'true':
                                count = 0
                                timeout = int(token['BUYCOUNT'])
                                nonce = client.eth.getTransactionCount(settings['WALLETADDRESS'])

                                while True:
                                    if count < timeout:
                                        buy_many(pending, token, nonce)
                                        count += 1
                                        nonce += 1
                                    else:
                                        logging.info("Buy's Sent Stopping Bot")
                                        sys.exit("Buy's Sent Stopping Bot")


                            else:
                                nonce = client.eth.getTransactionCount(settings['WALLETADDRESS'])
                                buy(pending, token, nonce, token['BUYAFTER_XXX_SECONDS'])
                                print("BUY SENT - CHECK TRANSACTION TO MAKE SURE IT WAS FOR THE CORRECT CONTRACT!!!!")
                                sleep(5)
                                #logging.info("Buy Sent Stopping Bot")
                                #sys.exit("Buy Sent Stopping Bot")

                        else:
                            pass

                else:
                    pass


def buy(pending, token, nonce, waitseconds):

    seconds = int(waitseconds)

    if waitseconds != '0':
        print("Bot will wait", waitseconds, " seconds before buy, as you entered in BUYAFTER_XXX_SECONDS parameter")
        sleep(seconds)

    deadline = int(time() + + 240)

    if token['USECUSTOMBASEPAIR'].lower() == 'true':
        base = Web3.toChecksumAddress(token['BASEADDRESS'])
        DECIMALS = decimals(base)
        amount = token['BUYAMOUNT'] * DECIMALS
        amount_out = routerContract.functions.getAmountsOut(amount, [base, Web3.toChecksumAddress(token['ADDRESS'])]).call()[-1]
        min_tokens = int(amount_out * (1 - (50 / 100)))

        transaction = routerContract.functions.swapExactTokensForTokens(
            amount,
            min_tokens,
            [base, Web3.toChecksumAddress(token['ADDRESS'])],
            Web3.toChecksumAddress(settings['WALLETADDRESS']),
            deadline
        ).buildTransaction({
            'gasPrice': pending['gasPrice'],
            'gas': 1500000,
            'from': Web3.toChecksumAddress(settings['WALLETADDRESS']),
            'nonce': nonce
        })
        signed_txn = client.eth.account.signTransaction(transaction, private_key=settings['PRIVATEKEY'])


    else:
        amount = Web3.toWei(token['BUYAMOUNT'], 'ether')

        if modified == True:

            if settings["EXCHANGE"].lower() == 'koffeeswap':
                transaction = routerContract.functions.swapExactKCSForTokens(
                    Web3.toWei(0.00000025, 'ether'),
                    [weth, Web3.toChecksumAddress(token['ADDRESS'])],
                    Web3.toChecksumAddress(settings['WALLETADDRESS']),
                    deadline
                ).buildTransaction({
                    'gasPrice': pending['gasPrice'],
                    'gas': 1500000,
                    'value': amount,
                    'from': Web3.toChecksumAddress(settings['WALLETADDRESS']),
                    'nonce': nonce
                })
                signed_txn = client.eth.account.signTransaction(transaction, private_key=settings['PRIVATEKEY'])

            if settings["EXCHANGE"].lower() == 'pangolin' or settings["EXCHANGE"].lower() == 'traderjoe':
                transaction = routerContract.functions.swapExactAVAXForTokens(
                    Web3.toWei(0.00000025, 'ether'),
                    [weth, Web3.toChecksumAddress(token['ADDRESS'])],
                    Web3.toChecksumAddress(settings['WALLETADDRESS']),
                    deadline
                ).buildTransaction({
                    'gasPrice': pending['gasPrice'],
                    'gas': 1500000,
                    'value': amount,
                    'from': Web3.toChecksumAddress(settings['WALLETADDRESS']),
                    'nonce': nonce
                })
                signed_txn = client.eth.account.signTransaction(transaction, private_key=settings['PRIVATEKEY'])

        else:
            transaction = routerContract.functions.swapExactETHForTokens(
                Web3.toWei(0.00000025, 'ether'),
                [weth, Web3.toChecksumAddress(token['ADDRESS'])],
                Web3.toChecksumAddress(settings['WALLETADDRESS']),
                deadline
            ).buildTransaction({
                'gasPrice': pending['gasPrice'],
                'gas': 1500000,
                'value': amount,
                'from': Web3.toChecksumAddress(settings['WALLETADDRESS']),
                'nonce': nonce
            })
            signed_txn = client.eth.account.signTransaction(transaction, private_key=settings['PRIVATEKEY'])



    try:
        return client.eth.sendRawTransaction(signed_txn.rawTransaction)
    finally:
        print("Sending Buy Order for ", token['SYMBOL'])
        print("Transaction Hash = ", Web3.toHex(client.keccak(signed_txn.rawTransaction)))
        # wait for TX
        tx_hash = client.toHex(client.keccak(signed_txn.rawTransaction))
        # wait fo tx
        status = wait_for_tx(tx_hash)
        sleep(15)


def buy_many(pending, token, nonce):
    deadline = int(time() + + 240)


    if token['USECUSTOMBASEPAIR'].lower() == 'true':
        base = Web3.toChecksumAddress(token['BASEADDRESS'])
        DECIMALS = decimals(base)
        amount = token['BUYAMOUNT'] * DECIMALS
        amount_out = routerContract.functions.getAmountsOut(amount, [base, Web3.toChecksumAddress(token['ADDRESS'])]).call()[-1]
        min_tokens = int(amount_out * (1 - (50 / 100)))

        transaction = routerContract.functions.swapExactTokensForTokens(
            amount,
            min_tokens,
            [base, Web3.toChecksumAddress(token['ADDRESS'])],
            Web3.toChecksumAddress(settings['WALLETADDRESS']),
            deadline
        ).buildTransaction({
            'gasPrice': pending['gasPrice'],
            'gas': 1500000,
            'from': Web3.toChecksumAddress(settings['WALLETADDRESS']),
            'nonce': nonce
        })
        signed_txn = client.eth.account.signTransaction(transaction, private_key=settings['PRIVATEKEY'])

    else:
        amount = Web3.toWei(token['BUYAMOUNT'], 'ether')
        if modified == True:

            if settings["EXCHANGE"].lower() == 'koffeeswap':
                transaction = routerContract.functions.swapExactKCSForTokens(
                    Web3.toWei(0.00000025, 'ether'),
                    [weth, Web3.toChecksumAddress(token['ADDRESS'])],
                    Web3.toChecksumAddress(settings['WALLETADDRESS']),
                    deadline
                ).buildTransaction({
                    'gasPrice': pending['gasPrice'],
                    'gas': 1500000,
                    'value': amount,
                    'from': Web3.toChecksumAddress(settings['WALLETADDRESS']),
                    'nonce': nonce
                })
                signed_txn = client.eth.account.signTransaction(transaction, private_key=settings['PRIVATEKEY'])

            elif settings["EXCHANGE"].lower() == 'pangolin' or settings["EXCHANGE"].lower() == 'traderjoe':
                transaction = routerContract.functions.swapExactAVAXForTokens(
                    Web3.toWei(0.00000025, 'ether'),
                    [weth, Web3.toChecksumAddress(token['ADDRESS'])],
                    Web3.toChecksumAddress(settings['WALLETADDRESS']),
                    deadline
                ).buildTransaction({
                    'gasPrice': pending['gasPrice'],
                    'gas': 1500000,
                    'value': amount,
                    'from': Web3.toChecksumAddress(settings['WALLETADDRESS']),
                    'nonce': nonce
                })
                signed_txn = client.eth.account.signTransaction(transaction, private_key=settings['PRIVATEKEY'])

        else:
            transaction = routerContract.functions.swapExactETHForTokens(
                Web3.toWei(0.00000025, 'ether'),
                [weth, Web3.toChecksumAddress(token['ADDRESS'])],
                Web3.toChecksumAddress(settings['WALLETADDRESS']),
                deadline
            ).buildTransaction({
                'gasPrice': pending['gasPrice'],
                'gas': 1500000,
                'value': amount,
                'from': Web3.toChecksumAddress(settings['WALLETADDRESS']),
                'nonce': nonce
            })
            signed_txn = client.eth.account.signTransaction(transaction, private_key=settings['PRIVATEKEY'])

    try:
        return client.eth.sendRawTransaction(signed_txn.rawTransaction)
    finally:
        print("Sending Buy Order for ", token['SYMBOL'])
        print("Transaction Hash = ", Web3.toHex(client.keccak(signed_txn.rawTransaction)))
        sleep(0.5)



def run():

    userpassword = get_password()
    load_wallet_settings(userpassword)
    true_balance = auth()
    save_settings(userpassword)

    true_balance = auth()
    if true_balance >= 100:
        print(timestamp(), "Sniper Subscription Active")
        print("==================================================================================================================================================================")
        print("Please Note:")
        print("- bot will only detect NEW Liquidity Add Events in Mempool: liquidity already added won't be detected")
        print("- bot will NOT work on contracts with Bot Protection, where the add liquidity is made from the smart contract")
        print("==================================================================================================================================================================")

        while True:
            s = open('./tokens.json', )
            tokens = json.load(s)
            s.close()
            scan(tokens)


    else:
        logging.info("You Need to Hold 100 $LIMIT tokens to use this bot!")
        print("You Need to Hold 100 $LIMIT tokens to use this bot!")


try:
    run()
except Exception as err:
    logging.exception(err)
    print("Uh oh, please send me this message: '" + str(err) + "'")
