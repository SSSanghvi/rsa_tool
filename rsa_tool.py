# RSA ENCRYPTION/DECRYPTION TOOL AND PASSWORD MANAGER
# BY SAHIL SANGHVI
# CS10 Final Project

#Imports
import random
import math
from _ast import Num

#Declaring Variables
listOfPrimes = [643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971]
p, q, n, totient, e, d = 0,0,0,0,0,0                                #These are all variables used to set the public and private keys. 

#methods
def genPrime():                                                     #Returns a random prime from the array above. No inputs. 
    global listOfPrimes                                             
    return listOfPrimes[random.randint(0, len(listOfPrimes)-1)]

def findGCD(a, b):                                                  #This uses Euclid's Algorithm to find the Greatest Common Denominator. 
    if b == 0:                                                      #Takes inputs a,b and returns the greatest common denominator 
        return a
    else:
        return findGCD(b, (a % b))

def initPQN():                                                      #Sets up P,Q, totient, and N. No inputs or outputs. 
    global p,q,n,totient
    p = genPrime()
    while q == 0 or q == p:
        q = genPrime()                                              #We don't want to have p and q be the same. 
    n = p*q
    totient = (p-1) * (q-1)

def genPubKey():                                                    #Generates the value of e. The public key is then (e,n). No inputs or outputs. 
    global e                                                        #Due to hardware limitations we use a low value of e (257) that is a Fermat prime
    if findGCD(257, totient) == 1:                                  #it is usually set to 65537, but we just need to make sure that it is prime and it's GCD with the
        e = 257                                                     #totient is one. 257 is another Fermat Prime, and we prioritize this fist because it makes the                                    
    elif findGCD(65537, totient) == 1:                              #calculations faster. 
        e = 65537   
    else:
        print("Critical Error; e not found. ") 

def genPrivKey():                                                   #Uses the Extended Euclidean Algorithm to calculate the private key. No input/output
    global e, totient, d
    temp_e, temp_n = e, totient
    steps, pvals = {},{0:0, 1:1}
    nstep = 0
    cdiv, pdiv, remainder = 0,temp_e,-1
    while remainder != 0:
        cdiv = temp_n//pdiv
        remainder = temp_n - pdiv*cdiv
        steps[nstep] = [pdiv, cdiv, remainder]
        temp_n = pdiv
        pdiv = remainder
        nstep += 1 
    if steps[nstep - 2][2] == 1:
        np = 2
        while np < nstep +2:
            pvals[np] = (pvals[np - 2] - (pvals[np-1]*steps[np-2][1]))%n
            np +=1
        d = pvals[np-2]
    else:                                                           #In case the prime numbers do not have a GCD of 1 (which should never happen). 
        print("Critical Error: Modular Multiplicative Inverse Failed")    
        quit

def encrypt(message , verb):                                        #encrypts message. Inputs are the message and whether the user wants verbose mode or not. 
    global e, n
    letters=list(message)                                           #list of characters in message
    enc, temp = "", ""
    for let in letters:
        if verb == True:
            print("Encrypting Character: ", let)
        temp = ord(let)                                             #gets the ASCII value of the character
        m = (temp**e)%n
        m_str = (f'{m:06}')                                         #pads all integers to 6 digits
        enc+=m_str        
    print("Encryption complete! Result: ", enc)
    return enc
    
def decrypt(message, verb):                                         #decrypts an encrypted message. Input is an encrypted string and whether the user wants verbose mode.
    global d,n
    m, result = "", ""
    for i in range(int(len(message) / 6)):              
        m = int(message[6*i:6*(i+1)])                               #loops through, every 6 digits (one character)
        result += (chr((m**d)%n))                                   #recalculates the ASCII value and finds the character from it.
        if verb == True:
            print("Decrypting character ", i+1, "...")
    #print(result)
    print("Decryption complete! Result: " + str(result))
    return result
    
def init():                                                         #initializes the program. Can be run again to get new key values. No inputs/outputs. 
    print("Initializing...")
    initPQN()
    genPubKey()
    genPrivKey()
    
def setkeys():                                                      #Allows the user to set the key values themself. Inputs are on-screen. No output. 
    global e,d,n
    e = int(input("setkeys>>> e: "))    
    d = int(input("setkeys>>> d: "))
    n = int(input("setkeys>>> n: "))    

def add():                                                          #add a password to the pwman utility. No inputs/outputs to the function. 
    f = open("pwman.txt", "a+")                                     #writes the username and encrypted password to the pwman file. 
    f.write('\n' + input("pwman>>>add>>>username: "))               #if there is no file it will create one. 
    f.write("\n" + encrypt(input("pwman>>>add>>>password: "), False))

def show():                                                         #reveals password in pwman file. No input. Output is printed on screen. 
    f = open("pwman.txt", "r")                                      #decrypts each file, then prints a list of usernames and passwords. 
    passes = f.readlines()
    out = []
    for n in range(1,len(passes),2):
        #print("\n" + passes[n] + "... ... ... " + decrypt(str(passes[n+1]),False))
        out.append([passes[n][:-1], decrypt(str(passes[n+1]),False)])   #a list of usernames and passwords
    [print(x) for x in out]
    
def pwman():                                                        #CLI method for the pwman section of the program. Input is on-screen. No output. 
    uin = input("pwman>>>")
    if uin == "help":
        print("pwman utilty help:"
              "\n\t add ... ... ... ... ... add a password to the pwman utility."
              "\n\t show .. ... ... ... ... show passwords in the pwman utility."
              "\n\t setkeys ... ... ... ... set key values to use the pwman utility"
              "\n\t exit .. ... ... ... ... return to RSA encryptor utility.")
        pwman()
    elif uin == "setkeys":
        setkeys()
        pwman()
    elif uin == "add":
        add()
        pwman() 
    elif uin == "show":
        show()
        pwman()   
    elif uin == "exit":
        CLI()
    else:
        print("That's not a valid option. Type \"help\" for help.")
        pwman()    
          
def CLI():                                                          #establishes a command line interface. The program will always run in this method. No inputs or outputs. 
    global p,q,n,d,e,totient
    print("RSA Encryption Algorithm")
    uin = input("RSA_Algorithm>>>") 
    if uin == "help":                                               #help menu
        print("RSA Algorithm Help Guide:")
        print("******** \nBasic Commands:")
        print ("\n\t help ... ... ... ... ... ... ... ... ... ... ... ... ... returns this help menu."
               "\n\t encrypt <message> [-v for verbose mode] ... ... ... .... encrypts your message and returns the output"
               "\n\t decrypt <encrypted message> [-v for verbose mode] ... .. decrypts encrypted hash and returns the result."
               "\n\t init ... ... ... ... ... ... ... ... ... ... ... .... .. re-assigns values for public and private keys."
               "\n\t setkeys  ... ... ... ... ... ... ... ... ... ... .... .. manually re-assign values for public and private keys."
               "\n\t report . ... ... ... ... ... ... ... ... ... ... ... ... prints a report of the public and private key values."
               "\n\t pwman .. ... ... ... ... ... ... ... ... ... ... ... ... launches the password manager."
               "\n\t exit ... ... ... ... ... ... ... ... ... ... ... ... ... exits the program.")
        CLI()
    elif uin == "init":                                             #Reassigns values to keys
        init()
        CLI()       
    elif uin == "report":
        print("RSA Keys Report:"
              "\n\t Public Key"
              "\n\t\t e:", e, 
              "\n\t\t n:", n,
              "\n\t Private Key"
              "\n\t\t d:", d,
              "\n\t\t n:", n)    
        CLI()
    elif uin == "setkeys":
        setkeys()
        CLI()    
    elif uin[0:7] == "encrypt":                                     #Encrypts message
        message = uin[8:]                                           #the message is everything but the first 7 letters
        if uin[-2:] == "-v":                                        #checking for verbose flag
            message = uin[8:-2]                                     #if verbose then the last two letters aren't part of the message. 
            verb = True
        else:
            verb = False    
        encrypt(message, verb)
        CLI()
    elif uin[0:7] == "decrypt":                                         
        encHash = uin[8:]                                           #the encrypted message is everything but the first 7 letters. 
        if uin[-2:] == "-v":                                        #same verbose-checking procedure as above. 
            encHash = uin[8:-2] 
            verb = True
        else:
            verb = False
        decrypt(encHash, verb)
        CLI()
    elif uin == "pwman":
        pwman()    
    elif uin == "exit":
        quit()  
    else:
        print("That's not a valid option. Type \"help\" for help.")
        CLI()
        
#Main    
init()
CLI()