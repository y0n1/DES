DES Cryptosystem
==============================================
SIS Final Project
Our modest implamentation of DES encryption
==============================================

SECTIONS:
	a. Usage
	b. How to use the 'config' file
	c. Provided examples

==============================================

a. Usage:
We supply an executable jar file (DES.jar) which supports the following sintax:

	DES.jar input output key
	
Each argument should be self explanatory, and samples for the 'input' argument are provided
whithin the the 'Examples' folder. The 'output' argument is mandatory and specifies the absolute path
for the requested output file.


b. How to use the 'config' file:
In order to change the program's operation mode the following settings should be modified in the attached 
configuration file.

1. OPERATION
Inorder to encrypt using our des mechanism please enter "Encrypt" under Operation:
		
		Operation=Encrypt
		
Inorder to decrypt use:

		Operation=Decrypt

And inorder to verify ciper file match plain text file use:
		Operation=Verify

2. MODE
Inorder to use CBC encryptio simply:
		
		mode=CBC
		
and the same with ECB encryption:
		
		mode=ECB
		
3. FORMAT
To read plain text file in ASCII format please use:
		
		format=ASCII
		
And to read base64

		format=BASE64
		
c. Provided examples:
Our project includes a folder called "Examples".
Three different examples are provided in order to test the capababilities of our implementation.
Each example contains a sample of the cyphered data (as a BASE64 encoded file - as requested), and
a sample file which contains the expected data after decrypting the encrypted file.