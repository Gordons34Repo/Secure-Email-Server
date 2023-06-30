# Secure Email Server
## Team Members:
- Simon Gordon ([gordons34](https://github.com/gordons34))
- Eric Carstensen ([thebowser20](https://github.com/E-Carstensen))
- Samuel Brownlee ([benwalsh23](https://github.com/brownleg))
- Evan Stewart ([dcruzm0](https://github.com/stewarte19))

## Basic Introduction to Project
This was the final project for **CMPT 361: Networks**, where our group was tasked with creating an encrypted email server for a business. This server would allow users with the Client Application to access the server with the appropriate IP adress and login. The secure mail service supports up to 5 simultaneous connections. Once acceptable credentials are entered, the server and client exchange their public keys for symmetric keys, and the remaining operations occur on a fork of the server. Upon successful access, the user is prompted to:
- Send an email
- View inbox contents
- Display an email
- Terminate the program

The project was developed in Python, and used the library **Crypto** to assist in encryption. Messages were tested in size up to 1 million bytes, as that was our set cap for the application. This project had no GUI component, so videos and pictures of the project will be from the command line.

## Watch A Video!

[](https://github.com/Gordons34Repo/Secure-Email-Server/assets/135652713/0bc859ce-5266-43e2-8f95-ad7bc79528ef)

## Server-Side Application
<p align="center">
<img src=https://github.com/Gordons34Repo/Secure-Email-Server/assets/135652713/5e827010-5d3a-4b65-a500-838a0b2d626d />
</p>
<p align="center">
  <i>In this screenshot, I display the server's output logs from 2 users connecting and performing operations on the server.</i></p>
