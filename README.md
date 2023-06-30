# Secure Email Server
## Team Members:
- Simon Gordon ([gordons34](https://github.com/gordons34))
- Eric Carstensen ([thebowser20](https://github.com/E-Carstensen))
- Samuel Brownlee ([benwalsh23](https://github.com/brownleg))
- Evan Stewart ([dcruzm0](https://github.com/stewarte19))

## Basic Introduction to Project
This was the final project for **CMPT 361: Networks**, where our group was tasked with creating an encrypted email server for a business. This [Server Application](#server-side-application) would allow users with the [Client Application](#client-side-application) to access the server with the appropriate IP adress and login. The secure mail service supports up to 5 simultaneous connections. Once acceptable credentials are entered, the server and client exchange their public keys for symmetric keys, and the remaining operations occur on a fork of the server. Upon successful access, the user is prompted to:
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
<p align="center"><i>In this screenshot, I display the server's output logs from 2 users connecting and performing operations on the server.</i></p>

### Basic Operations

The server side of the application of the program manages all of client operations, and supports up to 5 simultaneous connections. This is accomplished through forking the main loop of the program. The server mainly performs the following operations:
- Accepting/Refusing connections
- Sending and verifying emails
- Managing Client operations

The client enters the server's address, and then enters their login information. Once this is accepted, the user can then make requests to the server to perform operations. The server also verifies that the keys are accurate, else the connection will be terminated. 

## Client-Side Application
<p align="center">
<img src=https://github.com/Gordons34Repo/Secure-Email-Server/assets/135652713/0a1f6ab0-e963-4504-b50f-80e1951b0908 />
</p>
<p align="center"><i>In this screenshot, I display the client accessing their inbox.</i></p>

The client application, once their login was accepted by the server, has a menu that they can select from:
- Create and send an email
- Dispaly the inbox list
- Display the email contents
- Terminate the connection

As shown in the picture above, the user asks to view their inbox, which then the server diplays a list of all emails in their inbox. The user can then select to view the email contents by selecting the number from their inbox. The user can also choose to send an email. In this screen you can choose to send the email to multiple users and load the email body from a file. This is displayed in the [video](#watch-a-video). After this process, the server sends the email to each person(s) inbox which can then be read and loaded by users. The inbox displays the sender, the epoch date of when the email was sent, and the email title.

## Enhancement and Retrospective

Part of our grading on the final project was implementing a security enhancement, as part of the course was on cybersecurity. For our Enhancement, we focused on man in the middle attacks. This was based around our initial connection being adjusted by another person. Through a malicious third party, a person trying to log in could have their initial connection to the server changed or denied. Also, on the server end, a malicious attack of this nature could cause the credentials being sent to go to a different user. To keep the messages from being intercepted and changed, a Hash code of the login credentials is added to the initial connection. On the server end when it arrives, the message is then re-hashed, and the two hash values are compared. If they match, then we know that the client’s message was not changed in any way. 

For testing this enhancement, we sent a different message with the hash code and the server rejected our connection, as expected. Even with just one number changed from client1 to client2, it rejected the connection. This does not protect against someone sending more messages or causing other forms of DOS attacks, but it does help on one level of security, where our client is verified to be the one sending messages to the server.
