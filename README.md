Project 1 for CyberSecurity


We developed the core functionality of a secure distributed application called **mySNS**, using **Java** and its **Security API**. We implemented a **client-server system** where the **doctor (client)** can securely store medical files such as exams and prescriptions on a **central server**. The system is composed of two main components: the **server (mySNSServer)**, which listens for client connections via **TCP sockets**, and the **client application (mySNS)**, which sends the files to the server. I implemented several operations that allow the client to **encrypt (-sc)**, **sign (-sa)**, or **sign and encrypt (-se)** files before sending them, and to **retrieve (-g)** them while verifying their integrity and authenticity. The encryption process uses a **hybrid model**, combining **AES (128-bit)** for symmetric encryption and **RSA (2048-bit)** for asymmetric encryption. Each user has a personal **Java keystore** containing their key pairs and certificates. This first phase focused on implementing the doctor’s functionalities, ensuring secure file transmission, proper key management, and reliable communication between the client and the server.



Group members: Laura, Maria Beatriz, Maria Rita 


doctors: alice e jose
users: bob e maria


How to use the program:
On server, on file mySNSServer.java on src/server directory Run As Java Aplication on eclipse
Then:
Open terminal on this: ~/eclipse-workspace/SEG/src/client$
and execute the following:
java mySNS.java -a 127.0.0.1:23456 -m alice -u bob -sc opa.pd cifras2.pdf file2.txt
java mySNS.java -a 127.0.0.1:23456 -m alice -u bob -sa opa.pd cifras2.pdf file2.txt
java mySNS.java -a 127.0.0.1:23456 -m alice -u bob -se opa.pd cifras2.pdf file2.txt
java mySNS.java -a 127.0.0.1:23456 -u bob -g cifras2.pdf file1.txt
