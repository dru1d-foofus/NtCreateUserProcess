This repo contains a minimal working PoC to create a process using the native API function `NtCreateUserProcess()`. An accompanying post about this code can be read at https://captmeelo.com/redteam/maldev/2022/05/10/ntcreateuserprocess.html

Additional work was done to add PPID spoofing and BlockDLL functionality, as well as a simple way of running shellcode in the created process's thread. 
- https://offensivedefence.co.uk/posts/ntcreateuserprocess/
- https://github.com/thefLink/RecycledGate
